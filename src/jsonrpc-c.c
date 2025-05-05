#include "stdio.h"
#include "stdlib.h"
#include "errno.h"
#include "string.h"

#ifdef HAVE_STDBOOL_H
# include "stdbool.h"
#else
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif

#include "cy_wcm.h"
#include "cy_secure_sockets.h"

#include "jsonrpc-c.h"

#ifndef NDEBUG
#define JRPC_LOG(...) printf("jrpc: "); printf(__VA_ARGS__); printf("\n");
#else
#define JRPC_LOG(...)
#endif

struct jrpc_connection {
	struct jrpc_server * server;
	cy_socket_t socket;
	cy_socket_sockaddr_t peer_addr;
	uint32_t peer_addr_len;
	int pos;
	char buffer[JRPC_MAX_RECV_BUFFER_SIZE];
};

void jrpc_rslt_log(cy_rslt_t result);

static int send_response(struct jrpc_connection * conn, char *response) {
	cy_rslt_t result;
	JRPC_LOG("JSON response:\n%s", response);
	result = cy_socket_send(conn->socket, response, strlen(response), CY_SOCKET_FLAGS_MORE, NULL);
	if(result != CY_RSLT_SUCCESS)
		return result;
	return cy_socket_send(conn->socket, "\n", 1, CY_SOCKET_FLAGS_NONE, NULL);
}

static int send_error(struct jrpc_connection * conn, int code, char* message,
		cJSON * id) {
	int return_value = 0;
	cJSON *result_root = cJSON_CreateObject();
	cJSON *error_root = cJSON_CreateObject();
	cJSON_AddNumberToObject(error_root, "code", code);
	cJSON_AddStringToObject(error_root, "message", message);
	cJSON_AddItemToObject(result_root, "error", error_root);
	cJSON_AddItemToObject(result_root, "id", id);
	char * str_result = cJSON_Print(result_root);
	return_value = send_response(conn, str_result);
	free(str_result);
	cJSON_Delete(result_root);
	return return_value;
}

static int send_result(struct jrpc_connection * conn, cJSON * result,
		cJSON * id) {
	int return_value = 0;
	cJSON *result_root = cJSON_CreateObject();
	if (result)
		cJSON_AddItemToObject(result_root, "result", result);
	cJSON_AddItemToObject(result_root, "id", id);

	char * str_result = cJSON_Print(result_root);
	return_value = send_response(conn, str_result);
	free(str_result);
	cJSON_Delete(result_root);
	return return_value;
}

static int invoke_procedure(struct jrpc_server *server,
		struct jrpc_connection * conn, char *name, cJSON *params, cJSON *id) {
	cJSON *returned = NULL;
	int procedure_found = 0;
	jrpc_context ctx;
	ctx.error_code = 0;
	ctx.error_message = NULL;
	int i = server->procedure_count;
	while (i--) {
		if (!strcmp(server->procedures[i].name, name)) {
			procedure_found = 1;
			ctx.data = server->procedures[i].data;
			returned = server->procedures[i].function(&ctx, params, id);
			break;
		}
	}
	if (!procedure_found)
		return send_error(conn, JRPC_METHOD_NOT_FOUND,"Method not found.", id);
	else {
		if (ctx.error_code)
			return send_error(conn, ctx.error_code, ctx.error_message, id);
		else {
			// notifications have no reply
			// the standard indicates that notifications are sent without "id"
			// but we leave the decision for clients; by returning NULL we skip the reply
			if (returned != NULL) {
				return send_result(conn, returned, id);
			} else {
				return 0;
			}
		}
	}
}

static int eval_request(struct jrpc_server *server,
		struct jrpc_connection * conn, cJSON *root) {
	cJSON *method, *params, *id;
	method = cJSON_GetObjectItem(root, "method");
	if (method != NULL && method->type == cJSON_String) {
		params = cJSON_GetObjectItem(root, "params");
		if (params == NULL|| params->type == cJSON_Array
		|| params->type == cJSON_Object) {
			id = cJSON_GetObjectItem(root, "id");
			if (id == NULL|| id->type == cJSON_String
			|| id->type == cJSON_Number) {
			//We have to copy ID because using it on the reply and deleting the response Object will also delete ID
				cJSON * id_copy = NULL;
				if (id != NULL)
					id_copy =
							(id->type == cJSON_String) ? cJSON_CreateString(
									id->valuestring) :
									cJSON_CreateNumber(id->valueint);
				JRPC_LOG("Method Invoked: %s", method->valuestring);
				return invoke_procedure(server, conn, method->valuestring,
						params, id_copy);
			}
		}
	}
	send_error(conn, JRPC_INVALID_REQUEST, "The JSON sent is not a valid Request object.", NULL);
	return -1;
}

static cy_rslt_t destroy_connection(cy_socket_t handle, void *arg) {
	struct jrpc_connection * conn = (struct jrpc_connection *) arg;
	cy_rslt_t result;
	// cy_socket_shutdown(handle, CY_SOCKET_SHUT_RDWR);
	result =  cy_socket_delete(handle);
	if(result == CY_RSLT_SUCCESS)
	{
		free(conn);
	}
	return result;
}

static cy_rslt_t recieve( cy_socket_t hanlde, void *arg) 
{
	cy_rslt_t result;
	struct jrpc_connection * conn = (struct jrpc_connection *) arg;
	struct jrpc_server *server = (struct jrpc_server *) conn->server;
	uint32_t bytes_read = 0;

	cJSON *root;
	const char *end_ptr = NULL;

	if (conn->pos == (JRPC_MAX_RECV_BUFFER_SIZE - 1)) {
		JRPC_LOG("json string too long")
		conn->pos = 0;
		memset(conn->buffer, '\0', JRPC_MAX_RECV_BUFFER_SIZE);
	}
	// can not fill the entire buffer, string must be NULL terminated
	int max_read_size = JRPC_MAX_RECV_BUFFER_SIZE - conn->pos - 1;
	result = cy_socket_recv(
		hanlde, conn->buffer + conn->pos, 
		max_read_size, CY_SOCKET_FLAGS_NONE, &bytes_read
	);
	if (result != CY_RSLT_SUCCESS) {
		jrpc_rslt_log(result);
		return cy_socket_disconnect(hanlde, 0);
	}
	conn->pos += bytes_read;
	*(conn->buffer + conn->pos) = '\0';
	conn->pos++;

	if ((root = cJSON_ParseWithOpts(conn->buffer, &end_ptr, false)) != NULL) {
		char * str_result = cJSON_Print(root);
		JRPC_LOG("Valid JSON Received:\n%s", str_result);
		free(str_result);

		if (root->type == cJSON_Object) {
			eval_request(server, conn, root);
		}

		conn->pos = 0;
		memset(conn->buffer, '\0', JRPC_MAX_RECV_BUFFER_SIZE);
		cJSON_Delete(root);
	} else {
		// did we parse the entire buffer? If so, just wait for more.
		// else there was an error before the buffer's end
		if (end_ptr != (conn->buffer + conn->pos)) {
			JRPC_LOG("INVALID JSON Received:\n---\n%s\n---", conn->buffer);
			send_error(conn, JRPC_PARSE_ERROR, "Parse error. Invalid JSON was received by the server.", NULL);
		}
	}
	
	return result;
}

cy_rslt_t accept_cb(cy_socket_t handle, void *arg) {
	struct jrpc_server * server = (struct jrpc_server * ) arg;
	struct jrpc_connection *conn = (struct jrpc_connection *) malloc(sizeof(struct jrpc_connection));
	cy_socket_opt_callback_t disconn_cb = {
		.callback = destroy_connection,
		.arg = conn
	};
	cy_socket_opt_callback_t recieve_cb = {
		.callback = recieve,
		.arg = conn
	};
	cy_rslt_t result;

	result = cy_socket_accept(server->socket, &conn->peer_addr, &conn->peer_addr_len, &conn->socket);
	if(result != CY_RSLT_SUCCESS) {
		jrpc_rslt_log(result);
		free(conn);
	} else {
		JRPC_LOG(
			"got connection from  %d.%d.%d.%d\n",
			(uint8) (conn->peer_addr.ip_address.ip.v4), 
			(uint8) (conn->peer_addr.ip_address.ip.v4 >> 8),
			(uint8) (conn->peer_addr.ip_address.ip.v4 >> 16),
			(uint8) (conn->peer_addr.ip_address.ip.v4 >> 24)
		);

		conn->server = server;
		conn->pos = 0;
		memset(conn->buffer, '\0', JRPC_MAX_RECV_BUFFER_SIZE);
		result = cy_socket_setsockopt(
			conn->socket, CY_SOCKET_SOL_SOCKET,
			CY_SOCKET_SO_DISCONNECT_CALLBACK,
			&disconn_cb,
			sizeof(cy_socket_opt_callback_t)
		);

		if(result != CY_RSLT_SUCCESS)
		{
			jrpc_rslt_log(result);
			CY_ASSERT(0);
		}

		result = cy_socket_setsockopt(
			conn->socket, CY_SOCKET_SOL_SOCKET,
			CY_SOCKET_SO_RECEIVE_CALLBACK,
			&recieve_cb,
			sizeof(cy_socket_opt_callback_t)
		);

		if(result != CY_RSLT_SUCCESS)
		{
			jrpc_rslt_log(result);
			CY_ASSERT(0);
		}
	}
	return result;
}

static cy_rslt_t create_tcp_server_socket(struct jrpc_server * server)
{
    cy_rslt_t result;

    result = cy_socket_create(CY_SOCKET_DOMAIN_AF_INET, CY_SOCKET_TYPE_STREAM, CY_SOCKET_IPPROTO_TCP, &server->socket);
    if (result != CY_RSLT_SUCCESS)
	{
		jrpc_rslt_log(result);
		JRPC_LOG("failed to create socket");
		CY_ASSERT(0);
		return result;
	}

    server->addr.port = JRPC_SERVER_PORT;
    result = cy_socket_bind( server->socket, &server->addr, sizeof(server->addr));
    if (result == CY_RSLT_SUCCESS)
		JRPC_LOG("socket bound to port: %d", server->addr.port);

    return result;
}

void jrpc_server_start(struct jrpc_server * server)
{
	cy_rslt_t result;
	uint32_t rcv_timeout = JRPC_SERVER_RECV_TIMEOUT_MS;
	cy_socket_opt_callback_t conn_req_cb = {
		.callback = accept_cb,
		.arg = server
	};
	
    result = create_tcp_server_socket(server);
    if (result != CY_RSLT_SUCCESS)
		return;

	result = cy_socket_setsockopt(
		server->socket, CY_SOCKET_SOL_SOCKET, 
		CY_SOCKET_SO_RCVTIMEO,
		&rcv_timeout,
		sizeof(uint32_t)
	);
	if(result != CY_RSLT_SUCCESS)
		jrpc_rslt_log(result);
		

	result = cy_socket_setsockopt(
		server->socket, CY_SOCKET_SOL_SOCKET, 
		CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK,
		&conn_req_cb,
		sizeof(cy_socket_opt_callback_t)
	);
	if(result != CY_RSLT_SUCCESS)
	{
		jrpc_rslt_log(result);
		jrpc_server_stop(server);
		CY_ASSERT(0);
		return;
	}

	result = cy_socket_listen(server->socket, JRPC_SERVER_MAX_PENDING_CONNECTIONS);
	if (result != CY_RSLT_SUCCESS) {
		jrpc_rslt_log(result);
		jrpc_server_stop(server);
		CY_ASSERT(0);
		return;
	}
	JRPC_LOG("waiting for connections...");
}

void jrpc_procedure_destroy(struct jrpc_procedure *procedure){
	if (procedure->name){
		free(procedure->name);
		procedure->name = NULL;
	}
	if (procedure->data){
		free(procedure->data);
		procedure->data = NULL;
	}
}

void jrpc_server_stop(struct jrpc_server *server){
	int i;
	for (i = 0; i < server->procedure_count; i++)
		jrpc_procedure_destroy( &(server->procedures[i]) );
	free(server->procedures);
	cy_socket_delete(server->socket);
	free(server);
}

int jrpc_register_procedure(struct jrpc_server *server,
		jrpc_function function_pointer, char *name, void * data) {
	int i = server->procedure_count++;
	if (!server->procedures)
		server->procedures = (struct jrpc_procedure *) malloc(sizeof(struct jrpc_procedure));
	else {
		struct jrpc_procedure * ptr = (struct jrpc_procedure *) realloc(server->procedures,
				sizeof(struct jrpc_procedure) * server->procedure_count);
		if (!ptr)
			return -1;
		server->procedures = ptr;

	}
	server->procedures[i].name = (char *) malloc(strlen(name)+1);
	strcpy(server->procedures[i].name, name);
	if (server->procedures[i].name == NULL)
		return -1;
	server->procedures[i].function = function_pointer;
	server->procedures[i].data = data;
	return 0;
}

int jrpc_deregister_procedure(struct jrpc_server *server, char *name) {
	/* Search the procedure to deregister */
	int i;
	int found = 0;
	if (server->procedures){
		for (i = 0; i < server->procedure_count; i++){
			if (found)
				server->procedures[i-1] = server->procedures[i];
			else if(!strcmp(name, server->procedures[i].name)){
				found = 1;
				jrpc_procedure_destroy( &(server->procedures[i]) );
			}
		}
		if (found){
			server->procedure_count--;
			if (server->procedure_count){
				struct jrpc_procedure * ptr = (struct jrpc_procedure *) realloc(server->procedures,
					sizeof(struct jrpc_procedure) * server->procedure_count);
				if (!ptr){
					perror("realloc");
					return -1;
				}
				server->procedures = ptr;
			}else{
				server->procedures = NULL;
			}
		}
	} else {
		JRPC_LOG("procedure '%s' not found", name);
		return -1;
	}
	return 0;
}

#ifndef NDEBUG
void jrpc_rslt_log(cy_rslt_t result)
{

    switch(result)
    {
        case CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET:
            JRPC_LOG("invalid socket");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR:
			JRPC_LOG("tls error");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT:
			JRPC_LOG("socket timeout");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM:
			JRPC_LOG("nomem");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_BADARG:
			JRPC_LOG("badarg");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_NOT_LISTENING:
			JRPC_LOG("not listening");
            break;           
        case CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR:
            JRPC_LOG("tcpip error");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED:
			JRPC_LOG("secure socket closed");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_WOULDBLOCK:
			JRPC_LOG("secure socket would block");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_ALREADY_CONNECTED:
			JRPC_LOG("already connected");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION:
			JRPC_LOG("invalid optio");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_ADDRESS_IN_USE:
			JRPC_LOG("address in use");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_MAX_MEMBERSHIP_ERROR:
			JRPC_LOG("max memebership error");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_MULTICAST_ADDRESS_NOT_REGISTERED:
			JRPC_LOG("address not registered");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED:
			JRPC_LOG("option not supported");
			break;
        default:
            JRPC_LOG("unknown error %d", (int) result);
    }

}
#elif
inline void jrpc_rslt_log(void){}
#endif