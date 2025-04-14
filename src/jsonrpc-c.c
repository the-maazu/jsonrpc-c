#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "cy_wcm.h"

#include "config.h"
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif

#include "jsonrpc-c.h"

// should be globaly initialized in application source after connecting wifi
extern cy_wcm_ip_address_t wifi_addr;

static void jrpc_procedure_destroy(struct jrpc_procedure *procedure);
inline void cy_rslt_log(cy_rslt_t result);

static int send_response(struct jrpc_connection * conn, char *response) {
	cy_rslt_t result;
	if (conn->server->debug_level > 1)
		printf("jrpc: JSON response:\n%s\n", response);
	result = cy_socket_send(conn->socket, response, strlen(response), CY_SOCKET_FLAGS_MORE, NULL);
	cy_socket_send(conn->socket, "\n", 1, CY_SOCKET_FLAGS_NONE, NULL);
	return 0;
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
	free(message);
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
				if (server->debug_level)
					printf("Method Invoked: %s\n", method->valuestring);
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
		free(conn->buffer);
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

	if (conn->pos == (conn->buffer_size - 1)) {
		char * new_buffer = (char *) realloc(conn->buffer, conn->buffer_size *= 2);
		if (new_buffer == NULL) {
			printf("jrpc: memory error");
			return cy_socket_disconnect(hanlde, 0);
		}
		conn->buffer = new_buffer;
		memset(conn->buffer + conn->pos, 0, conn->buffer_size - conn->pos);
	}
	// can not fill the entire buffer, string must be NULL terminated
	int max_read_size = conn->buffer_size - conn->pos - 1;
	result = cy_socket_recv(
		hanlde, conn->buffer + conn->pos, 
		max_read_size, CY_SOCKET_FLAGS_NONE, &bytes_read
	);
	if (result != CY_RSLT_SUCCESS) {
		JRPC_LOG(result);
		return cy_socket_disconnect(hanlde, 0);
	}
	if (!bytes_read) {
		// client closed the sending half of the connection
		if (server->debug_level) printf("jrpc: client closed connection.\n");
		return cy_socket_disconnect(hanlde, 0);
	} else {
		cJSON *root;
		const char *end_ptr = NULL;
		conn->pos += bytes_read;

		if ((root = cJSON_ParseWithOpts(conn->buffer, &end_ptr, false)) != NULL) {
			if (server->debug_level > 1) {
				char * str_result = cJSON_Print(root);
				printf("Valid JSON Received:\n%s\n", str_result);
				free(str_result);
			}

			if (root->type == cJSON_Object) {
				eval_request(server, conn, root);
			}
			//shift processed request, discarding it
			memmove(conn->buffer, end_ptr, strlen(end_ptr) + 2);

			conn->pos = strlen(end_ptr);
			memset(conn->buffer + conn->pos, 0,
					conn->buffer_size - conn->pos - 1);

			cJSON_Delete(root);
		} else {
			// did we parse the entire buffer? If so, just wait for more.
			// else there was an error before the buffer's end
			if (end_ptr != (conn->buffer + conn->pos)) {
				if (server->debug_level) {
					printf("INVALID JSON Received:\n---\n%s\n---\n",
							conn->buffer);
				}
				send_error(conn, JRPC_PARSE_ERROR, "Parse error. Invalid JSON was received by the server.", NULL);
				return cy_socket_disconnect(hanlde, 0);
			}
		}
	}

}

cy_rslt_t accept_cb(cy_socket_t handle, void *arg) {
	struct jrpc_server * server = (struct jrpc_server * ) arg;
	struct jrpc_connection *conn;
	conn = (struct jrpc_connection *) malloc(sizeof(struct jrpc_connection));
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
		JRPC_LOG(result);
		free(conn);
	} else {
		if (server->debug_level) //TODO: print peer address
			printf("jrpc: got connection from  %d.%d.%d.%d\n", &conn->peer_addr.ip_address.ip.v4);
		
		conn->server = server;
		conn->buffer_size = JRPC_MAX_RECV_BUFFER_SIZE;
		conn->buffer = (char *) malloc(JRPC_MAX_RECV_BUFFER_SIZE);
		memset(conn->buffer, 0, JRPC_MAX_RECV_BUFFER_SIZE);

		result = cy_socket_setsockopt(
			conn->socket, CY_SOCKET_SOL_SOCKET,
			CY_SOCKET_SO_DISCONNECT_CALLBACK,
			&disconn_cb,
			sizeof(cy_socket_opt_callback_t)
		);

		if(result != CY_RSLT_SUCCESS)
		{
			cy_rslt_log(result);
			CY_ASSERT(0);
		}

		result = cy_socket_setsockopt(
			conn->socket, CY_SOCKET_SOL_TCP,
			CY_SOCKET_SO_RECEIVE_CALLBACK,
			&recieve_cb,
			sizeof(cy_socket_opt_callback_t)
		);
	}
	return result;
}

static cy_rslt_t _create_server_socket(struct jrpc_server * server)
{
    cy_rslt_t result;

    result = cy_socket_create(CY_SOCKET_DOMAIN_AF_INET, CY_SOCKET_TYPE_DGRAM, CY_SOCKET_IPPROTO_TCP, &server->socket);
    if (result != CY_RSLT_SUCCESS)
        return result;

    server->addr.ip_address.ip.v4 = wifi_addr.ip.v4;
    server->addr.ip_address.version = CY_SOCKET_IP_VER_V4;
    server->addr.port = JRPC_SERVER_PORT;
    result = cy_socket_bind( &server->socket, &server->addr, sizeof(server->addr));
    if (result == CY_RSLT_SUCCESS)
         printf("Socket bound to port: %d\n", server->addr.port);

    return result;
}

void jrpc_server_start(struct jrpc_server * server)
{
	server = (struct jrpc_server *) malloc(sizeof (struct jrpc_server));
	cy_rslt_t result;
	cy_socket_opt_callback_t conn_req_cb = {
		.callback = accept_cb,
		.arg = server
	};
	
    result = _create_server_socket(server);
    if (result != CY_RSLT_SUCCESS)
    {
        printf("TCP Server Socket creation failed. Error: %"PRIu32"\n", result);
        CY_ASSERT(0);
    }

	result = cy_socket_setsockopt(
		server->socket, CY_SOCKET_SOL_TCP, 
		CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK,
		&conn_req_cb,
		sizeof(cy_socket_opt_callback_t)
	);

	memset(server, 0, sizeof(struct jrpc_server));
	if (server->debug_level != NULL)
		server->debug_level = 0;
	else {
		server->debug_level = strtol( (const char *) &server->debug_level, NULL, 10);
		printf("jrpc: debug level %d\n", server->debug_level);
	}

	result = cy_socket_listen(server->socket, 1);
	if (result != CY_RSLT_SUCCESS) {
		JRPC_LOG(result);
		CY_ASSERT(0);
	}
	if (server->debug_level)
		printf("jrpc: waiting for connections...\n");
}

void jrpc_server_stop(struct jrpc_server *server){
	int i;
	for (i = 0; i < server->procedure_count; i++)
		jrpc_procedure_destroy( &(server->procedures[i]) );
	free(server->procedures);
	cy_socket_delete(server->socket);
	free(server);
}

static void jrpc_procedure_destroy(struct jrpc_procedure *procedure){
	if (procedure->name){
		free(procedure->name);
		procedure->name = NULL;
	}
	if (procedure->data){
		free(procedure->data);
		procedure->data = NULL;
	}
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
		printf("jrpc : procedure '%s' not found\n", name);
		return -1;
	}
	return 0;
}


void cy_rslt_log(cy_rslt_t result)
{
    switch(result)
    {
        case CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET:
            printf("jrpc: invalid socket");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR:
            printf("jrpc: tls error");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT:
            printf("jrpc: socket timeout");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM:
            printf("jrpc: nomem");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_BADARG:
            printf("jrpc: nomem");
            break;
        case CY_RSLT_MODULE_SECURE_SOCKETS_NOT_LISTENING:
            printf("jrpc: nomem");
            break;           
        case CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR:
            printf("jrpc: tcpip error");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED:
			printf("jrpc: secure socket closed");
			break;
		case CY_RSLT_MODULE_SECURE_SOCKETS_WOULDBLOCK:
			printf("jrpc: secure socket would block");
			break;
        default:
            printf("jrpc: unknown error");
    }
}