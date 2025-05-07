mtb-jsonrpc-c
=========

JSON-RPC server in C for Infineon(Cypress) ModusToolbox &trade;

What?
-----
A library for a C program to receive JSON-RPC requests on tcp sockets (no HTTP) based on work by [@hmngomes](https://github.com/hmng/jsonrpc-c/commits?author=hmng). This is a port for Infineon(Cypress) platforms/kits with support for ModusToolbox &trade; [secure-sockets](https://github.com/Infineon/secure-sockets) middleware.

Free software, MIT license.

Why?
----
I needed to implement a simple remote config scheme for radar kit [KIT_CSK_BGT60TR13C](https://www.infineon.com/cms/en/product/evaluation-boards/kit_csk_bgt60tr13c/) so I ported jsonrpc-c by [@hmngomes](https://github.com/hmng/jsonrpc-c/commits?author=hmng) which is originally meant for embedded Linux to the RTOS based Infineon(Cypress) [secure-sockets](https://github.com/Infineon/secure-sockets).

How?
----
It depends on ModusToolbox &trade; libraries and includes cJSON (from https://github.com/DaveGamble/cJSON).
No further dependencies.

Who?
----

[@the-maazu](https://github.com/the-maazu)