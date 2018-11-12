#include <winsock2.h>			// socket
#include <windows.h>
#include <ws2tcpip.h>			// inet_pton
#include <io.h>					// access
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>				// uint
#include <string.h>
#include <openssl/ssl.h>		// ssl
#include "windivert.h"			// windivert
#include "header.h"				// packet header

#define SERVER_MODE		1
#define CLIENT_MODE		2
#define MAXBUF			1460

using namespace std;

char c_message[MAXBUF] = { "\0", };
char *server_hello = "HTTP/1.1 200 OK\nContent-Length: 5\n\nHello\n\0";

sockaddr_in set_sockaddr(int port, char* ip) {
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (ip = 0) addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else inet_pton(AF_INET, ip, &addr.sin_addr.s_addr);

	return addr;
}

SOCKET connect_tcp(int port, char* ip) {
	WSADATA wsadata;
	SOCKET s;
	sockaddr_in server_addr;
	server_addr = set_sockaddr(port, ip);

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Socket reset error" << endl;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == SOCKET_ERROR) {
		cout << "Socket create error" << endl;
		WSACleanup();
		return -1;
	}

	if (bind(s, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {	// Bind
		cout << "Bind error" << endl;
	}

	if (listen(s, 5) == SOCKET_ERROR) {														// Listen
		cout << "Listen error" << endl;
	}

	return s;
}

void create_crt(SSL_CTX* ctx, SSL* ssl) {
	const char* server_name;
	char* crt_path = 0;

	if (SSL_get_servername_type(ssl) == TLSEXT_NAMETYPE_host_name) {				// Get Server Name
		server_name = SSL_get_servername(ssl, NULL);
		int server_name_len = strlen(server_name);
		cout << "\n servername = " << server_name << endl;

		char* _crt = (char*)malloc(server_name_len + 5);
		sprintf_s(_crt, server_name_len + 5, "%s.crt", server_name);

		if (_access(_crt, 0) == -1) {				// Create .crt
			system("_init_site.bat");
			char* make_bat = (char*)malloc(server_name_len + 16);
			sprintf_s(make_bat, server_name_len + 16, "_make_site.bat %s", server_name);
			system(make_bat);
		}
		crt_path = (char*)malloc(37 + server_name_len + 5);
		sprintf_s(crt_path, 37 + server_name_len + 5, "C:\\CCIT\\ssl_web_proxy\\ssl_web_proxy\\%s.crt", server_name);
		SSL_CTX_use_certificate_file(ctx, crt_path, SSL_FILETYPE_PEM);
		sprintf_s(crt_path, 37 + server_name_len + 5, "C:\\CCIT\\ssl_web_proxy\\ssl_web_proxy\\%s.key", server_name);
		SSL_CTX_use_PrivateKey_file(ctx, crt_path, SSL_FILETYPE_PEM);
	}
}

int connect_ssl(SOCKET s, int flag) {
	sockaddr_in client_addr;
	SSL_library_init();				// OpenSSL init
	SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_server_method());				// TLSv1.2 context create

	while (1) {
		int c_addr_size = sizeof(client_addr);
		SOCKET c = accept(s, (struct sockaddr *)&client_addr, &c_addr_size);
		if (c == SOCKET_ERROR) {															// Accept
			cout << "Accept error" << endl;
		}

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, (int)c);
		SSL_accept(ssl);
 		
		if (flag = SERVER_MODE) {
			create_crt(ctx, ssl);

			while (SSL_read(ssl, c_message, sizeof(c_message)) > 0) {
				cout << c_message << endl;
				memset(c_message, '\0', sizeof(c_message));
				SSL_write(ssl, server_hello, strlen(server_hello));
			}
		}
		SSL_free(ssl);
	}
	SSL_CTX_free(ctx);
	closesocket(s);
	WSACleanup();
	return 0;
}

int main(int argc, char* argv[]) {

	if (argc != 1) {
		return -1;
	}

	int port = 443;
	u_char packet[MAXBUF];
	WINDIVERT_ADDRESS addr;
	uint32_t packet_len;

	HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	SOCKET s = connect_tcp(port, 0);
	connect_ssl(s, SERVER_MODE);

	return 0;
}