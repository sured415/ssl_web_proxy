#include <winsock2.h>			// socket
#include <windows.h>
#include <io.h>					// access
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>				// uint
#include <string.h>
#include <string>
#include <openssl/ssl.h>		// ssl
#include "windivert.h"			// windivert
#include "header.h"				// packet header

using namespace std;

char c_message[1460] = { "\0", };
char *server_hello = "HTTP/1.1 200 OK\nContent-Length: 5\n\nHello\n\0";

int connect_tcp() {
	WSADATA wsadata;
	SOCKET s;
	sockaddr_in server_addr, client_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(443);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Socket reset error" << endl;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == SOCKET_ERROR) {
		cout << "Socket create error" << endl;
		WSACleanup();
		return -1;
	}

	SSL_library_init();				// OpenSSL init
	SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_server_method());				// TLSv1.2 context create
	
	if (bind(s, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {	// Bind
		cout << "Bind error" << endl;
	}

	if (listen(s, 5) == SOCKET_ERROR) {														// Listen
		cout << "Listen error" << endl;
	}

	while (1) {
		int c_addr_size = sizeof(client_addr);
		SOCKET c = accept(s, (struct sockaddr *)&client_addr, &c_addr_size);
		if (c == SOCKET_ERROR) {															// Accept
			cout << "Accept error" << endl;
		}

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, (int)c);
		SSL_accept(ssl);
 		const char* server_name;
		
		if (SSL_get_servername_type(ssl) == TLSEXT_NAMETYPE_host_name) {				// Get Server Name
			server_name = SSL_get_servername(ssl, NULL);
			int server_name_len = strlen(server_name);
			cout << "\n 1. servername = " << server_name << endl;

			if (_access("test.com.crt", 0) == -1) {
				system("_init_site.bat");
				system("_make_site.bat test.com");
			}
		}

		SSL_CTX_use_certificate_file(ctx, "C:\\CCIT\\ssl_web_proxy\\ssl_web_proxy\\test.com.crt", SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(ctx, "C:\\CCIT\\ssl_web_proxy\\ssl_web_proxy\\test.com.key", SSL_FILETYPE_PEM);

		while (SSL_read(ssl, c_message, sizeof(c_message)) > 0) {
			cout << c_message << endl;
			memset(c_message, '\0', sizeof(c_message));
			SSL_write(ssl, server_hello, strlen(server_hello));
		}
		SSL_free(ssl);
	}
	SSL_CTX_free(ctx);
	closesocket(s);
	WSACleanup();
	return 0;
}

int btw_CNP() {					// Between Client & Proxy

	return 0;
}

int btw_PNS() {					// Between Proxy & Server
	return 0;
}

int main(int argc, char* argv[]) {

	if (argc != 1) {
		return -1;
	}

	//	connect_tcp(wsadata, s, server_addr, client_addr);
	connect_tcp();

	return 0;
}