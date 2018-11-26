#include <winsock2.h>			// socket
#include <windows.h>
#include <ws2tcpip.h>			// inet_pton
#include <io.h>					// access
#include <iostream>
#include <process.h>			// thread
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>				// uint
#include <string.h>
#include <openssl/ssl.h>		// ssl
#include <openssl/tls1.h>

#define SERVER_MODE		0
#define CLIENT_MODE		1
#define MAXBUF			1460

using namespace std;

char *server_hello = "HTTP/1.1 200 OK\nContent-Length: 5\n\nHello\n\0";
char *req_to_server = "GET / HTTP/1.1\nHost: test.com\n\0";
const char* server_name;
const char* host_name = 0;
SSL_CTX* ctx_s;

struct ssl_obj {
	SOCKET server_s;
	SOCKET client_s;
	SSL *first_ssl;
	SSL *second_ssl;
}objs;

sockaddr_in set_sockaddr(int port, char* ip);
SOCKET connect_tcp(int port, char* ip);
void create_crt(SSL_CTX* ctx);
void get_servername(SSL* ssl);
int connect_ssl_vServer(SOCKET s);
void connect_ssl_vClient(SOCKET s);
int com_ssl(SSL* src, SSL* dst);
unsigned WINAPI connect_ssl_vServer2(void* obj);
unsigned WINAPI connect_ssl_vClient2(void* obj);

int main(int argc, char* argv[]) {
	if (argc != 1) {
		return -1;
	}

	objs.server_s = connect_tcp(443, SERVER_MODE);
//	objs.client_s = connect_tcp(4433, "172.31.12.162");
	objs.client_s = connect_tcp(4433, "172.31.5.59");
	HANDLE server_thread = (HANDLE)_beginthreadex(NULL, 0, connect_ssl_vServer2, (void*)&objs, 0, NULL);
	HANDLE client_thread = (HANDLE)_beginthreadex(NULL, 0, connect_ssl_vClient2, (void*)&objs, 0, NULL);
	WaitForSingleObject(server_thread, INFINITE);
	WaitForSingleObject(client_thread, INFINITE);

	return 0;
}

sockaddr_in set_sockaddr(int port, char* ip) {
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (ip == SERVER_MODE) addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else inet_pton(AF_INET, ip, &addr.sin_addr.s_addr);

	return addr;
}

SOCKET connect_tcp(int port, char* ip) {
	WSADATA wsadata;
	SOCKET s;
	sockaddr_in addr;
	addr = set_sockaddr(port, ip);

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Socket reset error" << endl;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == SOCKET_ERROR) {
		cout << "Socket create error" << endl;
		WSACleanup();
		return -1;
	}

	if (ip == SERVER_MODE) {
		if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {	// Bind
			cout << "Bind error" << endl;
		}

		if (listen(s, 5) == SOCKET_ERROR) {										// Listen
			cout << "Listen error" << endl;
		}
	}
	else {
		if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
			cout << "Connect error" << endl;
			closesocket(s);
			return -1;
		}
	}
	return s;
}

void create_crt(SSL_CTX* ctx) {
	char* crt_path = 0;
	int server_name_len = strlen(server_name);

	char* crt = (char*)malloc(server_name_len + 5);
	sprintf_s(crt, server_name_len + 5, "%s.crt", server_name);
	if (_access(crt, 0) == -1) {				// Create .crt
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

	free(crt);
	free(crt_path);
}

void get_servername(SSL* ssl) {
	server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);			// Get Server Name
	cout << "\n servername = " << server_name << endl;

	create_crt(ctx_s);
}

int connect_ssl_vServer(SOCKET s) {
	sockaddr_in client_addr;
	int c_addr_size = sizeof(client_addr);
	char c_message[MAXBUF] = { "\0", };

	SSL_library_init();				// OpenSSL init
	ctx_s = SSL_CTX_new(TLSv1_2_server_method());				// TLSv1.2 context create

	while (1) {
		SOCKET c = accept(s, (struct sockaddr *)&client_addr, &c_addr_size);
		if (c == SOCKET_ERROR) {															// Accept
			cout << "Accept error" << endl;
		}

		SSL *ssl = SSL_new(ctx_s);
		SSL_CTX_set_tlsext_servername_callback(ctx_s, get_servername);
		SSL_set_fd(ssl, (int)c);
		SSL_accept(ssl);

		while (SSL_read(ssl, c_message, sizeof(c_message)) > 0) {
			cout << c_message << endl;
			memset(c_message, '\0', sizeof(c_message));
			SSL_write(ssl, server_hello, strlen(server_hello));
		}

		SSL_free(ssl);
	}
	SSL_CTX_free(ctx_s);
	closesocket(s);
	WSACleanup();
	return 0;
}

void connect_ssl_vClient(SOCKET s) {
	char rev_message[MAXBUF] = { "\0", };

	SSL_library_init();				// OpenSSL init
	ctx_s = SSL_CTX_new(TLSv1_2_client_method());				// TLSv1.2 context create

	while (1) {
		SSL *ssl = SSL_new(ctx_s);
		SSL_set_fd(ssl, (int)s);
		if (SSL_connect(ssl)) {
			SSL_write(ssl, req_to_server, strlen(req_to_server));
			while (SSL_read(ssl, rev_message, sizeof(rev_message)) > 0) {
				cout << rev_message << endl;
				memset(rev_message, '\0', sizeof(rev_message));
			}
		}
		else {
			cout << "ssl connect fail" << endl;
			break;
		}
		SSL_free(ssl);
	}
	SSL_CTX_free(ctx_s);
	closesocket(s);
	WSACleanup();
}

unsigned WINAPI connect_ssl_vServer2(void* obj) {
//	objs = *(ssl_obj*)obj;

	sockaddr_in client_addr;
	int c_addr_size = sizeof(client_addr);

	SSL_library_init();				// OpenSSL init
	ctx_s = SSL_CTX_new(TLSv1_2_server_method());				// TLSv1.2 context create

	while (1) {
		SOCKET c = accept(objs.server_s, (struct sockaddr *)&client_addr, &c_addr_size);
		if (c == SOCKET_ERROR) {															// Accept
			cout << "Accept error" << endl;
		}

		objs.first_ssl = SSL_new(ctx_s);
		SSL_CTX_set_tlsext_servername_callback(ctx_s, get_servername);
		SSL_set_fd(objs.first_ssl, (int)c);
		SSL_accept(objs.first_ssl);

		com_ssl(objs.first_ssl, objs.second_ssl);
		
		SSL_free(objs.first_ssl);
		closesocket(c);
	}
	SSL_CTX_free(ctx_s);
	WSACleanup();
	return 0;
}

unsigned WINAPI connect_ssl_vClient2(void* obj) {
//	objs = *(ssl_obj*)obj;
	SSL_library_init();				// OpenSSL init
	ctx_s = SSL_CTX_new(TLSv1_2_client_method());				// TLSv1.2 context create

	while (1) {
		objs.second_ssl = SSL_new(ctx_s);
		SSL_set_fd(objs.second_ssl, (int)objs.client_s);

		/*
		if (SSL_connect(objs.second_ssl)) {
			com_ssl(objs.second_ssl, objs.first_ssl);
		}
		else {
			cout << "ssl connect fail" << endl;
		}
		*/
		SSL_connect(objs.second_ssl);
		com_ssl(objs.second_ssl, objs.first_ssl);
		SSL_free(objs.second_ssl);
	}
	SSL_CTX_free(ctx_s);
	closesocket(objs.client_s);
	WSACleanup();
	return 0;
}

int com_ssl(SSL* src, SSL* dst) {
	char ssl_data[MAXBUF] = { "\0", };

	while (SSL_read(src, ssl_data, sizeof(ssl_data)) > 0) {
		cout << ssl_data << endl << endl;
		/*
		if (SSL_write(a.first_ssl, server_hello, strlen(server_hello)) > 0) {
			cout << "send success" << endl;
		}
		else cout << "send fail" << endl;*/
		SSL_write(dst, ssl_data, strlen(ssl_data));
		memset(ssl_data, '\0', sizeof(ssl_data));
	}

	return 0;
}