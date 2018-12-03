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
#define GLOG_NO_ABBREVIATED_SEVERITIES
#include <glog/logging.h>

#define SERVER_MODE		0
#define CLIENT_MODE		1
#define MAXBUF			1460

using namespace std;

const char* server_name;
SSL_CTX* ctx_s;
SSL_CTX* ctx_c;

struct ssl_obj {
	SOCKET server_s;
	SOCKET client_s;
	SSL *first_ssl{ nullptr };
	SSL *second_ssl{ nullptr };
}objs;

sockaddr_in set_sockaddr(int port, int flag);
SOCKET connect_tcp(int port, int flag);
void create_crt(SSL_CTX* ctx);
void get_servername(SSL* ssl);
int connect_ssl();
unsigned WINAPI com_ssl(void* obj);

int main(int argc, char* argv[]) {
	if (argc != 1) {
		return -1;
	}

	objs.server_s = connect_tcp(443, SERVER_MODE);
	connect_ssl();

	WSACleanup();
	return 0;
}

sockaddr_in set_sockaddr(int port, int flag) {
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (flag == SERVER_MODE) addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else {
		struct addrinfo* result;
		char c_port[5] = { 0, };
		sprintf_s(c_port, "%d", port);

		int res = getaddrinfo(server_name, c_port, NULL, &result);
		if (res != 0) {
			cout << "getaddrinfo fail" << endl;
		}
		else {
			sockaddr_in* host_name;
			host_name = (sockaddr_in *)result->ai_addr;
			addr.sin_addr.s_addr = host_name->sin_addr.s_addr;
		}
		freeaddrinfo(result);
	}
	return addr;
}

SOCKET connect_tcp(int port, int flag) {
	WSADATA wsadata;
	SOCKET s;
	sockaddr_in addr;
	addr = set_sockaddr(port, flag);

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "Socket reset error" << endl;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == SOCKET_ERROR) {
		cout << "Socket create error" << endl;
		WSACleanup();
		return -1;
	}

	if (flag == SERVER_MODE) {
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

int connect_ssl() {
	LOG(INFO) << "start connect";
	sockaddr_in client_addr;
	int c_addr_size = sizeof(client_addr);

	ctx_s = SSL_CTX_new(TLSv1_2_server_method());				// TLSv1.2 context create
	SOCKET c;
	while (1) {
		c = accept(objs.server_s, (struct sockaddr *)&client_addr, &c_addr_size);
		if (c == SOCKET_ERROR) {															// Accept
			cout << "Accept error" << endl;
		}

		objs.first_ssl = SSL_new(ctx_s);
		SSL_CTX_set_tlsext_servername_callback(ctx_s, get_servername);
		SSL_set_fd(objs.first_ssl, (int)c);
		int res = SSL_accept(objs.first_ssl);
		LOG(INFO) << "Server SSL_accept return = " << res;
		if (res == 1) {
			objs.client_s = connect_tcp(4433, CLIENT_MODE);
			ctx_c = SSL_CTX_new(TLSv1_2_client_method());
			objs.second_ssl = SSL_new(ctx_c);
			SSL_set_fd(objs.second_ssl, (int)objs.client_s);
			if (SSL_connect(objs.second_ssl) == 1) {
				HANDLE ps_thread = (HANDLE)_beginthreadex(NULL, 0, com_ssl, (void*)&objs, 0, NULL);
				ssl_obj revers_objs;
				revers_objs.first_ssl = objs.second_ssl;
				revers_objs.second_ssl = objs.first_ssl;
				HANDLE pc_thread = (HANDLE)_beginthreadex(NULL, 0, com_ssl, (void*)&revers_objs, 0, NULL);
			}
		}
	}
	SSL_free(objs.first_ssl);
	SSL_free(objs.second_ssl);
	closesocket(c);

	SSL_CTX_free(ctx_s);
	SSL_CTX_free(ctx_c);
	LOG(INFO) << "stop  connect_ssl";
	return 0;
}

unsigned WINAPI com_ssl(void* obj) {
	ssl_obj _obj = *(ssl_obj*)obj;
	LOG(INFO) << "com_ssl2 " << (void*)_obj.first_ssl << " " << (void*)_obj.second_ssl;
	char ssl_data[MAXBUF] = { "\0", };

	while (1) {
		LOG(INFO) << "bef SSL_read ssl=" << (void*)_obj.first_ssl;
		int res = SSL_read(_obj.first_ssl, ssl_data, sizeof(ssl_data));
		LOG(INFO) << "SSL_read res=" << res;
		if (res > 0) {
			cout << ssl_data << endl << endl;
			LOG(INFO) << "bef SSL_write =" << (void*)_obj.second_ssl;
			res = SSL_write(_obj.second_ssl, ssl_data, strlen(ssl_data));
			LOG(INFO) << "SSL_write res = " << res;
		}
		else {
			cout << SSL_get_error(_obj.first_ssl, res) << endl;
			break;
		}
		memset(ssl_data, '\0', sizeof(ssl_data));
	}
	return 0;
}