#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <sys/stat.h>
#include <pthread.h>
#define BUF_SIZE 1024

//http响应请求
void handle_http_request(int sock)
{
    char buf[BUF_SIZE] = {0};
    int bytes = read(sock, buf, sizeof(buf));
    if (bytes < 0) {
        perror("read failed");
        close(sock);
        return;
    }

    char method[16], url[256], httpVersion[16];
    sscanf(buf, "%15s %255s %15s", method, url, httpVersion);

    // 解析 Host 头用于构建重定向目标
    char host[256] = {0};
    char *host_hdr = strstr(buf, "Host:");
    if (host_hdr) {
        sscanf(host_hdr, "Host: %255s", host);
    }

    // 直接将所有 http 请求重定向到 https（保留原始路径）
    if (host[0] != '\0') {
        char response[BUF_SIZE] = {0};
        sprintf(response,
                "%s 301 Moved Permanently\r\n"
                "Location: https://%s%s\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                httpVersion, host, url);
        write(sock, response, strlen(response));
        close(sock);
        return;
    }
}

void handle_https_request(SSL* ssl)
{
    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}
    else {
        char response[BUF_SIZE]={0};
		char buf[BUF_SIZE] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			exit(1);
		}
        buf[bytes]='\0';
        char method[16],url[256],httpVersion[16];
		int parsed=sscanf(buf,"%s %s %s",method,url,httpVersion);
        if(parsed!=3){
            sprintf(response,"HTTP/1.0 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request");
            SSL_write(ssl, response, strlen(response));
            int sock = SSL_get_fd(ssl);
            SSL_free(ssl);
            close(sock);
            return;
        }
        char *range=strstr(buf,"Range:");
    //处理url，去掉开头的'/'
    if(url[0]=='/')
	{
		int i=0;
		for(;url[i]!='\0' && url[i+1]!='\0';i++)
		{
			url[i]=url[i+1];
		}
		url[i]='\0';
	}
    FILE* fp=fopen(url,"rb");
    struct stat st;
    stat(url,&st);
    int file_size=st.st_size;
     //找不到文件情况，返回404
    if(fp==NULL){
        perror("fopen failed");
        //发送响应报文
        sprintf(response,"%s 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n404 Not Found",httpVersion);
        SSL_write(ssl, response, strlen(response));
    }
    //range情况，返回206
    else if(range){
        int start=0,end=-1;
        sscanf(range,"Range: bytes=%d-%d",&start,&end);
        int range_size;
        if(end==-1||end>=file_size) end=file_size-1;
        if(start<0) start=0;
        if(start>end) start=end;
        range_size=end-start+1;
        //发送响应报文
        sprintf(response,"%s 206 Partial Content\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nContent-Range: bytes %d-%d/%d\r\n\r\n",httpVersion,range_size,start,end,file_size);
        SSL_write(ssl, response, strlen(response));
        //发送部分文件
        fseek(fp,start,SEEK_SET);
        char file_buf[BUF_SIZE];
        int bytes_to_send=range_size;
        while(bytes_to_send>0){
            int chunk_size=fread(file_buf,1,sizeof(file_buf),fp);
            if(chunk_size<=0) break;
            if(chunk_size>bytes_to_send) chunk_size=bytes_to_send;
            SSL_write(ssl, file_buf, chunk_size);
            bytes_to_send-=chunk_size;
        }
    }
    //成功，返回200
    else{
        //发送报文
        sprintf(response,"%s 200 OK\r\nContent-Type: appliccation/octet-stream\r\nContent-Length: %d\r\n\r\n",httpVersion,file_size);
        SSL_write(ssl, response, strlen(response));
        //发送文件
        char file_buf[BUF_SIZE];
        int bytes_read;
        while((bytes_read=fread(file_buf,1,sizeof(file_buf),fp))>0){
            SSL_write(ssl, file_buf, bytes_read);
        }
    }
    }
    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void* httpthread(void* arg)
{
   int sock80=socket(AF_INET,SOCK_STREAM,0);
	if(sock80<0){
		perror("Opening socket failed");
		exit(1);
	}
    int enable80 = 1;
    if (setsockopt(sock80, SOL_SOCKET, SO_REUSEADDR, &enable80, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}
    struct sockaddr_in addr80;
	bzero(&addr80, sizeof(addr80));
	addr80.sin_family = AF_INET;
	addr80.sin_addr.s_addr = INADDR_ANY;
	addr80.sin_port = htons(80);
    if (bind(sock80, (struct sockaddr*)&addr80, sizeof(addr80)) < 0) {
		perror("Bind failed");
		exit(1);
	}
    listen(sock80, 10);
    while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int sock = accept(sock80, (struct sockaddr*)&caddr, &len);
		if (sock < 0) {
			perror("Accept failed");
			exit(1);
		}
		handle_http_request(sock);
	}

}

void* httpsthread(void* arg)
{
    // init SSL Library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // enable TLS method
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    // load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
        perror("load cert failed");
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
        perror("load prikey failed");
        exit(1);
    }

    int sock443 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock443 < 0) {
        perror("Opening socket failed");
        exit(1);
    }
    int enable443 = 1;
    if (setsockopt(sock443, SOL_SOCKET, SO_REUSEADDR, &enable443, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }

    struct sockaddr_in addr443;
    bzero(&addr443, sizeof(addr443));
    addr443.sin_family = AF_INET;
    addr443.sin_addr.s_addr = INADDR_ANY;
    addr443.sin_port = htons(443);

    if (bind(sock443, (struct sockaddr*)&addr443, sizeof(addr443)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    listen(sock443, 10);

    while (1) {
        struct sockaddr_in caddr;
        socklen_t len;
        int csock = accept(sock443, (struct sockaddr*)&caddr, &len);
        SSL *ssl = SSL_new(ctx); 
        SSL_set_fd(ssl, csock);
        if (csock < 0) {
            perror("Accept failed");
            SSL_free(ssl);
            close(csock);
            continue;
        }
        handle_https_request(ssl);
    }

    SSL_CTX_free(ctx);
}
int main()
{
	pthread_t tid[2];
	int result;
    result = pthread_create(&tid[0], NULL, httpthread, NULL);
	if (result != 0) {
		perror("Error creating HTTP thread");
		exit(1);
	}
	
	result = pthread_create(&tid[1], NULL, httpsthread, NULL);
	if (result != 0) {
		perror("Error creating HTTPS thread");
		exit(1);
	}
	while(1);
	return 0;
}
