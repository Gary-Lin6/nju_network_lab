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
#define BUF_SIZE 1024

//http响应请求
void handle_http_request(int sock)
{
    //读请求
    char buf[BUF_SIZE]={0};
    int bytes=read(sock,buf,sizeof(buf));
    if(bytes<0){
        perror("read failed");
        exit(1);
    }
    //解析请求，method：get...,url:文件,httpVersion:HTTP/1.0
    char method[16],url[256],httpVersion[16];
	sscanf(buf,"%s %s %s",method,url,httpVersion);
    //获取range字段
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
    // 如果url不以'/'结尾，添加'/'
    if(url[strlen(url)-1] != '/')
    {
        strcat(url, "/");
    }
    // 检查是否是目录
    struct stat st;
    if(stat(url, &st) == 0 && S_ISDIR(st.st_mode))
    {
        // 返回301重定向到index.html
        sprintf(response, "%s 301 Moved Permanently\r\nLocation: /%sindex.html\r\n\r\n", httpVersion, url);
        write(sock, response, strlen(response));
        close(sock);
        return;
    }
    FILE* fp=fopen(url,"rb");
    char response[BUFFER_SIZE]={0};
    //找不到文件情况，返回404
    if(fp==NULL){
        perror("fopen failed");
        //发送响应报文
        sprintf(response,"%s 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n404 Not Found",httpVersion);
        write(sock,response,strlen(response));
        close(sock);
        return;
    }
    //range情况，返回206
    else if(range){
        struct stat st;
        stat(url,&st);
        int file_size=st.st_size;
        int start,end;
        sscanf(range,"Range: bytes=%d-%d",&start,&end);
        int range_size;
        if(end==-1) range_size=file_size-start;
        else 
            range_size=end-start+1;
        //发送响应报文
        sprintf(response,"%s 206 Partial Content\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nContent-Range: bytes %d-%d/%d\r\n\r\n",httpVersion,range_size,start,end,file_size);
        write(sock,response,strlen(response));
        //发送部分文件
        fseek(fp,start,SEEK_SET);
        char file_buf[BUF_SIZE];
        int bytes_to_send=range_size;
        while(bytes_to_send>0){
            int chunk_size=fread(file_buf,1,sizeof(file_buf),fp);
            if(chunk_size<=0) break;
            if(chunk_size>bytes_to_send) chunk_size=bytes_to_send;
            write(sock,file_buf,chunk_size);
            bytes_to_send-=chunk_size;
        }
    }
    //成功，返回200
    else{
        //发送报文
        sprintf(response,"%s 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n",httpVersion,BUF_SIZE);
        write(sock,response,strlen(response));
        //发送文件
        char file_buf[BUF_SIZE];
        int bytes_read;
        while((bytes_read=fread(file_buf,1,sizeof(file_buf),fp))>0){
            write(sock,file_buf,bytes_read);
        }
    }
    fclose(fp);
    close(sock);
}
void handle_https_request(SSL* ssl)
{
    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}
    else {
        char response[BUFFER_SIZE]={0};
		char buf[] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			exit(1);
		}
        SSL_write(ssl, response, strlen(response));
    }
    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

int main()
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

	// init socket, listening to port 443
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(443);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		SSL *ssl = SSL_new(ctx); 
		SSL_set_fd(ssl, csock);
		handle_https_request(ssl);
	}

	close(sock);
	SSL_CTX_free(ctx);

	return 0;
}
