/* Derived from sample/http-server.c in libevent source tree.
 * That file does not have a license notice, but generally libevent
 * is under the 3-clause BSD.
 *
 * Plus, some additional inspiration from:
 * http://archives.seul.org/libevent/users/Jul-2010/binGK8dlinMqP.bin
 * (which is a .c file despite the extension and mime type) */

/*
  A trivial https webserver using Libevent's evhttp.

  This is not the best code in the world, and it does some fairly stupid stuff
  that you would never want to do in a production webserver. Caveat hackor!

 */

#include "https-common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#ifndef S_ISDIR
#define S_ISDIR(x) (((x)&S_IFMT) == S_IFDIR)
#endif
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif

#ifdef _WIN32
#define stat _stat
#define fstat _fstat
#define open _open
#define close _close
#define O_RDONLY _O_RDONLY
#endif

unsigned short serverPort = COMMON_HTTPS_PORT;
char uri_root[512];
/* Instead of casting between these types, create a union with all of them,
 * to avoid -Wstrict-aliasing warnings. */
typedef union {
    struct sockaddr_storage ss; //128B通用地址结构体
    struct sockaddr sa;         //16B通用地址结构体
    struct sockaddr_in in;      //IPv4
    struct sockaddr_in6 i6;     //IPv6
} sock_hop;

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */


/* 处理get和post的回调方法 */
// GET方法中的查询字符串（键值对）实际上是从URI中获得的
void deal_get(struct evhttp_request *req, void *args)
{
    // deal GET request, callback function
    // show request information and send response message
    // for example : /test?name1=value1&name2=value2
    // pay attention: if you use curl,'&' is a kind of specific command
    struct evbuffer *evb = evbuffer_new();
    if (!evb)
    {
        fprintf(stderr, "Couldn't create buffer\n");
        return;
    }
    const char *uri = evhttp_request_get_uri(req);
    // kvs是一个的队列，用来存储uri解析后的键-值对,先判断是否是badrequest
    struct evkeyvalq kvs;
    if (evhttp_parse_query(uri,&kvs) != 0)
    {
        printf("It's a bad uri. BADREQUEST\n");
        evhttp_send_error(req, HTTP_BADREQUEST, 0);
        return;
    }
    evbuffer_add_printf(evb, "You have sent a GET request to the server\r\n");
    evbuffer_add_printf(evb, "Request URI: %s\r\n", uri);
    for (struct evkeyval *head = kvs.tqh_first; head != NULL; head = head->next.tqe_next)
    {
        evbuffer_add_printf(evb, "%s=%s\r\n", head->key, head->value);
    }
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    if(evb)
        evbuffer_free(evb);
}

void deal_post(struct evhttp_request *req, void *args)
{   
    struct evbuffer *evb = evbuffer_new();
    if (!evb)
    {
        fprintf(stderr, "Couldn't create buffer\n");
        return;
    }
    // put data and uri into intergrated
    size_t origin_uri_size = strlen(evhttp_request_get_uri(req))
    size_t data_size = EVBUFFER_LENGTH(evhttp_request_get_input_buffer(req))
    size_t real_uri_size = origin_uri_size + data_size


}
/*文件上传和下载函数实现*/
void do_upload_file(struct evhttp_request *req, void *args)
{
}

void do_download_file(struct evhttp_request *req, void *args)
{
    // Download Format: http://localhost:8800/download/index.html

}


// static void
// send_document_cb(struct evhttp_request *req, void *arg)
// {
//     struct evbuffer *evb = NULL;
//     //获取请求的uri,处理请求的类型:GET、POST、其他
//     const char *uri = evhttp_request_get_uri(req); 
//     struct evhttp_uri *decoded = NULL;
//     const char* path = NULL;
//     char *decoded_path = NULL;
//     char *whole_path = NULL;

//     if (evhttp_request_get_command(req) == EVHTTP_REQ_GET)
//     { //curl -k  https://localhost:8421/会跳转至该函数进行执行然后return
//         struct evbuffer *buf = evbuffer_new();
//         if (buf == NULL)
//             return;
//         evbuffer_add_printf(buf, "Requested: %s\n", uri);
//         evhttp_send_reply(req, HTTP_OK, "OK", buf);
//         return;
//     }

//     /* We only handle POST requests. */
//     if (evhttp_request_get_command(req) != EVHTTP_REQ_POST)
//     {
//         evhttp_send_reply(req, 200, "OK", NULL);
//         return;
//     }

//     printf("Got a POST request for <%s>\n", uri);

//     //将uri分段为各个部分,当uri存在err，evhttp_uri_parse返回NULL
//     decoded = evhttp_uri_parse(uri); 
//     if (!decoded)                                       
//     {
//         printf("It's not a good URI. Sending BADREQUEST\n");
//         evhttp_send_error(req, HTTP_BADREQUEST, 0);
//         return;
//     }
//     /*通过解析uri在以下部分完成请求判断*/
//     //printf("Path=%s",decoded->path);
//     //.......

//     /* Decode the payload */
//     //kv为一个evkeyval队列,key-value queue(队列结构)，主要用来保存HTTP headers
//     //也可以被用来保存parse uri参数的结果
//     struct evkeyvalq kv ;
//     struct evbuffer *buff = evbuffer_new();
//     memset(&kv, 0, sizeof(kv)); //清空缓冲队列，全部置0

//     if (0 != evhttp_parse_query(buff, &kv)) //Helper函数可从HTTP URI的查询部分中解析出参数
//     {
//         printf("Malformed payload. Sending BADREQUEST\n");
//         evhttp_send_error(req, HTTP_BADREQUEST, 0);
//         return;
//     }
//     evbuffer_add_printf(buff, "You have sent a POST request to the server\r\n");
//     evbuffer_add_printf(buff, "Request URI: %s\r\n", evhttp_request_get_uri(req));
//     for (struct evkeyval *head = kv.tqh_first; head != NULL; head = head->next.tqe_next)
//     {
//         evbuffer_add_printf(buff, "%s=%s\n", head->key, head->value);
//     }

//     evhttp_send_reply(req, 200, "OK", buff);
//     if (decoded)
//         evhttp_uri_free(decoded);
//     if (buff)
//         evbuffer_free(buff);
// }

/**
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 */
static struct bufferevent *bevcb(struct event_base *base, void *arg)
{
    struct bufferevent *r;
    SSL_CTX *ctx = (SSL_CTX *)arg;
    //bufferevent可以使用OpenSSL库来实现SSL/TLS安全传输层。
    //因为大多数应用不需要连接OpenSSL，所以该功能在一个独立的库“libevent_openssl”中实现。
    //未来版本的Libevent可以支持其他的SSL/TLS库，比如NSS或GnuTLS，但是当前只支持OpenSSL
    //bufferevent_openssl_socket_new 在event2/bufferevent_ssl.h中声明
    r = bufferevent_openssl_socket_new(base,
                                       -1,
                                       SSL_new(ctx),
                                       BUFFEREVENT_SSL_ACCEPTING,
                                       BEV_OPT_CLOSE_ON_FREE);
    //BEV_OPT_CLOSE_ON_FREE
    return r;
}

static void server_setup_certs(SSL_CTX *ctx,
                               const char *certificate_chain,
                               const char *private_key)
{
    info_report("Loading certificate chain from '%s'\n"
                "and private key from '%s'\n",
                certificate_chain, private_key);
    //为SSL会话加载本应用的证书所属的证书链
    if (1 != SSL_CTX_use_certificate_chain_file(ctx, certificate_chain))
        //该函数在https-common中完成，主要
        die_most_horribly_from_openssl_error("SSL_CTX_use_certificate_chain_file");
    //加载本应用的私钥
    if (1 != SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM))
        die_most_horribly_from_openssl_error("SSL_CTX_use_PrivateKey_file");
    //验证所加载的私钥和证书是否相匹配
    if (1 != SSL_CTX_check_private_key(ctx))
        die_most_horribly_from_openssl_error("SSL_CTX_check_private_key");
}

// Extract and display the address we're listening on.
// 创建监听端口
static int display_listen_sock(struct evhttp_bound_socket* handle)
{ 
    sock_hop ss;
    evutil_socket_t fd;
    ev_socklen_t socklen = sizeof(ss);
    char addrbuf[128];
    void *inaddr;
    const char *addr;
    int got_port = -1;
    fd = evhttp_bound_socket_get_fd(handle);
    memset(&ss, 0, sizeof(ss));
    if (getsockname(fd, &ss.sa, &socklen))
    {
        perror("getsockname() failed");
        return 1;
    }
    // 判断v4还是v6
    if (ss.ss.ss_family == AF_INET)
    {
        got_port = ntohs(ss.in.sin_port);
        inaddr = &ss.in.sin_addr;
    }
    else if (ss.ss.ss_family == AF_INET6)
    {
        got_port = ntohs(ss.i6.sin6_port);
        inaddr = &ss.i6.sin6_addr;
    }
    else
    {
        fprintf(stderr, "Weird address family %d\n", ss.ss.ss_family);
        return 1;
    }
    addr = evutil_inet_ntop(ss.ss.ss_family, inaddr, addrbuf,
                            sizeof(addrbuf));
    if (addr)
    {
        printf("Listening on %s:%d\n", addr, got_port);
        evutil_snprintf(uri_root, sizeof(uri_root),"http://%s:%d",addr,got_port);
    }
    else
    {
        fprintf(stderr, "evutil_inet_ntop failed\n");
        return 1;
    }
    return 0;
}

void stop_connect(struct event_base*base, struct evhttp*http)
{
    if(http)
        evhttp_free(http);
    if(base)
        event_base_free(base);
}

static int serve_some_http(void)
{
    struct event_base *base = NULL;
    struct evhttp *http = NULL;
    struct evhttp_bound_socket *handle = NULL;
    base = event_base_new();
    if (!base)
    {
        fprintf(stderr, "Couldn't create an event_base: exiting\n");
        return 1;
    }
    /* Create a new evhttp object to handle requests. */
    http = evhttp_new(base);
    if (!http)
    {
        fprintf(stderr, "couldn't create evhttp. Exiting.\n");
        stop_connect(base, http);
        return 1;
    }

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ctx,
                        SSL_OP_SINGLE_DH_USE |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_NO_SSLv2);

    /* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
   * We just hardcode a single curve which is reasonably decent.
   * See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh)
        die_most_horribly_from_openssl_error("EC_KEY_new_by_curve_name");
    if (1 != SSL_CTX_set_tmp_ecdh(ctx, ecdh))
        die_most_horribly_from_openssl_error("SSL_CTX_set_tmp_ecdh");

    /* Find and set up our server certificate. */
    const char *certificate_chain = "../keys/server-certificate-chain.pem"; //证书链
    const char *private_key = "../keys/server-private-key.pem";             //私钥
    server_setup_certs(ctx, certificate_chain, private_key);

    /* This is the magic that lets evhttp use SSL. */
    // evhttp_set_bevcb(http, bevcb, ctx);

    /* This is the callback that gets called when a request comes in. */
    evhttp_set_gencb(http, deal_get, NULL);

    /* Now we tell the evhttp what port to listen on */
    //设置监听端口
    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", serverPort);
    if (!handle)
    {
        fprintf(stderr, "couldn't bind to port %d. Exiting.\n",serverPort);
        stop_connect(base, http);
        return 1;
    }
    if (display_listen_sock(handle)) {
        stop_connect(base, http);
		return  1;
	}
    
    event_base_dispatch(base);
    /* not reached; runs forever */
    return 0;
}

int main(int argc, char **argv)
{
    common_setup(); /* Initialize OpenSSL */

    if (argc > 1)
    {
        char *end_ptr;
        // 提取出字符串里面的数字（当字符串不以0x开头时，0表示该字符串为10进制，否则为16进制）作为端口号
        long lp = strtol(argv[1], &end_ptr, 0);
        // 处理逻辑
        if (*end_ptr)
        {
            fprintf(stderr, "Invalid integer\n");
            return -1;
        }
        if (lp <= 0)
        {
            fprintf(stderr, "Port must be positive\n");
            return -1;
        }
        if (lp >= USHRT_MAX)
        {
            fprintf(stderr, "Port must fit 16-bit range\n");
            return -1;
        }
        serverPort = (unsigned short)lp;
    }

    /* now run http server (never returns) */
    return serve_some_http();
}
