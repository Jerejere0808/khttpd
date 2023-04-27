#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct list_head node;
    struct work_struct khttpd_work;
    struct dir_context dir_context;
};

extern struct workqueue_struct *khttpd_wq;
struct httpd_service daemon_list = {.is_stop = 0};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static void send_http_header(struct socket *sock,
                             int status,
                             char *status_msg,
                             char *content_type,
                             int content_length,
                             char *connection)
{
    char buf[SEND_BUFFER_SIZE] = {0};

    snprintf(buf, SEND_BUFFER_SIZE,
             "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: "
             "%d\r\nConnection: %s\r\n\r\n",
             status, status_msg, content_type, content_length, connection);

    http_server_send(sock, buf, strlen(buf));
}

static void send_http_content(struct socket *sock, char *content)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    snprintf(buf, SEND_BUFFER_SIZE, "%s\r\n", content);
    http_server_send(sock, buf, strlen(buf));
}

static void catstr(char *res, char *WWWROOT, char *http_request_url)
{
    int WWWROOT_size = strlen(WWWROOT);
    int http_request_url_size = strlen(http_request_url);
    memset(res, 0, 256);
    memcpy(res, WWWROOT, WWWROOT_size);
    memcpy(res + WWWROOT_size, http_request_url, http_request_url_size);
}

static inline int read_file(struct file *fp, char *buf)
{
    return kernel_read(fp, buf, fp->f_inode->i_size, 0);
}

static int tracedir(struct dir_context *dir_context,
                    const char *name,
                    int namelen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};
        char *url =
            !strcmp(request->request_url, "/") ? "" : request->request_url;
        snprintf(buf, SEND_BUFFER_SIZE,
                 "%lx\r\n<tr><td><a href=\"%s/%s\">%s</a></td></tr>\r\n",
                 34 + strlen(url) + (namelen << 1), url, name, name);
        http_server_send(request->socket, buf, strlen(buf));
    }
    return 0;
}

static bool directory_handler(struct http_request *request, int keep_alive)
{
    struct file *fp;
    char *path_buf;

    path_buf = kzalloc(SEND_BUFFER_SIZE, GFP_KERNEL);
    if (!path_buf) {
        pr_err("can't allocate memory!\n");
        return false;
    }

    request->dir_context.actor = tracedir;

    char *connection;
    connection = keep_alive ? "KeepAlive" : "Close";

    if (request->method != HTTP_GET) {
        send_http_header(request->socket, 501, "Not Implemented", "text/plain",
                         19, connection);
        send_http_content(request->socket, "501 Not Implemented");
        return false;
    }

    catstr(path_buf, daemon_list.path, request->request_url);
    fp = filp_open(path_buf, O_RDONLY, 0);

    if (IS_ERR(fp)) {
        pr_info("Open file failed");
        send_http_header(request->socket, 404, "Not Found", "text/plain", 13,
                         "Close");
        send_http_content(request->socket, "404 Not Found");
        return false;
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {
        char send_buf[SEND_BUFFER_SIZE] = {0};
        snprintf(send_buf, SEND_BUFFER_SIZE, "%s%s%s", "HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/html\r\n",
                 "Transfer-Encoding: chunked\r\n\r\n");
        http_server_send(request->socket, send_buf, strlen(send_buf));

        snprintf(send_buf, SEND_BUFFER_SIZE, "7B\r\n%s%s%s%s",
                 "<html><head><style>\r\n",
                 "body{font-family: monospace; font-size: 15px;}\r\n",
                 "td {padding: 1.5px 6px;}\r\n",
                 "</style></head><body><table>\r\n");
        http_server_send(request->socket, send_buf, strlen(send_buf));

        iterate_dir(fp, &request->dir_context);

        snprintf(send_buf, SEND_BUFFER_SIZE,
                 "16\r\n</table></body></html>\r\n");
        http_server_send(request->socket, send_buf, strlen(send_buf));

        snprintf(send_buf, SEND_BUFFER_SIZE, "0\r\n\r\n");
        http_server_send(request->socket, send_buf, strlen(send_buf));

    } else if (S_ISREG(fp->f_inode->i_mode)) {
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int ret = read_file(fp, read_data);

        send_http_header(request->socket, 200, "OK", "text/plain", ret,
                         connection);
        http_server_send(request->socket, read_data, ret);

        kfree(read_data);
    }

    filp_close(fp, NULL);
    kfree(path_buf);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    pr_info("requested_url = %s\n", request->request_url);
    directory_handler(request, keep_alive);
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker_CMWQ(struct work_struct *work)
{
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) worker->socket;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!daemon_list.is_stop) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        // pr_info("buf = %s\n", buf);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    kfree(buf);
    return;
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;

    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    INIT_WORK(&work->khttpd_work, http_server_worker_CMWQ);
    list_add(&work->node, &daemon_list.head);

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct http_request *l, *tar;
    /* cppcheck-suppress uninitvar */

    list_for_each_entry_safe (tar, l, &daemon_list.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    // struct task_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;
    struct work_struct *work;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon_list.head);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        if (unlikely(!(work = create_work(socket)))) {
            printk(KERN_ERR MODULE_NAME
                   ": create work error, connection closed\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        /* start server worker */
        queue_work(khttpd_wq, work);
    }

    printk(MODULE_NAME ": daemon shutdown in progress...\n");

    daemon_list.is_stop = 1;
    free_work();

    return 0;
}
