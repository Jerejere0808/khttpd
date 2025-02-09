#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>

#include "compress.h"
#include "http_server.h"
#include "timer.h"

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
#define BUCKET_SIZE 10

extern struct workqueue_struct *khttpd_wq;
struct httpd_service daemon_list = {.is_stop = 0};
struct hash_table *ht;
struct timer_heap cache_timer_heap;

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
             "%d\r\nContent-Encoding: deflate\r\nConnection: %s\r\n\r\n",
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

        char absolute_path[256];
        int path_pos = 0;
        memset(absolute_path, 0, 256);

        memcpy(absolute_path, daemon_list.path, strlen(daemon_list.path));
        path_pos += strlen(daemon_list.path);
        memcpy(absolute_path + path_pos, request->request_url,
               strlen(request->request_url));
        path_pos += strlen(request->request_url);

        if (strcmp(absolute_path, "/")) {
            memcpy(absolute_path + path_pos, "/", 1);
            path_pos += 1;
        }

        memcpy(absolute_path + path_pos, name, strlen(name));

        struct file *fp = filp_open(absolute_path, O_RDONLY, 0);
        if (IS_ERR(fp)) {
            pr_info("Open file failed");
            return 0;
        }

        struct tm result;
        time64_to_tm(fp->f_inode->i_mtime.tv_sec, 0, &result);

        char size_str[100];
        memset(size_str, 0, 100);
        snprintf(size_str, 100, "%lld", fp->f_inode->i_size);

        char *url =
            !strcmp(request->request_url, "/") ? "" : request->request_url;
        snprintf(buf, SEND_BUFFER_SIZE,
                 "%lx\r\n<tr><td><a href=\"%s/%s\">%s</a>    %04ld/%02d/%02d "
                 "%s Bytes</td></tr>\r\n",
                 34 + strlen(url) + (namelen << 1) + 14 + strlen(size_str) + 7,
                 url, name, name, result.tm_year + 1900, result.tm_mon + 1,
                 result.tm_mday, size_str);
        memcpy(request->cache_buf + request->cache_buf_pos, buf + 4,
               strlen(buf) - 4);
        request->cache_buf_pos += (strlen(buf) - 4);

        http_server_send(request->socket, buf, strlen(buf));

        filp_close(fp, NULL);
    }
    return 0;
}

static bool directory_handler(struct http_request *request, int keep_alive)
{
    struct file *fp;
    char *path_buf;
    char *connection;
    char *cache_data;
    unsigned int cache_size;

    path_buf = kzalloc(SEND_BUFFER_SIZE, GFP_KERNEL);
    if (!path_buf) {
        pr_err("can't allocate memory!\n");
        return false;
    }

    request->dir_context.actor = tracedir;

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

    cache_data = hash_table_find(ht, path_buf, &cache_size);
    if (cache_data) {
        if (S_ISDIR(fp->f_inode->i_mode)) {
            send_http_header(request->socket, 200, "OK", "text/html",
                             cache_size, connection);
            http_server_send(request->socket, cache_data, cache_size);

        } else if (S_ISREG(fp->f_inode->i_mode)) {
            send_http_header(request->socket, 200, "OK", "text/plain",
                             cache_size, connection);
            http_server_send(request->socket, cache_data, cache_size);
        }

        filp_close(fp, NULL);
        kfree(cache_data);
        kfree(path_buf);
        return true;
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

        request->cache_buf = (char *) kzalloc(20000, GFP_KERNEL);
        request->cache_buf_pos = 0;

        memcpy(request->cache_buf + request->cache_buf_pos, "<table><tbody>",
               14);
        request->cache_buf_pos += 14;

        iterate_dir(fp, &request->dir_context);

        memcpy(request->cache_buf + request->cache_buf_pos, "</tbody></table>",
               16);
        request->cache_buf_pos += 16;

        unsigned int tmp_size = 20000;
        char *tmp = kmalloc(tmp_size + 1, GFP_KERNEL);
        memcpy(tmp, request->cache_buf, tmp_size);
        request->cache_size = tmp_size;
        deflate_compress(tmp, tmp_size, request->cache_buf,
                         &request->cache_size);
        kfree(tmp);

        snprintf(send_buf, SEND_BUFFER_SIZE,
                 "16\r\n</table></body></html>\r\n");
        http_server_send(request->socket, send_buf, strlen(send_buf));

        snprintf(send_buf, SEND_BUFFER_SIZE, "0\r\n\r\n");
        http_server_send(request->socket, send_buf, strlen(send_buf));

    } else if (S_ISREG(fp->f_inode->i_mode)) {
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int len = read_file(fp, read_data);

        request->cache_buf = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        request->cache_size = len;

        deflate_compress(read_data, len, request->cache_buf,
                         &request->cache_size);

        send_http_header(request->socket, 200, "OK", "text/plain",
                         request->cache_size, connection);
        http_server_send(request->socket, request->cache_buf,
                         request->cache_size);

        kfree(read_data);
    }

    struct hash_element *elem =
        hash_table_add(ht, path_buf, request->cache_buf, request->cache_size);
    if (elem)
        cache_add_timer(elem, 10000, &cache_timer_heap);

    kfree(request->cache_buf);
    kfree(cache_data);
    filp_close(fp, NULL);
    kfree(path_buf);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    // pr_info("requested_url = %s\n", request->request_url);
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
    // pr_err("http_server_worker_CMWQ\n");
    struct httpd_work *worker =
        container_of(work, struct httpd_work, khttpd_work);
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
        // pr_info("request_url = %s\n", request.request_url);
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
    struct httpd_work *work;

    if (!(work = kmalloc(sizeof(struct httpd_work), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    INIT_WORK(&work->khttpd_work, http_server_worker_CMWQ);
    list_add(&work->node, &daemon_list.head);

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct httpd_work *l, *tar;
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
    struct http_server_param *param = (struct http_server_param *) arg;
    struct work_struct *work;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon_list.head);

    ht = hash_table_create(BUCKET_SIZE);
    spin_lock_init(&ht->lock);

    server_init_timer_heap(&cache_timer_heap);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, SOCK_NONBLOCK);
        cache_handle_expired_timers(&cache_timer_heap, ht);

        if (err < 0) {
            if (signal_pending(current))
                break;
            // pr_err("kernel_accept() error: %d\n", err);
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
    server_free_timer(&cache_timer_heap);
    free_work();

    return 0;
}
