#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/module.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include "hash.h"
#include "http_parser.h"

#define MODULE_NAME "khttpd"

struct http_server_param {
    struct socket *listen_socket;
};

struct httpd_service {
    char *path;
    int is_stop;
    struct list_head head;
};

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
    char *cache_buf;
    int cache_buf_pos;
    unsigned int cache_size;
};

struct httpd_work {
    struct socket *socket;
    struct list_head node;
    struct work_struct khttpd_work;
};

extern int http_server_daemon(void *arg);

#endif
