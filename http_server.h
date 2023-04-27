#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/module.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#define MODULE_NAME "khttpd"

struct http_server_param {
    struct socket *listen_socket;
};

struct httpd_service {
    char *path;
    int is_stop;
    struct list_head head;
};

extern int http_server_daemon(void *arg);

#endif
