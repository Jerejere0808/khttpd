#ifndef KHTTPD_TIMER_NODE_H
#define KHTTPD_TIMER_NODE_H

#include <linux/module.h>

struct timer_node {
    size_t time_limit;
};

#endif