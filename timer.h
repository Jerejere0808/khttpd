#ifndef KHTTPD_TIMER_H
#define KHTTPD_TIMER_H

#include <linux/module.h>
#include <net/sock.h>

#include "hash.h"
#include "http_server.h"

struct timer_heap;

typedef int (*timer_heap_compare)(struct timer_node *, struct timer_node *);
struct timer_heap {
    atomic_t size;
    atomic_t capacity;
    timer_heap_compare compare;
    struct timer_node **heap;
};

void server_init_timer_heap(struct timer_heap *server_timer_heap);
void server_free_timer(struct timer_heap *server_timer_heap);

void cache_handle_expired_timers(struct timer_heap *cache_timer_heap,
                                 struct hash_table *ht);
bool cache_add_timer(struct hash_element *elem,
                     size_t timeout,
                     struct timer_heap *cache_timer_heap);

#endif