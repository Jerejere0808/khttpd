#ifndef KHTTPD_HASH_H
#define KHTTPD_HASH_H

#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "timer_node.h"

struct hash_element {
    struct list_head node;
    char *key;
    void *data;
    unsigned int size;
    struct timer_node timer_item;
    struct rcu_head rcu;
};

struct hash_table {
    unsigned int bucket_size;
    struct list_head *buckets;
    spinlock_t lock;
};

char *hash_table_find(struct hash_table *ht,
                      char *key,
                      unsigned int *cache_size);
void *hash_table_remove(struct hash_table *ht, char *key);
void *hash_table_remove_by_elem_pointer(struct hash_table *ht,
                                        struct hash_element *elem);
struct hash_element *hash_table_add(struct hash_table *ht,
                                    char *key,
                                    void *data,
                                    unsigned int size);
struct hash_table *hash_table_create(unsigned int bucket_size);

#endif
