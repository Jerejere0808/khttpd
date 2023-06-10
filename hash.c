#include "hash.h"

char *hash_table_find(struct hash_table *ht,
                      char *key,
                      unsigned int *cache_size)
{
    struct hash_element *loop = NULL;
    struct list_head *bucket = &ht->buckets[strlen(key) % ht->bucket_size];
    char *cache_data = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(loop, bucket, node)
    {
        if (strcmp(loop->key, key) == 0) {
            *cache_size = loop->size;
            cache_data = kmalloc(loop->size + 1, GFP_KERNEL);
            memcpy(cache_data, loop->data, loop->size);
            break;
        }
    }
    rcu_read_unlock();

    return cache_data;
}

static void free_hash_element_rcu(struct rcu_head *rcu)
{
    struct hash_element *elem = container_of(rcu, struct hash_element, rcu);
    kfree(elem->key);
    kfree(elem->data);
    kfree(elem);
    return;
}

void *hash_table_remove_by_elem_pointer(struct hash_table *ht,
                                        struct hash_element *elem)
{
    void *data = NULL;
    spin_lock(&ht->lock);
    data = elem->data;
    list_del_rcu(&elem->node);
    call_rcu(&elem->rcu, free_hash_element_rcu);
    spin_unlock(&ht->lock);
    return data;
}

struct hash_element *hash_table_add(struct hash_table *ht,
                                    char *key,
                                    void *data,
                                    unsigned int size)
{
    struct hash_element *loop = NULL, *elem = NULL;
    struct list_head *bucket = &ht->buckets[strlen(key) % ht->bucket_size];

    elem = (struct hash_element *) kmalloc(sizeof(struct hash_element),
                                           GFP_KERNEL);
    if (!elem)
        return NULL;

    elem->key = (char *) kmalloc(strlen(key) + 1, GFP_KERNEL);
    memcpy(elem->key, key, strlen(key));

    elem->data = (void *) kmalloc(size + 1, GFP_KERNEL);
    memcpy(elem->data, data, size);

    elem->size = size;

    rcu_read_lock();
    list_for_each_entry_rcu(loop, bucket, node)
    {
        if (strcmp(loop->key, key) == 0) {
            kfree(elem->key);
            kfree(elem->data);
            kfree(elem);
            rcu_read_unlock();
            return NULL;
        }
    }
    rcu_read_unlock();

    spin_lock(&ht->lock);
    list_add_rcu(&elem->node, bucket);
    spin_unlock(&ht->lock);

    return elem;
}

struct hash_table *hash_table_create(unsigned int bucket_size)
{
    size_t size =
        sizeof(struct hash_table) + bucket_size * sizeof(struct list_head);
    struct hash_table *ht = kmalloc(size, GFP_KERNEL);
    if (bucket_size == 0)
        return NULL;

    if (!ht)
        return NULL;
    ht->bucket_size = bucket_size;
    ht->buckets =
        (struct list_head *) ((char *) ht + sizeof(struct hash_table));

    while (bucket_size--)
        INIT_LIST_HEAD(&ht->buckets[bucket_size]);

    return ht;
}
