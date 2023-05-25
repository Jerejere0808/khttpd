#include "timer.h"
#include <linux/time64.h>

#define HEAP_DEFAULT_SIZE 5000

static atomic_t current_msec;

static bool timer_heap_init(struct timer_heap *server_timer_heap,
                            timer_heap_compare comp,
                            size_t capacity)
{
    server_timer_heap->heap =
        kmalloc(sizeof(struct timer_node *) * (capacity + 1), GFP_KERNEL);
    if (!server_timer_heap->heap) {
        pr_err("Init timer heap err: kmalloc fails.");
        return 0;
    }

    atomic_set(&server_timer_heap->size, 0);
    atomic_set(&server_timer_heap->capacity, capacity + 1);
    server_timer_heap->compare = comp;
    return 1;
}

static void timer_heap_delete(struct timer_heap *server_timer_heap)
{
    kfree(server_timer_heap->heap);
    return;
}

static bool timer_heap_is_empty(struct timer_heap *server_timer_heap)
{
    return !atomic_read(&server_timer_heap->size);
}

static struct timer_node *timer_heap_get_min(
    struct timer_heap *server_timer_heap)
{
    return (!timer_heap_is_empty(server_timer_heap))
               ? server_timer_heap->heap[1]
               : NULL;
}

static void timer_heap_swap(struct timer_heap *server_timer_heap,
                            size_t i,
                            size_t j)
{
    struct timer_node *tmp = server_timer_heap->heap[i];
    server_timer_heap->heap[i] = server_timer_heap->heap[j];
    server_timer_heap->heap[j] = tmp;
    return;
}

static size_t timer_heap_sink(struct timer_heap *server_timer_heap,
                              size_t start)
{
    size_t size = (size_t) atomic_read(&server_timer_heap->size);
    size_t i = start;
    size_t j = i * 2;
    while (j <= size) {
        if (j < size &&
            server_timer_heap->compare(server_timer_heap->heap[j + 1],
                                       server_timer_heap->heap[j])) {
            j++;
        }
        if (server_timer_heap->compare(server_timer_heap->heap[i],
                                       server_timer_heap->heap[j])) {
            break;
        }
        timer_heap_swap(server_timer_heap, i, j);
        i = j;
        j *= 2;
    }
    return i;
}

static bool cache_heap_delete_min(struct timer_heap *cache_timer_heap,
                                  struct hash_table *ht)
{
    size_t size;
    struct timer_node *victim;

    if (timer_heap_is_empty(cache_timer_heap))
        return 0;

    while (1) {
        if (timer_heap_is_empty(cache_timer_heap))
            return true;

        size = atomic_read(&cache_timer_heap->size);
        timer_heap_swap(cache_timer_heap, 1, size);

        if (size == atomic_read(&cache_timer_heap->size)) {
            victim = cache_timer_heap->heap[size];
            break;
        }

        timer_heap_swap(cache_timer_heap, 1, size);
    }

    struct hash_element *elem =
        container_of(victim, struct hash_element, timer_item);
    hash_table_remove_by_elem_pointer(ht, elem);

    atomic_set(&cache_timer_heap->size, --size);
    timer_heap_sink(cache_timer_heap, 1);

    return 1;
}


static inline bool timer_heap_cmpxchg(struct timer_node **var,
                                      long long *old,
                                      long long neu)
{
    bool ret;
    union u64 {
        struct {
            int low, high;
        } s;
        long long ui;
    } cmp = {.ui = *old}, with = {.ui = neu};

    /**
     * 1. cmp.s.hi:cmp.s.lo compare with *var
     * 2. if equall, set ZF and copy with.s.hi:with.s.lo to *var
     * 3. if not equall， clear ZF and copy *var to cmp.s.hi:cmp.s.lo
     */
    __asm__ __volatile__("lock cmpxchg8b %1\n\tsetz %0"
                         : "=q"(ret), "+m"(*var), "+d"(cmp.s.high),
                           "+a"(cmp.s.low)
                         : "c"(with.s.high), "b"(with.s.low)
                         : "cc", "memory");
    if (!ret)
        *old = cmp.ui;
    return ret;
}

void timer_heap_insert(struct timer_heap *server_timer_heap,
                       struct timer_node *item)
{
    struct timer_node **slot;
    size_t old_size;
    long long old;
    bool restart = false;
    do {
        old_size = atomic_read(&server_timer_heap->size);

        slot = (struct timer_node **) &server_timer_heap->heap[old_size + 1];
        old = (long long) *slot;

        restart = false;
        if (old_size == atomic_read(&server_timer_heap->size)) {
            if (!timer_heap_cmpxchg(slot, &old, (long long) item)) {
                restart = true;
            }
        } else {
            restart = true;
        }
    } while (restart);
    // pr_err("before increase %d", atomic_read(&server_timer_heap->size));
    atomic_inc(&server_timer_heap->size);
    // pr_err("after increase %d", atomic_read(&server_timer_heap->size));
    return;
}

int timer_node_cmp(struct timer_node *a, struct timer_node *b)
{
    return (a->time_limit < b->time_limit) ? 1 : 0;
}

static void timer_update_current_msec(void)
{
    struct timespec64 tv;
    ktime_get_ts64(&tv);
    atomic_set(&current_msec, tv.tv_sec * 1000 + tv.tv_nsec / 1000000);
    return;
}

void server_init_timer_heap(struct timer_heap *server_timer_heap)
{
    timer_heap_init(server_timer_heap, timer_node_cmp, HEAP_DEFAULT_SIZE);
    timer_update_current_msec();
    return;
}

void server_free_timer(struct timer_heap *server_timer_heap)
{
    timer_heap_delete(server_timer_heap);
    return;
}

void cache_handle_expired_timers(struct timer_heap *cache_timer_heap,
                                 struct hash_table *ht)
{
    while (!timer_heap_is_empty(cache_timer_heap)) {
        struct timer_node *node = timer_heap_get_min(cache_timer_heap);
        timer_update_current_msec();
        if (node->time_limit > atomic_read(&current_msec))
            return;
        cache_heap_delete_min(cache_timer_heap, ht);
    }
    return;
}

bool cache_add_timer(struct hash_element *elem,
                     size_t timeout,
                     struct timer_heap *cache_timer_heap)
{
    timer_update_current_msec();
    elem = (struct hash_element *) elem;
    (elem->timer_item).time_limit = atomic_read(&current_msec) + timeout;

    timer_heap_insert(cache_timer_heap, &elem->timer_item);

    return 1;
}
