/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef ANPNETSTACK_SUBUFF_H
#define ANPNETSTACK_SUBUFF_H

#include "linklist.h"
#include "systems_headers.h"

// The kernel has socket kernel buffer (SKB), we have socket user buffer - both are equally ugly and painful ;)
// for the brave among us : https://elixir.bootlin.com/linux/latest/source/include/linux/skbuff.h#L711
// for the documentation, a good source, http://vger.kernel.org/~davem/skb.html
// coming back to our small userspace networking stack...

struct subuff {
    struct list_head list;
    struct rtentry *rt;
    struct anp_netdev *dev;
    int refcnt;
    uint16_t protocol;
    uint32_t len;
    uint32_t dlen;
    uint32_t seq;
    uint32_t end_seq;
    uint8_t *end;
    uint8_t *head;
    uint8_t *data;
    uint8_t *payload;
};

struct subuff_head {
    struct list_head head;
    uint32_t queue_len;
};

struct subuff *alloc_sub(unsigned int size);
void free_sub(struct subuff *skb);
uint8_t *sub_push(struct subuff *skb, unsigned int len);
uint8_t *sub_head(struct subuff *skb);
void *sub_reserve(struct subuff *skb, unsigned int len);
void sub_reset_header(struct subuff *skb);

static inline uint32_t sub_queue_len(const struct subuff_head *list)
{
    return list->queue_len;
}

static inline void sub_queue_init(struct subuff_head *list)
{
    list_init(&list->head);
    list->queue_len = 0;
}

static inline void sub_queue_add(struct subuff_head *list, struct subuff *new, struct subuff *next)
{
    list_add_tail(&new->list, &next->list);
    list->queue_len += 1;
}

static inline void sub_queue_tail(struct subuff_head *list, struct subuff *new)
{
    list_add_tail(&new->list, &list->head);
    list->queue_len += 1;
}

static inline struct subuff *sub_dequeue(struct subuff_head *list)
{
    struct subuff *skb = list_first_entry(&list->head, struct subuff, list);
    list_del(&skb->list);
    list->queue_len -= 1;

    return skb;
}

static inline int sub_queue_empty(const struct subuff_head *list)
{
    return sub_queue_len(list) < 1;
}

static inline struct subuff *sub_peek(struct subuff_head *list)
{
    if (sub_queue_empty(list)) return NULL;

    return list_first_entry(&list->head, struct subuff, list);
}

static inline void sub_queue_free(struct subuff_head *list)
{
    struct subuff *skb = NULL;

    while ((skb = sub_peek(list)) != NULL) {
        sub_dequeue(list);
        skb->refcnt--;
        free_sub(skb);
    }
}

#endif //ANPNETSTACK_SUBUFF_H
