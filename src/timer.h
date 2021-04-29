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

#ifndef ANPNETSTACK_TIMER_H
#define ANPNETSTACK_TIMER_H

#include "systems_headers.h"
#include "linklist.h"
#define timer_dbg(msg, t)                                               \
    do {                                                                \
        print_debug("Timer at %d: "msg": expires %d", tick, t->expires); \
    } while (0)

struct timer {
    struct list_head list;
    int refcnt;
    uint32_t expires;
    int cancelled;
    void *(*handler)(void *);
    void *arg;
    pthread_mutex_t lock;
};

struct timer *timer_add(uint32_t expire, void *(*handler)(void *), void *arg);
void timer_oneshot(uint32_t expire, void *(*handler)(void *), void *arg);
void timer_release(struct timer *t);
void timer_cancel(struct timer *t);
void *timers_start();
int timer_get_tick();

#endif //ANPNETSTACK_TIMER_H
