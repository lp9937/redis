/* A simple event-driven programming library. Originally I wrote this code
 * for the Jim's event-loop (Jim is a Tcl interpreter) but later translated
 * it in form of a library for easy reuse.
 *
 * Copyright (c) 2006-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "ae.h"
#include "anet.h"

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "zmalloc.h"
#include "config.h"

/* Include the best multiplexing layer supported by this system.
 * The following should be ordered by performances, descending. */
#ifdef HAVE_EVPORT
#include "ae_evport.c"
#else
    #ifdef HAVE_EPOLL
    #include "ae_epoll.c"
    #else
        #ifdef HAVE_KQUEUE
        #include "ae_kqueue.c"
        #else
        #include "ae_select.c"
        #endif
    #endif
#endif

/*
 * 初始化事件处理器状态
 */
aeEventLoop *aeCreateEventLoop(int setsize) {
    aeEventLoop *eventLoop;
    int i;

    monotonicInit();    /* just in case the calling app didn't initialize */

    if ((eventLoop = zmalloc(sizeof(*eventLoop))) == NULL) goto err;
    // 初始化文件事件结构
    eventLoop->events = zmalloc(sizeof(aeFileEvent)*setsize);
    // 初始化已就绪文件事件结构
    eventLoop->fired = zmalloc(sizeof(aeFiredEvent)*setsize);
    if (eventLoop->events == NULL || eventLoop->fired == NULL) goto err;
    // 设置数组大小
    eventLoop->setsize = setsize;

    // 初始化时间事件结构
    eventLoop->timeEventHead = NULL;
    eventLoop->timeEventNextId = 0;
    eventLoop->stop = 0;
    eventLoop->maxfd = -1;
    eventLoop->beforesleep = NULL;
    eventLoop->aftersleep = NULL;
    eventLoop->flags = 0;
    if (aeApiCreate(eventLoop) == -1) goto err;
    /* Events with mask == AE_NONE are not set. So let's initialize the
     * vector with it. */
    // 初始化监听事件
    for (i = 0; i < setsize; i++)
        eventLoop->events[i].mask = AE_NONE;
    return eventLoop;

err:
    if (eventLoop) {
        zfree(eventLoop->events);
        zfree(eventLoop->fired);
        zfree(eventLoop);
    }
    return NULL;
}

/* Return the current set size. */
int aeGetSetSize(aeEventLoop *eventLoop) {
    return eventLoop->setsize;
}

/* Tells the next iteration/s of the event processing to set timeout of 0. */
void aeSetDontWait(aeEventLoop *eventLoop, int noWait) {
    if (noWait)
        eventLoop->flags |= AE_DONT_WAIT;
    else
        eventLoop->flags &= ~AE_DONT_WAIT;
}

/* Resize the maximum set size of the event loop.
 * If the requested set size is smaller than the current set size, but
 * there is already a file descriptor in use that is >= the requested
 * set size minus one, AE_ERR is returned and the operation is not
 * performed at all.
 *
 * Otherwise AE_OK is returned and the operation is successful. */
int aeResizeSetSize(aeEventLoop *eventLoop, int setsize) {
    int i;

    if (setsize == eventLoop->setsize) return AE_OK;
    if (eventLoop->maxfd >= setsize) return AE_ERR;
    if (aeApiResize(eventLoop,setsize) == -1) return AE_ERR;

    eventLoop->events = zrealloc(eventLoop->events,sizeof(aeFileEvent)*setsize);
    eventLoop->fired = zrealloc(eventLoop->fired,sizeof(aeFiredEvent)*setsize);
    eventLoop->setsize = setsize;

    /* Make sure that if we created new slots, they are initialized with
     * an AE_NONE mask. */
    for (i = eventLoop->maxfd+1; i < setsize; i++)
        eventLoop->events[i].mask = AE_NONE;
    return AE_OK;
}

void aeDeleteEventLoop(aeEventLoop *eventLoop) {
    aeApiFree(eventLoop);
    zfree(eventLoop->events);
    zfree(eventLoop->fired);

    /* Free the time events list. */
    aeTimeEvent *next_te, *te = eventLoop->timeEventHead;
    while (te) {
        next_te = te->next;
        zfree(te);
        te = next_te;
    }
    zfree(eventLoop);
}

void aeStop(aeEventLoop *eventLoop) {
    eventLoop->stop = 1;
}
/**
 * 接收一个套接字描述符、一个事件类型，以及一个事件处理器作为参数，
 * 将给定套接字的给定事件加入到 I/O 多路复用程序的监听范围之内，
 * 并对事件和事件处理器进行关联
 */
int aeCreateFileEvent(aeEventLoop *eventLoop, int fd, int mask,
        aeFileProc *proc, void *clientData)
{
    if (fd >= eventLoop->setsize) {
        errno = ERANGE;
        return AE_ERR;
    }
    aeFileEvent *fe = &eventLoop->events[fd];
    // 将 fd 的 mask 事件加入到 I/O 多路复用程序的监听范围之内
    if (aeApiAddEvent(eventLoop, fd, mask) == -1)
        return AE_ERR;
    fe->mask |= mask;
    if (mask & AE_READABLE) fe->rfileProc = proc;
    if (mask & AE_WRITABLE) fe->wfileProc = proc;
    fe->clientData = clientData;
    if (fd > eventLoop->maxfd)
        eventLoop->maxfd = fd;
    return AE_OK;
}
/**
 * 接收一个套接字描述符和一个事件类型，让 I/O 多路复用程序取消对
 * 给定套接字的给定事件的监听，并取消事件和事件处理器之间的关联
 */
void aeDeleteFileEvent(aeEventLoop *eventLoop, int fd, int mask)
{
    if (fd >= eventLoop->setsize) return;
    // 描述符 fd 对应的文件事件
    aeFileEvent *fe = &eventLoop->events[fd];
    // 没有任何监听的事件
    if (fe->mask == AE_NONE) return;

    /* We want to always remove AE_BARRIER if set when AE_WRITABLE
     * is removed. */
    /**
     * 当移除 AE_WRITABLE 事件的监听时，总是一并移除 AE_BARRIER 事件的监听
     */
    if (mask & AE_WRITABLE) mask |= AE_BARRIER;
    /**
     * 将 fd 的 mask 事件从 I/O 多路复用程序的监听范围内移除
     */
    aeApiDelEvent(eventLoop, fd, mask);
    fe->mask = fe->mask & (~mask);
    if (fd == eventLoop->maxfd && fe->mask == AE_NONE) {
        /* Update the max fd */
        // 更新最大文件描述符
        int j;

        for (j = eventLoop->maxfd-1; j >= 0; j--)
            if (eventLoop->events[j].mask != AE_NONE) break;
        eventLoop->maxfd = j;
    }
}
/**
 * 接收一个套接字描述符，返回该套接字正在被监听的事件类型
 */
int aeGetFileEvents(aeEventLoop *eventLoop, int fd) {
    if (fd >= eventLoop->setsize) return 0;
    // 获取描述符对应的文件事件
    aeFileEvent *fe = &eventLoop->events[fd];

    return fe->mask;
}

/**
 * 创建时间事件
 */
long long aeCreateTimeEvent(aeEventLoop *eventLoop, long long milliseconds,
        aeTimeProc *proc, void *clientData,
        aeEventFinalizerProc *finalizerProc)
{
    long long id = eventLoop->timeEventNextId++;
    aeTimeEvent *te;

    te = zmalloc(sizeof(*te));
    if (te == NULL) return AE_ERR;
    te->id = id;
    te->when = getMonotonicUs() + milliseconds * 1000;
    te->timeProc = proc;
    te->finalizerProc = finalizerProc;
    te->clientData = clientData;
    te->prev = NULL;
    te->next = eventLoop->timeEventHead;
    te->refcount = 0;
    if (te->next)
        te->next->prev = te;
    eventLoop->timeEventHead = te;
    return id;
}
/**
 * 删除时间事件
 */
int aeDeleteTimeEvent(aeEventLoop *eventLoop, long long id)
{
    aeTimeEvent *te = eventLoop->timeEventHead;
    while(te) {
        if (te->id == id) {
            te->id = AE_DELETED_EVENT_ID;
            return AE_OK;
        }
        te = te->next;
    }
    return AE_ERR; /* NO event with the specified ID found */
}

/* How many milliseconds until the first timer should fire.
 *
 * 离第一个计时器触发还有多少毫秒
 * 
 * If there are no timers, -1 is returned.
 * 
 * 如果没有计时器，则返回-1
 *
 * Note that's O(N) since time events are unsorted.
 * 
 * 注意：时间复杂度是 O(N)， 因为时间事件是未排序的
 * 
 * Possible optimizations (not needed by Redis so far, but...):
 * 
 * 可能的优化:
 * 
 * 1) Insert the event in order, so that the nearest is just the head.
 *    Much better but still insertion or deletion of timers is O(N).
 * 
 * 按顺序插入事件，最近的事件放在前面。
 * 但计时器插入或删除的时间复制都任然是 O(N)
 * 
 * 2) Use a skiplist to have this operation as O(1) and insertion as O(log(N)).
 * 
 * 使用跳表来实现此功能，这样该操作的时间复制度为 O(1)，
 * 而插入的时间复制度为 O(log(N))
 */
static long msUntilEarliestTimer(aeEventLoop *eventLoop) {
    // 时间事件
    aeTimeEvent *te = eventLoop->timeEventHead;
    if (te == NULL) return -1;

    aeTimeEvent *earliest = NULL;
    while (te) {
        if (!earliest || te->when < earliest->when)
            earliest = te;
        te = te->next;
    }

    monotime now = getMonotonicUs();
    return (now >= earliest->when)
            ? 0 : (long)((earliest->when - now) / 1000);
}

/* Process time events */
/**
 * 处理所有已到达的时间事件
 */
static int processTimeEvents(aeEventLoop *eventLoop) {
    int processed = 0;
    aeTimeEvent *te;
    long long maxId;
    
    // 遍历链表
    // 执行那些已经到达的事件
    te = eventLoop->timeEventHead;
    maxId = eventLoop->timeEventNextId-1;
    monotime now = getMonotonicUs();
    while(te) {
        long long id;

        /* Remove events scheduled for deletion. 
         * 移除计划删除的事件
         */
        if (te->id == AE_DELETED_EVENT_ID) {
            aeTimeEvent *next = te->next;
            /* If a reference exists for this timer event,
             * don't free it. This is currently incremented
             * for recursive timerProc calls
             * 
             * 如果此计时器事件存在引用，请不要释放它。
             * 随着递归调用 timerProc 函数，此值递增
             * */
            if (te->refcount) {
                te = next;
                continue;
            }
            if (te->prev)
                te->prev->next = te->next;
            else
                eventLoop->timeEventHead = te->next;
            if (te->next)
                te->next->prev = te->prev;
            if (te->finalizerProc) {
                te->finalizerProc(eventLoop, te->clientData);
                now = getMonotonicUs();
            }
            zfree(te);
            te = next;
            continue;
        }

        /* Make sure we don't process time events created by time events in
         * this iteration. Note that this check is currently useless: we always
         * add new timers on the head, however if we change the implementation
         * detail, this check may be useful again: we keep it here for future
         * defense. 
         * 
         * 跳过无效事件
         * */
        if (te->id > maxId) {
            te = te->next;
            continue;
        }

        // 事件的执行时间已经达到，执行该时间事件
        if (te->when <= now) {
            int retval;

            id = te->id;
            te->refcount++;
            // 执行时间事件处理器，并获取返回值
            retval = te->timeProc(eventLoop, id, te->clientData);
            te->refcount--;
            processed++;
            now = getMonotonicUs();
            // 判断是否需要循环执行这个时间事件
            if (retval != AE_NOMORE) {
                // 需要循环执行，计算下一次执行该事件的时间
                te->when = now + retval * 1000;
            } else {
                // 不需要循环执行，则标记该时间事件为待删除状态
                te->id = AE_DELETED_EVENT_ID;
            }
        }
        te = te->next;
    }
    return processed;
}

/* Process every pending time event, then every pending file event
 * (that may be registered by time event callbacks just processed).
 *
 * 因为文件事件可以由时间事件回掉注册，所以先处理每个挂起的时间事件，
 * 然后处理每个挂起的文件事件。
 * 
 * Without special flags the function sleeps until some file event
 * fires, or when the next time event occurs (if any).
 * 
 * 如果没有特殊标志，函数将一直休眠，直到某些文件事件触发或下一次时间事件发生
 *
 * If flags is 0, the function does nothing and returns.
 * 
 * 如果 flags 的值是 0，函数不执行任何操作，直接返回
 * 
 * if flags has AE_ALL_EVENTS set, all the kind of events are processed.
 * 
 * 如果 flags 的值是 AE_ALL_EVENTS，所有类型的事件都会被处理
 * 
 * if flags has AE_FILE_EVENTS set, file events are processed.
 * 
 * 如果 flags 的值是 AE_FILE_EVENTS，文件事件被处理
 * 
 * if flags has AE_TIME_EVENTS set, time events are processed.
 * 
 * 如果 flags 的值是 AE_TIME_EVENTS，时间事件被处理
 * 
 * if flags has AE_DONT_WAIT set the function returns ASAP until all
 * the events that's possible to process without to wait are processed.
 * 
 * 如果 flags 的值是 AE_DONT_WAIT，直到处理完所有不必等待的事件后，
 * 函数会尽快返回，
 * 
 * if flags has AE_CALL_AFTER_SLEEP set, the aftersleep callback is called.
 * 
 * 如果 flags 的值是 AE_CALL_AFTER_SLEEP，调用 aftersleep 回调。
 * 
 * if flags has AE_CALL_BEFORE_SLEEP set, the beforesleep callback is called.
 * 
 * 如果 flags 的值是 AE_CALL_BEFORE_SLEEP，调用 beforesleep 回调。
 *
 * The function returns the number of events processed. 
 * 
 * 函数返回被处理事件的数目
 * 
 * 该函数是文件事件分派器，它先调用 aeApiPoll 函数来等待事件产生，
 * 然后遍历所产生的事件，并调用相应的事件处理器来处理这些事件 
 * 
 * */
int aeProcessEvents(aeEventLoop *eventLoop, int flags)
{
    int processed = 0, numevents;

    /* Nothing to do? return ASAP */
    /**
     * 如果 flags 既不是时间事件，也不是文件事件，则什么也不做，直接返回 0
     */
    if (!(flags & AE_TIME_EVENTS) && !(flags & AE_FILE_EVENTS)) return 0;

    /* Note that we want to call select() even if there are no
     * file events to process as long as we want to process time
     * events, in order to sleep until the next time event is ready
     * to fire. */
    if (eventLoop->maxfd != -1 ||
        ((flags & AE_TIME_EVENTS) && !(flags & AE_DONT_WAIT))) {
        int j;
        struct timeval tv, *tvp;
        long msUntilTimer = -1;
        
        // 获取最近的时间事件还有多久触发
        if (flags & AE_TIME_EVENTS && !(flags & AE_DONT_WAIT))
            // 最近时间事件发生时间与当前时间的差值
            msUntilTimer = msUntilEarliestTimer(eventLoop);

        // 如果差值大于等于0，表示最近有时间事件发生
        if (msUntilTimer >= 0) {
            // 根据差值计算文件事件阻塞的时间
            tv.tv_sec = msUntilTimer / 1000;
            tv.tv_usec = (msUntilTimer % 1000) * 1000;
            tvp = &tv;
        } else {
            /* If we have to check for events but need to return
             * ASAP because of AE_DONT_WAIT we need to set the timeout
             * to zero */
            /**
             * 最近没有时间事件，且 flags 包含 AE_DONT_WAIT，
             * 则设置文件事件不阻塞
             */
            if (flags & AE_DONT_WAIT) {
                tv.tv_sec = tv.tv_usec = 0;
                tvp = &tv;
            } else {
                // 文件事件可以阻塞直到有事件到达为止
                /* Otherwise we can block */
                tvp = NULL; /* wait forever */
            }
        }

        // 设置文件事件不阻塞
        if (eventLoop->flags & AE_DONT_WAIT) {
            tv.tv_sec = tv.tv_usec = 0;
            tvp = &tv;
        }

        // 如果 flags 被 AE_CALL_BEFORE_SLEEP 标记，则调用 beforesleep 回调
        if (eventLoop->beforesleep != NULL && flags & AE_CALL_BEFORE_SLEEP)
            eventLoop->beforesleep(eventLoop);

        /* Call the multiplexing API, will return only on timeout or when
         * some event fires. */
        /**
         * 调用多路复用API，阻塞等待直到超时或一些事件被触发，
         * 获得产生事件的个数
         */
        numevents = aeApiPoll(eventLoop, tvp);

        /* After sleep callback. */
        // 如果 flags 包含 AE_CALL_AFTER_SLEEP，则调用 aftersleep 回调
        if (eventLoop->aftersleep != NULL && flags & AE_CALL_AFTER_SLEEP)
            eventLoop->aftersleep(eventLoop);

        // 循环遍历处理产生的事件
        for (j = 0; j < numevents; j++) {
            // 触发的文件事件
            aeFileEvent *fe = &eventLoop->events[eventLoop->fired[j].fd];
            int mask = eventLoop->fired[j].mask;
            int fd = eventLoop->fired[j].fd;
            // 记录当前文件描述符触发的事件数
            int fired = 0; /* Number of events fired for current fd. */

            /* Normally we execute the readable event first, and the writable
             * event later. This is useful as sometimes we may be able
             * to serve the reply of a query immediately after processing the
             * query.
             *
             * 通常先执行读事件，再执行写事件。这对于服务器处理查询后，
             * 立即向客户端回复查询很有用。
             * 
             * However if AE_BARRIER is set in the mask, our application is
             * asking us to do the reverse: never fire the writable event
             * after the readable. In such a case, we invert the calls.
             * This is useful when, for instance, we want to do things
             * in the beforeSleep() hook, like fsyncing a file to disk,
             * before replying to a client. 
             * 
             * 如果 AE_BARRIER 被设置在 mask 中，要求执行顺序反过来：
             * 永远不要在可读事件之后触发可写事件。
             * 例如在 beforeSleep() 的回调函数中，回复客户端以前将文件同步到磁盘
             * 这种情况下反过来调用是很有用的
             * */
            int invert = fe->mask & AE_BARRIER;

            /* Note the "fe->mask & mask & ..." code: maybe an already
             * processed event removed an element that fired and we still
             * didn't processed, so we check if the event is still valid.
             *
             * Fire the readable event if the call sequence is not
             * inverted. */
            /**
             * 如果调用序列没有反转，则触发可读事件
             */
            if (!invert && fe->mask & mask & AE_READABLE) {
                // 实际调用的 acceptTcpHandler 函数
                fe->rfileProc(eventLoop,fd,fe->clientData,mask);
                fired++;
                fe = &eventLoop->events[fd]; /* Refresh in case of resize. */
            }

            /* Fire the writable event. */
            // 触发写事件
            if (fe->mask & mask & AE_WRITABLE) {
                if (!fired || fe->wfileProc != fe->rfileProc) {
                    fe->wfileProc(eventLoop,fd,fe->clientData,mask);
                    fired++;
                }
            }

            /* If we have to invert the call, fire the readable event now
             * after the writable one. 
             * 
             * 如果必须反转调用，则在可写事件之后立即触发可读事件
             */
            if (invert) {
                fe = &eventLoop->events[fd]; /* Refresh in case of resize. */
                if ((fe->mask & mask & AE_READABLE) &&
                    (!fired || fe->wfileProc != fe->rfileProc))
                {
                    fe->rfileProc(eventLoop,fd,fe->clientData,mask);
                    fired++;
                }
            }

            processed++;
        }
    }
    /* Check time events 
     * 执行时间事件
     */
    if (flags & AE_TIME_EVENTS)
        processed += processTimeEvents(eventLoop);

    return processed; /* return the number of processed file/time events */
}

/* Wait for milliseconds until the given file descriptor becomes
 * writable/readable/exception */
 /**
  * 接收一个文件描述符，事件类型，毫秒数，在给定的时间内阻塞等待
  * 给定的事件产生，当事件成功产生或者等待超时之后，函数返回
  */
int aeWait(int fd, int mask, long long milliseconds) {
    /**
     * typedef struct pollfd {
     *     SOCKET  fd;       // 文件描述符
     *     SHORT   events;   // 等待的事件
     *     SHORT   revents;  // 实际发生了的事件
     * }
     */
    struct pollfd pfd;
    int retmask = 0, retval;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    if (mask & AE_READABLE) pfd.events |= POLLIN;
    if (mask & AE_WRITABLE) pfd.events |= POLLOUT;
    /**
     * int poll(struct pollfd fds[], nfds_t nfds, int timeout)
     * poll 函数将指定的文件描述符挂到设备内部定义的等待队列中
     * nfds:为 nfds_t 类型的参数，用于标记数组fds中的结构体元素的总数量
     * timeout:为 poll 函数调用阻塞的时间，单位毫秒
     */
    if ((retval = poll(&pfd, 1, milliseconds))== 1) {
        if (pfd.revents & POLLIN) retmask |= AE_READABLE;
        if (pfd.revents & POLLOUT) retmask |= AE_WRITABLE;
        if (pfd.revents & POLLERR) retmask |= AE_WRITABLE;
        if (pfd.revents & POLLHUP) retmask |= AE_WRITABLE;
        return retmask;
    } else {
        return retval;
    }
}

void aeMain(aeEventLoop *eventLoop) {
    eventLoop->stop = 0;
    while (!eventLoop->stop) {
        aeProcessEvents(eventLoop, AE_ALL_EVENTS|
                                   AE_CALL_BEFORE_SLEEP|
                                   AE_CALL_AFTER_SLEEP);
    }
}
/**
 * 返回 I/O 多路复用程序底层所使用的 I/O 多路复用函数库的名称
 * 返回 "epoll" 表示底层为 epoll 函数库
 * 返回 "select" 表示底层为 select 函数库
 */
char *aeGetApiName(void) {
    return aeApiName();
}

void aeSetBeforeSleepProc(aeEventLoop *eventLoop, aeBeforeSleepProc *beforesleep) {
    eventLoop->beforesleep = beforesleep;
}

void aeSetAfterSleepProc(aeEventLoop *eventLoop, aeBeforeSleepProc *aftersleep) {
    eventLoop->aftersleep = aftersleep;
}
