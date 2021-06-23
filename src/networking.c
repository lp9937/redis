/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
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

#include "server.h"
#include "atomicvar.h"
#include "cluster.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <math.h>
#include <ctype.h>

static void setProtocolError(const char *errstr, client *c);
int postponeClientRead(client *c);
int ProcessingEventsWhileBlocked = 0; /* See processEventsWhileBlocked(). */

/* Return the size consumed from the allocator, for the specified SDS string,
 * including internal fragmentation. This function is used in order to compute
 * the client output buffer size. */
size_t sdsZmallocSize(sds s) {
    void *sh = sdsAllocPtr(s);
    return zmalloc_size(sh);
}

/* Return the amount of memory used by the sds string at object->ptr
 * for a string object. This includes internal fragmentation. */
size_t getStringObjectSdsUsedMemory(robj *o) {
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
    switch(o->encoding) {
    case OBJ_ENCODING_RAW: return sdsZmallocSize(o->ptr);
    case OBJ_ENCODING_EMBSTR: return zmalloc_size(o)-sizeof(robj);
    default: return 0; /* Just integer encoding for now. */
    }
}

/* Return the length of a string object.
 * This does NOT includes internal fragmentation or sds unused space. */
size_t getStringObjectLen(robj *o) {
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
    switch(o->encoding) {
    case OBJ_ENCODING_RAW: return sdslen(o->ptr);
    case OBJ_ENCODING_EMBSTR: return sdslen(o->ptr);
    default: return 0; /* Just integer encoding for now. */
    }
}

/* Client.reply list dup and free methods. */
void *dupClientReplyValue(void *o) {
    clientReplyBlock *old = o;
    clientReplyBlock *buf = zmalloc(sizeof(clientReplyBlock) + old->size);
    memcpy(buf, o, sizeof(clientReplyBlock) + old->size);
    return buf;
}

void freeClientReplyValue(void *o) {
    zfree(o);
}

int listMatchObjects(void *a, void *b) {
    return equalStringObjects(a,b);
}

/* This function links the client to the global linked list of clients.
 * unlinkClient() does the opposite, among other things.
 * 
 * 将新客户端添加到服务器客户端列表的表尾
 */
void linkClient(client *c) {
    listAddNodeTail(server.clients,c);
    /* Note that we remember the linked list node where the client is stored,
     * this way removing the client in unlinkClient() will not require
     * a linear scan, but just a constant time operation. */
    c->client_list_node = listLast(server.clients);
    uint64_t id = htonu64(c->id);
    raxInsert(server.clients_index,(unsigned char*)&id,sizeof(id),c,NULL);
}

/* Initialize client authentication state.
 * 初始化客户端身份认证状态
 */
static void clientSetDefaultAuth(client *c) {
    /* If the default user does not require authentication, the user is
     * directly authenticated. 
     * 如果是默认用户，则不需要身份认证，
     * 直接设置该用户为被认证状态
     */
    c->user = DefaultUser;
    c->authenticated = (c->user->flags & USER_FLAG_NOPASS) &&
                       !(c->user->flags & USER_FLAG_DISABLED);
}
/**
 * 创建一个新的 client
 */
client *createClient(connection *conn) {
    client *c = zmalloc(sizeof(client));

    /* passing NULL as conn it is possible to create a non connected client.
     * 
     * 如果 conn 为 NULL，创建一个非连接的伪 client
     *
     * This is useful since all the commands needs to be executed
     * in the context of a client. When commands are executed in other
     * contexts (for instance a Lua script) we need a non connected client. 
     * 
     * 因为所有命令都是在 client 上下文中被执行的，
     * 所以在执行 Lua 上下中的命令时，需要用到这种伪 client
     * */
    if (conn) {
        // 非阻塞
        connNonBlock(conn);
        // 禁用 Nagle 算法，不延迟发送
        connEnableTcpNoDelay(conn);
        // 设置心跳
        if (server.tcpkeepalive)
            connKeepAlive(conn,server.tcpkeepalive);
        // 绑定读事件处理器
        connSetReadHandler(conn, readQueryFromClient);
        // 将 connection 的私有数据指针指向 client
        connSetPrivateData(conn, c);
    }

    // 默认数据库
    selectDb(c,0);
    uint64_t client_id;
    // 原子自增的方式分配客户端 id
    atomicGetIncr(server.next_client_id, client_id, 1);
    c->id = client_id;
    // RESP协议版本，默认 2
    c->resp = 2;
    // 连接
    c->conn = conn;
    // 名字
    c->name = NULL;
    // 回复缓冲区的偏移量
    c->bufpos = 0;
    // 查询缓存区的读取位置
    c->qb_pos = 0;
    // 查询缓冲区
    c->querybuf = sdsempty();
    // 从主服务器接收的尚未应用的复制流缓冲区
    c->pending_querybuf = sdsempty();
    // 查询缓冲区峰值
    c->querybuf_peak = 0;
    // 命令请求类型
    c->reqtype = 0;
    // 命令参数个数
    c->argc = 0;
    // 命令参数
    c->argv = NULL;
    // 命令参数总长度
    c->argv_len_sum = 0;
    // 如果参数被重写，原命令参数个数
    c->original_argc = 0;
    // 如果参数被重写，原命令参数
    c->original_argv = NULL;
    // 当前执行的命令和上一次执行的命令
    c->cmd = c->lastcmd = NULL;
    // 
    c->multibulklen = 0;
    c->bulklen = -1;
    // 已发送字节数
    c->sentlen = 0;
    // 客户端状态标志
    c->flags = 0;
    // 客户端创建时间和上一次互动时间
    c->ctime = c->lastinteraction = server.unixtime;
    clientSetDefaultAuth(c);
    // 复制状态
    c->replstate = REPL_STATE_NONE;
    // 
    c->repl_put_online_on_ack = 0;
    // 复制偏移量
    c->reploff = 0;
    // 主服务器读复制偏移量
    c->read_reploff = 0;
    // 从服务器最后一次发送 REPLCONF ACK 时的偏移量
    c->repl_ack_off = 0;
    // 从服务器最后一次发送 REPLCONF ACK 的时间
    c->repl_ack_time = 0;
    // 从服务器的监听端口
    c->slave_listening_port = 0;
    // 从服务器地址
    c->slave_addr = NULL;
    // 从服务器容量
    c->slave_capa = SLAVE_CAPA_NONE;
    // 回复链表
    c->reply = listCreate();
    // 回复列表中所有对象的中字节数
    c->reply_bytes = 0;
    // 客户端的输出缓冲区超过软性限制的时间
    c->obuf_soft_limit_reached_time = 0;
    // 回复链表的释放和复制函数
    listSetFreeMethod(c->reply,freeClientReplyValue);
    listSetDupMethod(c->reply,dupClientReplyValue);
    // 阻塞类型
    c->btype = BLOCKED_NONE;
    // 阻塞超时
    c->bpop.timeout = 0;
    // 造车客户端阻塞的列表键
    c->bpop.keys = dictCreate(&objectKeyHeapPointerValueDictType,NULL);
    // 
    c->bpop.target = NULL;
    c->bpop.xread_group = NULL;
    c->bpop.xread_consumer = NULL;
    c->bpop.xread_group_noack = 0;
    c->bpop.numreplicas = 0;
    c->bpop.reploffset = 0;
    c->woff = 0;
    // 进行事务时被监视的键
    c->watched_keys = listCreate();
    // 客户端订阅的频道
    c->pubsub_channels = dictCreate(&objectKeyPointerValueDictType,NULL);
    // 匹配频道的模式
    c->pubsub_patterns = listCreate();
    c->peerid = NULL;
    c->sockname = NULL;
    c->client_list_node = NULL;
    c->paused_list_node = NULL;
    c->client_tracking_redirection = 0;
    c->client_tracking_prefixes = NULL;
    c->client_cron_last_memory_usage = 0;
    c->client_cron_last_memory_type = CLIENT_TYPE_NORMAL;
    c->auth_callback = NULL;
    c->auth_callback_privdata = NULL;
    c->auth_module = NULL;
    listSetFreeMethod(c->pubsub_patterns,decrRefCountVoid);
    listSetMatchMethod(c->pubsub_patterns,listMatchObjects);
    // 如果不是伪客户端，将其添加进服务器的客户端列表中
    if (conn) linkClient(c);
    // 初始化客户端的事务状态
    initClientMultiState(c);
    return c;
}

/* This function puts the client in the queue of clients that should write
 * their output buffers to the socket. Note that it does not *yet* install
 * the write handler, to start clients are put in a queue of clients that need
 * to write, so we try to do that before returning in the event loop (see the
 * handleClientsWithPendingWrites() function).
 * If we fail and there is more data to write, compared to what the socket
 * buffers can hold, then we'll really install the handler. */
void clientInstallWriteHandler(client *c) {
    /* Schedule the client to write the output buffers to the socket only
     * if not already done and, for slaves, if the slave can actually receive
     * writes at this stage. */
    if (!(c->flags & CLIENT_PENDING_WRITE) &&
        (c->replstate == REPL_STATE_NONE ||
         (c->replstate == SLAVE_STATE_ONLINE && !c->repl_put_online_on_ack)))
    {
        /* Here instead of installing the write handler, we just flag the
         * client and put it into a list of clients that have something
         * to write to the socket. This way before re-entering the event
         * loop, we can try to directly write to the client sockets avoiding
         * a system call. We'll only really install the write handler if
         * we'll not be able to write the whole reply at once. */
        c->flags |= CLIENT_PENDING_WRITE;
        listAddNodeHead(server.clients_pending_write,c);
    }
}

/* This function is called every time we are going to transmit new data
 * to the client. The behavior is the following:
 * 
 * 每次向客户端发送数据时都会被调用此函数，该函数的行为如下：
 *
 * If the client should receive new data (normal clients will) the function
 * returns C_OK, and make sure to install the write handler in our event
 * loop so that when the socket is writable new data gets written.
 *
 * 如果客户端可以接收新数据(大多数情况都是这样的)，函数返回 C_OK
 * 并且安装写处理器到事件循环中
 * 这样当套接字可写时，新数据会被写入
 * 
 * If the client should not receive new data, because it is a fake client
 * (used to load AOF in memory), a master or because the setup of the write
 * handler failed, the function returns C_ERR.
 * 
 * 对于不应该接收新数据的客户端，
 * 比如伪客户端(被使用来加载AOF到内存)、master
 * 或者写处理器安装失败时
 * 函数返回C_ERR
 *
 * The function may return C_OK without actually installing the write
 * event handler in the following cases:
 * 
 * 在以下没有实际安装写事件处理器的情况下，该函数返回C_OK
 *
 * 1) The event handler should already be installed since the output buffer
 *    already contains something.
 * 2) The client is a slave but not yet online, so we want to just accumulate
 *    writes in the buffer but not actually sending them yet.
 * 
 * 1)在输出缓冲区包含有东西的情况下，写事件处理器已经被安装了
 * 2)客户端是slave且没有在线，我们只是累计写入数据到缓冲区，但实际不发送它
 *
 * Typically gets called every time a reply is built, before adding more
 * data to the clients output buffers. If the function returns C_ERR no
 * data should be appended to the output buffers.
 * 
 * 在向客户端输出缓冲区添加更多数据以前，该函数通常在每个回复被创建时调用。
 * 如果函数返回C_ERR，那么没有数据被追加到输出缓冲区
 * */
int prepareClientToWrite(client *c) {
    /* If it's the Lua client we always return ok without installing any
     * handler since there is no socket at all. */
    //如果是Lua脚本环境使用的客户端，将总是返回C_OK，
    //并且不用安装任何处理器，因为根本没有套接字
    if (c->flags & (CLIENT_LUA|CLIENT_MODULE)) return C_OK;

    /* If CLIENT_CLOSE_ASAP flag is set, we need not write anything. */
    //如果客户端即将关闭，则不需要写任何内容
    if (c->flags & CLIENT_CLOSE_ASAP) return C_ERR;

    /* CLIENT REPLY OFF / SKIP handling: don't send replies. */
    // 如果客户端被设置成不回复或跳过该命令的回复，则不发送回复信息
    if (c->flags & (CLIENT_REPLY_OFF|CLIENT_REPLY_SKIP)) return C_ERR;

    /* Masters don't receive replies, unless CLIENT_MASTER_FORCE_REPLY flag
     * is set. */
    // 客户端是主服务器且CLIENT_MASTER_FORCE_REPLY标志没有被设置的情况下，它是不可写的
    if ((c->flags & CLIENT_MASTER) &&
        !(c->flags & CLIENT_MASTER_FORCE_REPLY)) return C_ERR;

    if (!c->conn) return C_ERR; /* Fake client for AOF loading. */

    /* Schedule the client to write the output buffers to the socket, unless
     * it should already be setup to do so (it has already pending data).
     *
     * If CLIENT_PENDING_READ is set, we're in an IO thread and should
     * not install a write handler. Instead, it will be done by
     * handleClientsWithPendingReadsUsingThreads() upon return.
     */
    //除非已经安排了客户端将输出缓冲区写到套接字，否则安排客户端将输出缓冲区写到套接字
    //如果 CLIENT_PENDING_READ 标志被设置，在IO线程内，不应该安装写处理器
    //相反它将由 handleClientsWithPendingReadsUsingThreads 完成
    if (!clientHasPendingReplies(c) && !(c->flags & CLIENT_PENDING_READ))
            clientInstallWriteHandler(c);

    /* Authorize the caller to queue in the output buffer of this client. */
    return C_OK;
}

/* -----------------------------------------------------------------------------
 * Low level functions to add more data to output buffers.
 * -------------------------------------------------------------------------- */

/* Attempts to add the reply to the static buffer in the client struct.
 * Returns C_ERR if the buffer is full, or the reply list is not empty,
 * in which case the reply must be added to the reply list. 
 * 
 * 尝试将应答添加到客户端结构中的静态缓冲区。
 * 如果缓冲区满了或者回复列表不为空，则返回 C_ERR，
 * 在这种情况下，必须将回复添加到回复列表中
 * */
int _addReplyToBuffer(client *c, const char *s, size_t len) {
    // 静态回复缓冲区中可用字节数
    size_t available = sizeof(c->buf)-c->bufpos;

    if (c->flags & CLIENT_CLOSE_AFTER_REPLY) return C_OK;

    /* If there already are entries in the reply list, we cannot
     * add anything more to the static buffer. 
     *
     * 如果回复列表中已经有条目，我们就不能再向静态缓冲区添加任何内容
     */
    if (listLength(c->reply) > 0) return C_ERR;

    /* Check that the buffer has enough space available for this string. 
     * 静态回复缓冲区可用字节数不足以容纳新数据
     */
    if (len > available) return C_ERR;

    // 将数据复制到静态回复缓冲区中
    memcpy(c->buf+c->bufpos,s,len);
    c->bufpos+=len;
    return C_OK;
}

/* Adds the reply to the reply linked list.
 * 将回复信息添加到回复列表中
 * Note: some edits to this function need to be relayed to AddReplyFromClient.
 */
void _addReplyProtoToList(client *c, const char *s, size_t len) {
    if (c->flags & CLIENT_CLOSE_AFTER_REPLY) return;

    // 获取回复列表的未节点
    listNode *ln = listLast(c->reply);
    // 获取未节点保存的值
    clientReplyBlock *tail = ln? listNodeValue(ln): NULL;

    /* Note that 'tail' may be NULL even if we have a tail node, because when
     * addReplyDeferredLen() is used, it sets a dummy node to NULL just
     * fo fill it later, when the size of the bulk length is set. 
     * 
     * 注意：即使有未节点，tail 也可能为 NULL。
     * 因为当使用 addReplyDeferredLen() 的时候，
     * 它先将节点值设置为 NULL，以便稍后设置 bulk 
     * 长度的时候设置节点的值
     * */

    /* Append to tail string when possible. */
    if (tail) {
        /* Copy the part we can fit into the tail, and leave the rest for a
         * new node 
         * 如果 tail 中剩余空间不足以容纳现在的数据，则将部分数据放在 tail 中，
         * 剩余部分数据放在新节点中
         */
        size_t avail = tail->size - tail->used;
        size_t copy = avail >= len? len: avail;
        memcpy(tail->buf + tail->used, s, copy);
        tail->used += copy;
        s += copy;
        len -= copy;
    }

    // 如果还有剩余数据要放
    if (len) {
        /* Create a new node, make sure it is allocated to at
         * least PROTO_REPLY_CHUNK_BYTES
         * 
         * 创建一个新节点，该节点被分配至少 PROTO_REPLY_CHUNK_BYTES 字节的大小
         */
        size_t size = len < PROTO_REPLY_CHUNK_BYTES? PROTO_REPLY_CHUNK_BYTES: len;
        tail = zmalloc(size + sizeof(clientReplyBlock));
        /* take over the allocation's internal fragmentation */
        tail->size = zmalloc_usable_size(tail) - sizeof(clientReplyBlock);
        tail->used = len;
        memcpy(tail->buf, s, len);
        listAddNodeTail(c->reply, tail);
        c->reply_bytes += tail->size;
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

/* -----------------------------------------------------------------------------
 * Higher level functions to queue data on the client output buffer.
 * The following functions are the ones that commands implementations will call.
 * -------------------------------------------------------------------------- */

/* Add the object 'obj' string representation to the client output buffer. */
// 添加'obj'到客户端输出缓冲区
void addReply(client *c, robj *obj) {
    // 为客户端安装写处理器到事件循环
    if (prepareClientToWrite(c) != C_OK) return;

    if (sdsEncodedObject(obj)) {
        // 如果将回复信息添加到静态缓冲区失败，则将回复信息添加到回复列表中
        if (_addReplyToBuffer(c,obj->ptr,sdslen(obj->ptr)) != C_OK)
            _addReplyProtoToList(c,obj->ptr,sdslen(obj->ptr));
    } else if (obj->encoding == OBJ_ENCODING_INT) {
        /* For integer encoded strings we just convert it into a string
         * using our optimized function, and attach the resulting string
         * to the output buffer. 
         * 
         * 对于整数编码的字符串，使用优化函数将其转化为字符串，并将其添加到
         * 输出缓冲区中
         * */
        char buf[32];
        size_t len = ll2string(buf,sizeof(buf),(long)obj->ptr);
        if (_addReplyToBuffer(c,buf,len) != C_OK)
            _addReplyProtoToList(c,buf,len);
    } else {
        serverPanic("Wrong obj->encoding in addReply()");
    }
}

/* Add the SDS 's' string to the client output buffer, as a side effect
 * the SDS string is freed. */
void addReplySds(client *c, sds s) {
    if (prepareClientToWrite(c) != C_OK) {
        /* The caller expects the sds to be free'd. */
        sdsfree(s);
        return;
    }
    if (_addReplyToBuffer(c,s,sdslen(s)) != C_OK)
        _addReplyProtoToList(c,s,sdslen(s));
    sdsfree(s);
}

/* This low level function just adds whatever protocol you send it to the
 * client buffer, trying the static buffer initially, and using the string
 * of objects if not possible.
 *
 * It is efficient because does not create an SDS object nor an Redis object
 * if not needed. The object will only be created by calling
 * _addReplyProtoToList() if we fail to extend the existing tail object
 * in the list of objects. */
void addReplyProto(client *c, const char *s, size_t len) {
    if (prepareClientToWrite(c) != C_OK) return;
    if (_addReplyToBuffer(c,s,len) != C_OK)
        _addReplyProtoToList(c,s,len);
}

/* Low level function called by the addReplyError...() functions.
 * It emits the protocol for a Redis error, in the form:
 *
 * -ERRORCODE Error Message<CR><LF>
 *
 * If the error code is already passed in the string 's', the error
 * code provided is used, otherwise the string "-ERR " for the generic
 * error code is automatically added.
 * Note that 's' must NOT end with \r\n. */
void addReplyErrorLength(client *c, const char *s, size_t len) {
    /* If the string already starts with "-..." then the error code
     * is provided by the caller. Otherwise we use "-ERR". */
    if (!len || s[0] != '-') addReplyProto(c,"-ERR ",5);
    addReplyProto(c,s,len);
    addReplyProto(c,"\r\n",2);
}

/* Do some actions after an error reply was sent (Log if needed, updates stats, etc.) */
void afterErrorReply(client *c, const char *s, size_t len) {
    /* Increment the global error counter */
    server.stat_total_error_replies++;
    /* Increment the error stats
     * If the string already starts with "-..." then the error prefix
     * is provided by the caller ( we limit the search to 32 chars). Otherwise we use "-ERR". */
    if (s[0] != '-') {
        incrementErrorCount("ERR", 3);
    } else {
        char *spaceloc = memchr(s, ' ', len < 32 ? len : 32);
        if (spaceloc) {
            const size_t errEndPos = (size_t)(spaceloc - s);
            incrementErrorCount(s+1, errEndPos-1);
        } else {
            /* Fallback to ERR if we can't retrieve the error prefix */
            incrementErrorCount("ERR", 3);
        }
    }

    /* Sometimes it could be normal that a slave replies to a master with
     * an error and this function gets called. Actually the error will never
     * be sent because addReply*() against master clients has no effect...
     * A notable example is:
     *
     *    EVAL 'redis.call("incr",KEYS[1]); redis.call("nonexisting")' 1 x
     *
     * Where the master must propagate the first change even if the second
     * will produce an error. However it is useful to log such events since
     * they are rare and may hint at errors in a script or a bug in Redis. */
    int ctype = getClientType(c);
    if (ctype == CLIENT_TYPE_MASTER || ctype == CLIENT_TYPE_SLAVE || c->id == CLIENT_ID_AOF) {
        char *to, *from;

        if (c->id == CLIENT_ID_AOF) {
            to = "AOF-loading-client";
            from = "server";
        } else if (ctype == CLIENT_TYPE_MASTER) {
            to = "master";
            from = "replica";
        } else {
            to = "replica";
            from = "master";
        }

        if (len > 4096) len = 4096;
        char *cmdname = c->lastcmd ? c->lastcmd->name : "<unknown>";
        serverLog(LL_WARNING,"== CRITICAL == This %s is sending an error "
                             "to its %s: '%.*s' after processing the command "
                             "'%s'", from, to, (int)len, s, cmdname);
        if (ctype == CLIENT_TYPE_MASTER && server.repl_backlog &&
            server.repl_backlog_histlen > 0)
        {
            showLatestBacklog();
        }
        server.stat_unexpected_error_replies++;
    }
}

/* The 'err' object is expected to start with -ERRORCODE and end with \r\n.
 * Unlike addReplyErrorSds and others alike which rely on addReplyErrorLength. */
void addReplyErrorObject(client *c, robj *err) {
    addReply(c, err);
    afterErrorReply(c, err->ptr, sdslen(err->ptr)-2); /* Ignore trailing \r\n */
}

/* See addReplyErrorLength for expectations from the input string. */
void addReplyError(client *c, const char *err) {
    addReplyErrorLength(c,err,strlen(err));
    afterErrorReply(c,err,strlen(err));
}

/* See addReplyErrorLength for expectations from the input string. */
/* As a side effect the SDS string is freed. */
void addReplyErrorSds(client *c, sds err) {
    addReplyErrorLength(c,err,sdslen(err));
    afterErrorReply(c,err,sdslen(err));
    sdsfree(err);
}

/* See addReplyErrorLength for expectations from the formatted string.
 * The formatted string is safe to contain \r and \n anywhere. */
void addReplyErrorFormat(client *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap,fmt);
    sds s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    /* Trim any newlines at the end (ones will be added by addReplyErrorLength) */
    s = sdstrim(s, "\r\n");
    /* Make sure there are no newlines in the middle of the string, otherwise
     * invalid protocol is emitted. */
    s = sdsmapchars(s, "\r\n", "  ",  2);
    addReplyErrorLength(c,s,sdslen(s));
    afterErrorReply(c,s,sdslen(s));
    sdsfree(s);
}

void addReplyStatusLength(client *c, const char *s, size_t len) {
    addReplyProto(c,"+",1);
    addReplyProto(c,s,len);
    addReplyProto(c,"\r\n",2);
}

void addReplyStatus(client *c, const char *status) {
    addReplyStatusLength(c,status,strlen(status));
}

void addReplyStatusFormat(client *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap,fmt);
    sds s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    addReplyStatusLength(c,s,sdslen(s));
    sdsfree(s);
}

/* Sometimes we are forced to create a new reply node, and we can't append to
 * the previous one, when that happens, we wanna try to trim the unused space
 * at the end of the last reply node which we won't use anymore. */
void trimReplyUnusedTailSpace(client *c) {
    listNode *ln = listLast(c->reply);
    clientReplyBlock *tail = ln? listNodeValue(ln): NULL;

    /* Note that 'tail' may be NULL even if we have a tail node, because when
     * addReplyDeferredLen() is used */
    if (!tail) return;

    /* We only try to trim the space is relatively high (more than a 1/4 of the
     * allocation), otherwise there's a high chance realloc will NOP.
     * Also, to avoid large memmove which happens as part of realloc, we only do
     * that if the used part is small.  */
    if (tail->size - tail->used > tail->size / 4 &&
        tail->used < PROTO_REPLY_CHUNK_BYTES)
    {
        size_t old_size = tail->size;
        tail = zrealloc(tail, tail->used + sizeof(clientReplyBlock));
        /* take over the allocation's internal fragmentation (at least for
         * memory usage tracking) */
        tail->size = zmalloc_usable_size(tail) - sizeof(clientReplyBlock);
        c->reply_bytes = c->reply_bytes + tail->size - old_size;
        listNodeValue(ln) = tail;
    }
}

/* Adds an empty object to the reply list that will contain the multi bulk
 * length, which is not known when this function is called. */
void *addReplyDeferredLen(client *c) {
    /* Note that we install the write event here even if the object is not
     * ready to be sent, since we are sure that before returning to the
     * event loop setDeferredAggregateLen() will be called. */
    if (prepareClientToWrite(c) != C_OK) return NULL;
    trimReplyUnusedTailSpace(c);
    listAddNodeTail(c->reply,NULL); /* NULL is our placeholder. */
    return listLast(c->reply);
}

void setDeferredReply(client *c, void *node, const char *s, size_t length) {
    listNode *ln = (listNode*)node;
    clientReplyBlock *next;

    /* Abort when *node is NULL: when the client should not accept writes
     * we return NULL in addReplyDeferredLen() */
    if (node == NULL) return;
    serverAssert(!listNodeValue(ln));

    /* Normally we fill this dummy NULL node, added by addReplyDeferredLen(),
     * with a new buffer structure containing the protocol needed to specify
     * the length of the array following. However sometimes when there is
     * little memory to move, we may instead remove this NULL node, and prefix
     * our protocol in the node immediately after to it, in order to save a
     * write(2) syscall later. Conditions needed to do it:
     *
     * - The next node is non-NULL,
     * - It has enough room already allocated
     * - And not too large (avoid large memmove) */
    if (ln->next != NULL && (next = listNodeValue(ln->next)) &&
        next->size - next->used >= length &&
        next->used < PROTO_REPLY_CHUNK_BYTES * 4)
    {
        memmove(next->buf + length, next->buf, next->used);
        memcpy(next->buf, s, length);
        next->used += length;
        listDelNode(c->reply,ln);
    } else {
        /* Create a new node */
        clientReplyBlock *buf = zmalloc(length + sizeof(clientReplyBlock));
        /* Take over the allocation's internal fragmentation */
        buf->size = zmalloc_usable_size(buf) - sizeof(clientReplyBlock);
        buf->used = length;
        memcpy(buf->buf, s, length);
        listNodeValue(ln) = buf;
        c->reply_bytes += buf->size;
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

/* Populate the length object and try gluing it to the next chunk. */
void setDeferredAggregateLen(client *c, void *node, long length, char prefix) {
    serverAssert(length >= 0);

    /* Abort when *node is NULL: when the client should not accept writes
     * we return NULL in addReplyDeferredLen() */
    if (node == NULL) return;

    char lenstr[128];
    size_t lenstr_len = sprintf(lenstr, "%c%ld\r\n", prefix, length);
    setDeferredReply(c, node, lenstr, lenstr_len);
}

void setDeferredArrayLen(client *c, void *node, long length) {
    setDeferredAggregateLen(c,node,length,'*');
}

void setDeferredMapLen(client *c, void *node, long length) {
    int prefix = c->resp == 2 ? '*' : '%';
    if (c->resp == 2) length *= 2;
    setDeferredAggregateLen(c,node,length,prefix);
}

void setDeferredSetLen(client *c, void *node, long length) {
    int prefix = c->resp == 2 ? '*' : '~';
    setDeferredAggregateLen(c,node,length,prefix);
}

void setDeferredAttributeLen(client *c, void *node, long length) {
    int prefix = c->resp == 2 ? '*' : '|';
    if (c->resp == 2) length *= 2;
    setDeferredAggregateLen(c,node,length,prefix);
}

void setDeferredPushLen(client *c, void *node, long length) {
    int prefix = c->resp == 2 ? '*' : '>';
    setDeferredAggregateLen(c,node,length,prefix);
}

/* Add a double as a bulk reply */
void addReplyDouble(client *c, double d) {
    if (isinf(d)) {
        /* Libc in odd systems (Hi Solaris!) will format infinite in a
         * different way, so better to handle it in an explicit way. */
        if (c->resp == 2) {
            addReplyBulkCString(c, d > 0 ? "inf" : "-inf");
        } else {
            addReplyProto(c, d > 0 ? ",inf\r\n" : ",-inf\r\n",
                              d > 0 ? 6 : 7);
        }
    } else {
        char dbuf[MAX_LONG_DOUBLE_CHARS+3],
             sbuf[MAX_LONG_DOUBLE_CHARS+32];
        int dlen, slen;
        if (c->resp == 2) {
            dlen = snprintf(dbuf,sizeof(dbuf),"%.17g",d);
            slen = snprintf(sbuf,sizeof(sbuf),"$%d\r\n%s\r\n",dlen,dbuf);
            addReplyProto(c,sbuf,slen);
        } else {
            dlen = snprintf(dbuf,sizeof(dbuf),",%.17g\r\n",d);
            addReplyProto(c,dbuf,dlen);
        }
    }
}

/* Add a long double as a bulk reply, but uses a human readable formatting
 * of the double instead of exposing the crude behavior of doubles to the
 * dear user. */
void addReplyHumanLongDouble(client *c, long double d) {
    if (c->resp == 2) {
        robj *o = createStringObjectFromLongDouble(d,1);
        addReplyBulk(c,o);
        decrRefCount(o);
    } else {
        char buf[MAX_LONG_DOUBLE_CHARS];
        int len = ld2string(buf,sizeof(buf),d,LD_STR_HUMAN);
        addReplyProto(c,",",1);
        addReplyProto(c,buf,len);
        addReplyProto(c,"\r\n",2);
    }
}

/* Add a long long as integer reply or bulk len / multi bulk count.
 * Basically this is used to output <prefix><long long><crlf>. */
void addReplyLongLongWithPrefix(client *c, long long ll, char prefix) {
    char buf[128];
    int len;

    /* Things like $3\r\n or *2\r\n are emitted very often by the protocol
     * so we have a few shared objects to use if the integer is small
     * like it is most of the times. */
    if (prefix == '*' && ll < OBJ_SHARED_BULKHDR_LEN && ll >= 0) {
        //多条批量回复
        addReply(c,shared.mbulkhdr[ll]);
        return;
    } else if (prefix == '$' && ll < OBJ_SHARED_BULKHDR_LEN && ll >= 0) {
        //批量回复
        addReply(c,shared.bulkhdr[ll]);
        return;
    }

    buf[0] = prefix;
    len = ll2string(buf+1,sizeof(buf)-1,ll);
    buf[len+1] = '\r';
    buf[len+2] = '\n';
    addReplyProto(c,buf,len+3);
}
/*
*返回一个整数
*
*/
void addReplyLongLong(client *c, long long ll) {
    if (ll == 0)
        addReply(c,shared.czero);
    else if (ll == 1)
        addReply(c,shared.cone);
    else
        addReplyLongLongWithPrefix(c,ll,':');
}

void addReplyAggregateLen(client *c, long length, int prefix) {
    serverAssert(length >= 0);
    addReplyLongLongWithPrefix(c,length,prefix);
}

void addReplyArrayLen(client *c, long length) {
    addReplyAggregateLen(c,length,'*');
}

void addReplyMapLen(client *c, long length) {
    int prefix = c->resp == 2 ? '*' : '%';
    if (c->resp == 2) length *= 2;
    addReplyAggregateLen(c,length,prefix);
}

void addReplySetLen(client *c, long length) {
    int prefix = c->resp == 2 ? '*' : '~';
    addReplyAggregateLen(c,length,prefix);
}

void addReplyAttributeLen(client *c, long length) {
    int prefix = c->resp == 2 ? '*' : '|';
    if (c->resp == 2) length *= 2;
    addReplyAggregateLen(c,length,prefix);
}

void addReplyPushLen(client *c, long length) {
    int prefix = c->resp == 2 ? '*' : '>';
    addReplyAggregateLen(c,length,prefix);
}

void addReplyNull(client *c) {
    if (c->resp == 2) {
        addReplyProto(c,"$-1\r\n",5);
    } else {
        addReplyProto(c,"_\r\n",3);
    }
}

void addReplyBool(client *c, int b) {
    if (c->resp == 2) {
        addReply(c, b ? shared.cone : shared.czero);
    } else {
        addReplyProto(c, b ? "#t\r\n" : "#f\r\n",4);
    }
}

/* A null array is a concept that no longer exists in RESP3. However
 * RESP2 had it, so API-wise we have this call, that will emit the correct
 * RESP2 protocol, however for RESP3 the reply will always be just the
 * Null type "_\r\n". */
void addReplyNullArray(client *c) {
    if (c->resp == 2) {
        addReplyProto(c,"*-1\r\n",5);
    } else {
        addReplyProto(c,"_\r\n",3);
    }
}

/* Create the length prefix of a bulk reply, example: $2234 */
void addReplyBulkLen(client *c, robj *obj) {
    size_t len = stringObjectLen(obj);

    addReplyLongLongWithPrefix(c,len,'$');
}

/* Add a Redis Object as a bulk reply */
/*
 * 添加一个 redis 对象到回复缓冲区中
 */
void addReplyBulk(client *c, robj *obj) {
    addReplyBulkLen(c,obj);
    addReply(c,obj);
    addReply(c,shared.crlf);
}

/* Add a C buffer as bulk reply */
void addReplyBulkCBuffer(client *c, const void *p, size_t len) {
    addReplyLongLongWithPrefix(c,len,'$');
    addReplyProto(c,p,len);
    addReply(c,shared.crlf);
}

/* Add sds to reply (takes ownership of sds and frees it) */
void addReplyBulkSds(client *c, sds s)  {
    addReplyLongLongWithPrefix(c,sdslen(s),'$');
    addReplySds(c,s);
    addReply(c,shared.crlf);
}

/* Set sds to a deferred reply (for symmetry with addReplyBulkSds it also frees the sds) */
void setDeferredReplyBulkSds(client *c, void *node, sds s) {
    sds reply = sdscatprintf(sdsempty(), "$%d\r\n%s\r\n", (unsigned)sdslen(s), s);
    setDeferredReply(c, node, reply, sdslen(reply));
    sdsfree(reply);
    sdsfree(s);
}

/* Add a C null term string as bulk reply */
void addReplyBulkCString(client *c, const char *s) {
    if (s == NULL) {
        addReplyNull(c);
    } else {
        addReplyBulkCBuffer(c,s,strlen(s));
    }
}

/* Add a long long as a bulk reply */
void addReplyBulkLongLong(client *c, long long ll) {
    char buf[64];
    int len;

    len = ll2string(buf,64,ll);
    addReplyBulkCBuffer(c,buf,len);
}

/* Reply with a verbatim type having the specified extension.
 *
 * The 'ext' is the "extension" of the file, actually just a three
 * character type that describes the format of the verbatim string.
 * For instance "txt" means it should be interpreted as a text only
 * file by the receiver, "md " as markdown, and so forth. Only the
 * three first characters of the extension are used, and if the
 * provided one is shorter than that, the remaining is filled with
 * spaces. */
void addReplyVerbatim(client *c, const char *s, size_t len, const char *ext) {
    if (c->resp == 2) {
        addReplyBulkCBuffer(c,s,len);
    } else {
        char buf[32];
        size_t preflen = snprintf(buf,sizeof(buf),"=%zu\r\nxxx:",len+4);
        char *p = buf+preflen-4;
        for (int i = 0; i < 3; i++) {
            if (*ext == '\0') {
                p[i] = ' ';
            } else {
                p[i] = *ext++;
            }
        }
        addReplyProto(c,buf,preflen);
        addReplyProto(c,s,len);
        addReplyProto(c,"\r\n",2);
    }
}

/* Add an array of C strings as status replies with a heading.
 * This function is typically invoked by from commands that support
 * subcommands in response to the 'help' subcommand. The help array
 * is terminated by NULL sentinel. */
void addReplyHelp(client *c, const char **help) {
    sds cmd = sdsnew((char*) c->argv[0]->ptr);
    void *blenp = addReplyDeferredLen(c);
    int blen = 0;

    sdstoupper(cmd);
    addReplyStatusFormat(c,
        "%s <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",cmd);
    sdsfree(cmd);

    while (help[blen]) addReplyStatus(c,help[blen++]);

    addReplyStatus(c,"HELP");
    addReplyStatus(c,"    Prints this help.");

    blen += 1;  /* Account for the header. */
    blen += 2;  /* Account for the footer. */
    setDeferredArrayLen(c,blenp,blen);
}

/* Add a suggestive error reply.
 * This function is typically invoked by from commands that support
 * subcommands in response to an unknown subcommand or argument error. */
void addReplySubcommandSyntaxError(client *c) {
    sds cmd = sdsnew((char*) c->argv[0]->ptr);
    sdstoupper(cmd);
    addReplyErrorFormat(c,
        "Unknown subcommand or wrong number of arguments for '%s'. Try %s HELP.",
        (char*)c->argv[1]->ptr,cmd);
    sdsfree(cmd);
}

/* Append 'src' client output buffers into 'dst' client output buffers.
 * This function clears the output buffers of 'src' */
void AddReplyFromClient(client *dst, client *src) {
    /* If the source client contains a partial response due to client output
     * buffer limits, propagate that to the dest rather than copy a partial
     * reply. We don't wanna run the risk of copying partial response in case
     * for some reason the output limits don't reach the same decision (maybe
     * they changed) */
    if (src->flags & CLIENT_CLOSE_ASAP) {
        sds client = catClientInfoString(sdsempty(),dst);
        freeClientAsync(dst);
        serverLog(LL_WARNING,"Client %s scheduled to be closed ASAP for overcoming of output buffer limits.", client);
        sdsfree(client);
        return;
    }

    /* First add the static buffer (either into the static buffer or reply list) */
    addReplyProto(dst,src->buf, src->bufpos);

    /* We need to check with prepareClientToWrite again (after addReplyProto)
     * since addReplyProto may have changed something (like CLIENT_CLOSE_ASAP) */
    if (prepareClientToWrite(dst) != C_OK)
        return;

    /* We're bypassing _addReplyProtoToList, so we need to add the pre/post
     * checks in it. */
    if (dst->flags & CLIENT_CLOSE_AFTER_REPLY) return;

    /* Concatenate the reply list into the dest */
    if (listLength(src->reply))
        listJoin(dst->reply,src->reply);
    dst->reply_bytes += src->reply_bytes;
    src->reply_bytes = 0;
    src->bufpos = 0;

    /* Check output buffer limits */
    asyncCloseClientOnOutputBufferLimitReached(dst);
}

/* Copy 'src' client output buffers into 'dst' client output buffers.
 * The function takes care of freeing the old output buffers of the
 * destination client. */
void copyClientOutputBuffer(client *dst, client *src) {
    listRelease(dst->reply);
    dst->sentlen = 0;
    dst->reply = listDup(src->reply);
    memcpy(dst->buf,src->buf,src->bufpos);
    dst->bufpos = src->bufpos;
    dst->reply_bytes = src->reply_bytes;
}

/* Return true if the specified client has pending reply buffers to write to
 * the socket. */
int clientHasPendingReplies(client *c) {
    return c->bufpos || listLength(c->reply);
}

void clientAcceptHandler(connection *conn) {
    client *c = connGetPrivateData(conn);

    if (connGetState(conn) != CONN_STATE_CONNECTED) {
        serverLog(LL_WARNING,
                "Error accepting a client connection: %s",
                connGetLastError(conn));
        freeClientAsync(c);
        return;
    }

    /* If the server is running in protected mode (the default) and there
     * is no password set, nor a specific interface is bound, we don't accept
     * requests from non loopback interfaces. Instead we try to explain the
     * user what to do to fix it if needed. */
    if (server.protected_mode &&
        server.bindaddr_count == 0 &&
        DefaultUser->flags & USER_FLAG_NOPASS &&
        !(c->flags & CLIENT_UNIX_SOCKET))
    {
        char cip[NET_IP_STR_LEN+1] = { 0 };
        connPeerToString(conn, cip, sizeof(cip)-1, NULL);

        if (strcmp(cip,"127.0.0.1") && strcmp(cip,"::1")) {
            char *err =
                "-DENIED Redis is running in protected mode because protected "
                "mode is enabled, no bind address was specified, no "
                "authentication password is requested to clients. In this mode "
                "connections are only accepted from the loopback interface. "
                "If you want to connect from external computers to Redis you "
                "may adopt one of the following solutions: "
                "1) Just disable protected mode sending the command "
                "'CONFIG SET protected-mode no' from the loopback interface "
                "by connecting to Redis from the same host the server is "
                "running, however MAKE SURE Redis is not publicly accessible "
                "from internet if you do so. Use CONFIG REWRITE to make this "
                "change permanent. "
                "2) Alternatively you can just disable the protected mode by "
                "editing the Redis configuration file, and setting the protected "
                "mode option to 'no', and then restarting the server. "
                "3) If you started the server manually just for testing, restart "
                "it with the '--protected-mode no' option. "
                "4) Setup a bind address or an authentication password. "
                "NOTE: You only need to do one of the above things in order for "
                "the server to start accepting connections from the outside.\r\n";
            if (connWrite(c->conn,err,strlen(err)) == -1) {
                /* Nothing to do, Just to avoid the warning... */
            }
            server.stat_rejected_conn++;
            freeClientAsync(c);
            return;
        }
    }

    server.stat_numconnections++;
    moduleFireServerEvent(REDISMODULE_EVENT_CLIENT_CHANGE,
                          REDISMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED,
                          c);
}

#define MAX_ACCEPTS_PER_CALL 1000
/**
 * TCP 连接 accept 处理器
 */
static void acceptCommonHandler(connection *conn, int flags, char *ip) {
    client *c;
    char conninfo[100];
    UNUSED(ip);

    if (connGetState(conn) != CONN_STATE_ACCEPTING) {
        serverLog(LL_VERBOSE,
            "Accepted client connection in error state: %s (conn: %s)",
            connGetLastError(conn),
            connGetInfo(conn, conninfo, sizeof(conninfo)));
        connClose(conn);
        return;
    }

    /* Limit the number of connections we take at the same time.
     * 
     * 限制同时使用的连接数量
     *
     * Admission control will happen before a client is created and connAccept()
     * called, because we don't want to even start transport-level negotiation
     * if rejected. 
     * 
     * 在 client 被创建和 connAccept() 被调用之前进行连接控制，在此处做控制如果连接
     * 被拒，不用启动传输层的协商。
     * 
     * */
    if (listLength(server.clients) + getClusterConnectionsCount()
        >= server.maxclients)
    {
        char *err;
        if (server.cluster_enabled)
            err = "-ERR max number of clients + cluster "
                  "connections reached\r\n";
        else
            err = "-ERR max number of clients reached\r\n";

        /* That's a best effort error message, don't check write errors.
         * Note that for TLS connections, no handshake was done yet so nothing
         * is written and the connection will just drop. */
        if (connWrite(conn,err,strlen(err)) == -1) {
            /* Nothing to do, Just to avoid the warning... */
        }
        server.stat_rejected_conn++;
        connClose(conn);
        return;
    }

    /* Create connection and client */
    /**
     * 创建 client
     */
    if ((c = createClient(conn)) == NULL) {
        serverLog(LL_WARNING,
            "Error registering fd event for the new client: %s (conn: %s)",
            connGetLastError(conn),
            connGetInfo(conn, conninfo, sizeof(conninfo)));
        connClose(conn); /* May be already closed, just ignore errors */
        return;
    }

    /* Last chance to keep flags */
    c->flags |= flags;

    /* Initiate accept.
     * 
     * 启动 accept
     * 
     * Note that connAccept() is free to do two things here:
     * 注意 connAccept() 可以自由的做两件事：
     * 1. Call clientAcceptHandler() immediately;
     *    立刻调用 clientAcceptHandler() 函数
     * 2. Schedule a future call to clientAcceptHandler().
     *    为将来调用 clientAcceptHandler() 函数做准备
     *
     * Because of that, we must do nothing else afterwards.
     * 因此，现在调用了，之后就不用调用了
     */
    if (connAccept(conn, clientAcceptHandler) == C_ERR) {
        char conninfo[100];
        if (connGetState(conn) == CONN_STATE_ERROR)
            serverLog(LL_WARNING,
                    "Error accepting a client connection: %s (conn: %s)",
                    connGetLastError(conn), connGetInfo(conn, conninfo, sizeof(conninfo)));
        freeClient(connGetPrivateData(conn));
        return;
    }
}
/**
 * 客户端 TCP 连接应答处理器
 * 为了提高效率，该函数每次被调用时，最多
 * 可以处理 MAX_ACCEPTS_PER_CALL=1000 次的连接接入
 */
void acceptTcpHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
    // ip 地址字符集
    char cip[NET_IP_STR_LEN];
    UNUSED(el);
    UNUSED(mask);
    UNUSED(privdata);

    while(max--) {
        // accept 客户端连接，返回一个新套接字的文件描述符
        cfd = anetTcpAccept(server.neterr, fd, cip, sizeof(cip), &cport);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING,
                    "Accepting client connection: %s", server.neterr);
            return;
        }
        anetCloexec(cfd);
        serverLog(LL_VERBOSE,"Accepted %s:%d", cip, cport);
        // 创建客户端状态(Client)
        acceptCommonHandler(connCreateAcceptedSocket(cfd),0,cip);
    }
}

void acceptTLSHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
    char cip[NET_IP_STR_LEN];
    UNUSED(el);
    UNUSED(mask);
    UNUSED(privdata);

    while(max--) {
        cfd = anetTcpAccept(server.neterr, fd, cip, sizeof(cip), &cport);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING,
                    "Accepting client connection: %s", server.neterr);
            return;
        }
        anetCloexec(cfd);
        serverLog(LL_VERBOSE,"Accepted %s:%d", cip, cport);
        acceptCommonHandler(connCreateAcceptedTLS(cfd, server.tls_auth_clients),0,cip);
    }
}

void acceptUnixHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cfd, max = MAX_ACCEPTS_PER_CALL;
    UNUSED(el);
    UNUSED(mask);
    UNUSED(privdata);

    while(max--) {
        cfd = anetUnixAccept(server.neterr, fd);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING,
                    "Accepting client connection: %s", server.neterr);
            return;
        }
        anetCloexec(cfd);
        serverLog(LL_VERBOSE,"Accepted connection to %s", server.unixsocket);
        acceptCommonHandler(connCreateAcceptedSocket(cfd),CLIENT_UNIX_SOCKET,NULL);
    }
}

void freeClientOriginalArgv(client *c) {
    /* We didn't rewrite this client */
    if (!c->original_argv) return;

    for (int j = 0; j < c->original_argc; j++)
        decrRefCount(c->original_argv[j]);
    zfree(c->original_argv);
    c->original_argv = NULL;
    c->original_argc = 0;
}

static void freeClientArgv(client *c) {
    int j;
    for (j = 0; j < c->argc; j++)
        decrRefCount(c->argv[j]);
    c->argc = 0;
    c->cmd = NULL;
    c->argv_len_sum = 0;
}

/* Close all the slaves connections. This is useful in chained replication
 * when we resync with our own master and want to force all our slaves to
 * resync with us as well. */
void disconnectSlaves(void) {
    listIter li;
    listNode *ln;
    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        freeClient((client*)ln->value);
    }
}

/* Check if there is any other slave waiting dumping RDB finished expect me.
 * This function is useful to judge current dumping RDB can be used for full
 * synchronization or not. */
int anyOtherSlaveWaitRdb(client *except_me) {
    listIter li;
    listNode *ln;

    listRewind(server.slaves, &li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;
        if (slave != except_me &&
            slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END)
        {
            return 1;
        }
    }
    return 0;
}

/* Remove the specified client from global lists where the client could
 * be referenced, not including the Pub/Sub channels.
 * This is used by freeClient() and replicationCacheMaster().
 * 
 * 从全局客户端列表中移除指定的客户端，不包括 Pub/Sub 通道
 * 该函数被 freeClient() 和 replicationCacheMaster() 调用
 **/
void unlinkClient(client *c) {
    listNode *ln;

    /* If this is marked as current client unset it. */
    if (server.current_client == c) server.current_client = NULL;

    /* Certain operations must be done only if the client has an active connection.
     * If the client was already unlinked or if it's a "fake client" the
     * conn is already set to NULL. */
    if (c->conn) {
        /* Remove from the list of active clients. */
        if (c->client_list_node) {
            uint64_t id = htonu64(c->id);
            raxRemove(server.clients_index,(unsigned char*)&id,sizeof(id),NULL);
            listDelNode(server.clients,c->client_list_node);
            c->client_list_node = NULL;
        }

        /* Check if this is a replica waiting for diskless replication (rdb pipe),
         * in which case it needs to be cleaned from that list */
        if (c->flags & CLIENT_SLAVE &&
            c->replstate == SLAVE_STATE_WAIT_BGSAVE_END &&
            server.rdb_pipe_conns)
        {
            int i;
            for (i=0; i < server.rdb_pipe_numconns; i++) {
                if (server.rdb_pipe_conns[i] == c->conn) {
                    rdbPipeWriteHandlerConnRemoved(c->conn);
                    server.rdb_pipe_conns[i] = NULL;
                    break;
                }
            }
        }
        connClose(c->conn);
        c->conn = NULL;
    }

    /* Remove from the list of pending writes if needed. */
    if (c->flags & CLIENT_PENDING_WRITE) {
        ln = listSearchKey(server.clients_pending_write,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_pending_write,ln);
        c->flags &= ~CLIENT_PENDING_WRITE;
    }

    /* Remove from the list of pending reads if needed. */
    if (c->flags & CLIENT_PENDING_READ) {
        ln = listSearchKey(server.clients_pending_read,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_pending_read,ln);
        c->flags &= ~CLIENT_PENDING_READ;
    }

    /* When client was just unblocked because of a blocking operation,
     * remove it from the list of unblocked clients. */
    if (c->flags & CLIENT_UNBLOCKED) {
        ln = listSearchKey(server.unblocked_clients,c);
        serverAssert(ln != NULL);
        listDelNode(server.unblocked_clients,ln);
        c->flags &= ~CLIENT_UNBLOCKED;
    }

    /* Clear the tracking status. */
    if (c->flags & CLIENT_TRACKING) disableTracking(c);
}
/**
 * 释放客户端，如下情况可以导致客户端关闭
 * 1.客户端进程退出或者被杀死
 * 2.客户端向服务器发送了带有不符合协议格式的命令请求
 * 3.客户端成了 CLIENT KILL 命令的目标
 * 4.服务器设置了 timeout 配置选项，那么客户端的空转时间超过了 timeout 选项设置的值，客户端关闭
 * 5.客户端发送的命令请求的大小超过了输入缓冲区的限制大小
 * 6.发送给客户端的命令回复的大小超过了输出缓冲区的限制大小
 * 7.输出缓冲区的大小超过了硬性限制所设置的大小
 * 8.输出缓冲区的大小超过了软性限制所设置的大小，但还没有超过硬性限制，
 *   那么服务器使用客户端状态结构的 obuf_soft_limit_reached_time 属性
 *   纪录下客户端到达软性限制的起始时间，如果超出软性限制的持续时间超过服务器设定的时长
 *   客户都关闭
 * 
 * 
 */
void freeClient(client *c) {
    listNode *ln;

    /* If a client is protected, yet we need to free it right now, make sure
     * to at least use asynchronous freeing. */
    if (c->flags & CLIENT_PROTECTED) {
        freeClientAsync(c);
        return;
    }

    /* For connected clients, call the disconnection event of modules hooks. */
    if (c->conn) {
        moduleFireServerEvent(REDISMODULE_EVENT_CLIENT_CHANGE,
                              REDISMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED,
                              c);
    }

    /* Notify module system that this client auth status changed. */
    moduleNotifyUserChanged(c);

    /* If this client was scheduled for async freeing we need to remove it
     * from the queue. Note that we need to do this here, because later
     * we may call replicationCacheMaster() and the client should already
     * be removed from the list of clients to free. */
    if (c->flags & CLIENT_CLOSE_ASAP) {
        ln = listSearchKey(server.clients_to_close,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_to_close,ln);
    }

    /* If it is our master that's being disconnected we should make sure
     * to cache the state to try a partial resynchronization later.
     *
     * Note that before doing this we make sure that the client is not in
     * some unexpected state, by checking its flags. */
    if (server.master && c->flags & CLIENT_MASTER) {
        serverLog(LL_WARNING,"Connection with master lost.");
        if (!(c->flags & (CLIENT_PROTOCOL_ERROR|CLIENT_BLOCKED))) {
            c->flags &= ~(CLIENT_CLOSE_ASAP|CLIENT_CLOSE_AFTER_REPLY);
            replicationCacheMaster(c);
            return;
        }
    }

    /* Log link disconnection with slave */
    if (getClientType(c) == CLIENT_TYPE_SLAVE) {
        serverLog(LL_WARNING,"Connection with replica %s lost.",
            replicationGetSlaveName(c));
    }

    /* Free the query buffer */
    sdsfree(c->querybuf);
    sdsfree(c->pending_querybuf);
    c->querybuf = NULL;

    /* Deallocate structures used to block on blocking ops. */
    if (c->flags & CLIENT_BLOCKED) unblockClient(c);
    dictRelease(c->bpop.keys);

    /* UNWATCH all the keys */
    unwatchAllKeys(c);
    listRelease(c->watched_keys);

    /* Unsubscribe from all the pubsub channels */
    pubsubUnsubscribeAllChannels(c,0);
    pubsubUnsubscribeAllPatterns(c,0);
    dictRelease(c->pubsub_channels);
    listRelease(c->pubsub_patterns);

    /* Free data structures. */
    listRelease(c->reply);
    freeClientArgv(c);
    freeClientOriginalArgv(c);

    /* Unlink the client: this will close the socket, remove the I/O
     * handlers, and remove references of the client from different
     * places where active clients may be referenced. */
    unlinkClient(c);

    /* Master/slave cleanup Case 1:
     * we lost the connection with a slave. */
    if (c->flags & CLIENT_SLAVE) {
        /* If there is no any other slave waiting dumping RDB finished, the
         * current child process need not continue to dump RDB, then we kill it.
         * So child process won't use more memory, and we also can fork a new
         * child process asap to dump rdb for next full synchronization or bgsave.
         * But we also need to check if users enable 'save' RDB, if enable, we
         * should not remove directly since that means RDB is important for users
         * to keep data safe and we may delay configured 'save' for full sync. */
        if (server.saveparamslen == 0 &&
            c->replstate == SLAVE_STATE_WAIT_BGSAVE_END &&
            server.child_type == CHILD_TYPE_RDB &&
            server.rdb_child_type == RDB_CHILD_TYPE_DISK &&
            anyOtherSlaveWaitRdb(c) == 0)
        {
            killRDBChild();
        }
        if (c->replstate == SLAVE_STATE_SEND_BULK) {
            if (c->repldbfd != -1) close(c->repldbfd);
            if (c->replpreamble) sdsfree(c->replpreamble);
        }
        list *l = (c->flags & CLIENT_MONITOR) ? server.monitors : server.slaves;
        ln = listSearchKey(l,c);
        serverAssert(ln != NULL);
        listDelNode(l,ln);
        /* We need to remember the time when we started to have zero
         * attached slaves, as after some time we'll free the replication
         * backlog. */
        if (getClientType(c) == CLIENT_TYPE_SLAVE && listLength(server.slaves) == 0)
            server.repl_no_slaves_since = server.unixtime;
        refreshGoodSlavesCount();
        /* Fire the replica change modules event. */
        if (c->replstate == SLAVE_STATE_ONLINE)
            moduleFireServerEvent(REDISMODULE_EVENT_REPLICA_CHANGE,
                                  REDISMODULE_SUBEVENT_REPLICA_CHANGE_OFFLINE,
                                  NULL);
    }

    /* Master/slave cleanup Case 2:
     * we lost the connection with the master. */
    if (c->flags & CLIENT_MASTER) replicationHandleMasterDisconnection();

   /* Remove the contribution that this client gave to our
     * incrementally computed memory usage. */
    server.stat_clients_type_memory[c->client_cron_last_memory_type] -=
        c->client_cron_last_memory_usage;

    /* Release other dynamically allocated client structure fields,
     * and finally release the client structure itself. */
    if (c->name) decrRefCount(c->name);
    zfree(c->argv);
    c->argv_len_sum = 0;
    freeClientMultiState(c);
    sdsfree(c->peerid);
    sdsfree(c->sockname);
    sdsfree(c->slave_addr);
    zfree(c);
}

/* Schedule a client to free it at a safe time in the serverCron() function.
 * This function is useful when we need to terminate a client but we are in
 * a context where calling freeClient() is not possible, because the client
 * should be valid for the continuation of the flow of the program. */
void freeClientAsync(client *c) {
    /* We need to handle concurrent access to the server.clients_to_close list
     * only in the freeClientAsync() function, since it's the only function that
     * may access the list while Redis uses I/O threads. All the other accesses
     * are in the context of the main thread while the other threads are
     * idle. */
    if (c->flags & CLIENT_CLOSE_ASAP || c->flags & CLIENT_LUA) return;
    c->flags |= CLIENT_CLOSE_ASAP;
    if (server.io_threads_num == 1) {
        /* no need to bother with locking if there's just one thread (the main thread) */
        listAddNodeTail(server.clients_to_close,c);
        return;
    }
    static pthread_mutex_t async_free_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&async_free_queue_mutex);
    listAddNodeTail(server.clients_to_close,c);
    pthread_mutex_unlock(&async_free_queue_mutex);
}

/* Free the clients marked as CLOSE_ASAP, return the number of clients
 * freed. */
int freeClientsInAsyncFreeQueue(void) {
    int freed = 0;
    listIter li;
    listNode *ln;

    listRewind(server.clients_to_close,&li);
    while ((ln = listNext(&li)) != NULL) {
        client *c = listNodeValue(ln);

        if (c->flags & CLIENT_PROTECTED) continue;

        c->flags &= ~CLIENT_CLOSE_ASAP;
        freeClient(c);
        listDelNode(server.clients_to_close,ln);
        freed++;
    }
    return freed;
}

/* Return a client by ID, or NULL if the client ID is not in the set
 * of registered clients. Note that "fake clients", created with -1 as FD,
 * are not registered clients. */
client *lookupClientByID(uint64_t id) {
    id = htonu64(id);
    client *c = raxFind(server.clients_index,(unsigned char*)&id,sizeof(id));
    return (c == raxNotFound) ? NULL : c;
}

/* Write data in output buffers to client. Return C_OK if the client
 * is still valid after the call, C_ERR if it was freed because of some
 * error.  If handler_installed is set, it will attempt to clear the
 * write event.
 *
 * 写数据到客户端的输出缓冲区。
 * 如果调用后客户端仍然有效，则返回 C_OK
 * 如果客户端因为某种错误而被释放，则返回 C_ERR
 * 如果 handler_installed 被设置，它将尝试清除写事件
 * 
 * This function is called by threads, but always with handler_installed
 * set to 0. So when handler_installed is set to 0 the function must be
 * thread safe. 
 * 
 * 此函数被线程调用时，始终将 handler_installed 设置为 0
 * 因此当 handler_installed 设置为 0 时，函数必须是线程安全的
 * 
 * 写事件触发的调用此函数，handler_installed 设置为 1
 **/
int writeToClient(client *c, int handler_installed) {
    /* Update total number of writes on server */
    atomicIncr(server.stat_total_writes_processed, 1);

    ssize_t nwritten = 0, totwritten = 0;
    size_t objlen;
    clientReplyBlock *o;

    // 有数据要写入客户端输出缓冲区
    while(clientHasPendingReplies(c)) {
        // 处理 buf 中回复信息
        if (c->bufpos > 0) {
            nwritten = connWrite(c->conn,c->buf+c->sentlen,c->bufpos-c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            /* If the buffer was sent, set bufpos to zero to continue with
             * the remainder of the reply. 
             *
             * 如果发送了缓冲区，设置 bufpos 为 0，继续执行其余的回复
             */
            if ((int)c->sentlen == c->bufpos) {
                c->bufpos = 0;
                c->sentlen = 0;
            }
        // 处理 reply 列表中的回复信息
        } else {
            o = listNodeValue(listFirst(c->reply));
            objlen = o->used;

            if (objlen == 0) {
                c->reply_bytes -= o->size;
                listDelNode(c->reply,listFirst(c->reply));
                continue;
            }

            nwritten = connWrite(c->conn, o->buf + c->sentlen, objlen - c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            /* If we fully sent the object on head go to the next one 
             * 如果这个节点中的数已经全部发送完，则移动到下一个节点，
             * 并将该节点从 reply 中删除
             */
            if (c->sentlen == objlen) {
                c->reply_bytes -= o->size;
                listDelNode(c->reply,listFirst(c->reply));
                c->sentlen = 0;
                /* If there are no longer objects in the list, we expect
                 * the count of reply bytes to be exactly zero. */
                if (listLength(c->reply) == 0)
                    serverAssert(c->reply_bytes == 0);
            }
        }
        /* Note that we avoid to send more than NET_MAX_WRITES_PER_EVENT
         * bytes, in a single threaded server it's a good idea to serve
         * other clients as well, even if a very large request comes from
         * super fast link that is always able to accept data (in real world
         * scenario think about 'KEYS *' against the loopback interface).
         *
         * However if we are over the maxmemory limit we ignore that and
         * just deliver as much data as it is possible to deliver.
         *
         * Moreover, we also send as much as possible if the client is
         * a slave or a monitor (otherwise, on high-speed traffic, the
         * replication/output buffer will grow indefinitely) 
         * 
         * 避免发送的字节数超过 NET_MAX_WRITES_PER_EVENT= 1024 * 64
         * */
        if (totwritten > NET_MAX_WRITES_PER_EVENT &&
            (server.maxmemory == 0 ||
             zmalloc_used_memory() < server.maxmemory) &&
            !(c->flags & CLIENT_SLAVE)) break;
    }
    atomicIncr(server.stat_net_output_bytes, totwritten);
    if (nwritten == -1) {
        if (connGetState(c->conn) == CONN_STATE_CONNECTED) {
            nwritten = 0;
        } else {
            serverLog(LL_VERBOSE,
                "Error writing to client: %s", connGetLastError(c->conn));
            freeClientAsync(c);
            return C_ERR;
        }
    }
    if (totwritten > 0) {
        /* For clients representing masters we don't count sending data
         * as an interaction, since we always send REPLCONF ACK commands
         * that take some time to just fill the socket output buffer.
         * We just rely on data / pings received for timeout detection. */
        if (!(c->flags & CLIENT_MASTER)) c->lastinteraction = server.unixtime;
    }
    if (!clientHasPendingReplies(c)) {
        c->sentlen = 0;
        /* Note that writeToClient() is called in a threaded way, but
         * adDeleteFileEvent() is not thread safe: however writeToClient()
         * is always called with handler_installed set to 0 from threads
         * so we are fine.  
         * 
         * 没有要发送的数据时，如果注册了写事件处理器，则删除写时间处理器
         * */
        if (handler_installed) connSetWriteHandler(c->conn, NULL);

        /* Close connection after entire reply has been sent. 
         * 全部回复信息发送完毕后，关闭连接
         */
        if (c->flags & CLIENT_CLOSE_AFTER_REPLY) {
            freeClientAsync(c);
            return C_ERR;
        }
    }
    return C_OK;
}

/* Write event handler. Just send data to the client. 
 * 写事件处理器，向客户端发送数据
 */
void sendReplyToClient(connection *conn) {
    client *c = connGetPrivateData(conn);
    writeToClient(c,1);
}

/* This function is called just before entering the event loop, in the hope
 * we can just write the replies to the client output buffer without any
 * need to use a syscall in order to install the writable event handler,
 * get it called, and so forth. 
 * 
 * 进入事件循环以前，这个函数被调用。
 * 
 * */
int handleClientsWithPendingWrites(void) {
    listIter li;
    listNode *ln;
    int processed = listLength(server.clients_pending_write);

    listRewind(server.clients_pending_write,&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        c->flags &= ~CLIENT_PENDING_WRITE;
        listDelNode(server.clients_pending_write,ln);

        /* If a client is protected, don't do anything,
         * that may trigger write error or recreate handler. */
        if (c->flags & CLIENT_PROTECTED) continue;

        /* Don't write to clients that are going to be closed anyway. */
        if (c->flags & CLIENT_CLOSE_ASAP) continue;

        /* Try to write buffers to the client socket. */
        if (writeToClient(c,0) == C_ERR) continue;

        /* If after the synchronous writes above we still have data to
         * output to the client, we need to install the writable handler. */
        if (clientHasPendingReplies(c)) {
            int ae_barrier = 0;
            /* For the fsync=always policy, we want that a given FD is never
             * served for reading and writing in the same event loop iteration,
             * so that in the middle of receiving the query, and serving it
             * to the client, we'll call beforeSleep() that will do the
             * actual fsync of AOF to disk. the write barrier ensures that. */
            if (server.aof_state == AOF_ON &&
                server.aof_fsync == AOF_FSYNC_ALWAYS)
            {
                ae_barrier = 1;
            }
            if (connSetWriteHandlerWithBarrier(c->conn, sendReplyToClient, ae_barrier) == C_ERR) {
                freeClientAsync(c);
            }
        }
    }
    return processed;
}

/* resetClient prepare the client to process the next command */
void resetClient(client *c) {
    redisCommandProc *prevcmd = c->cmd ? c->cmd->proc : NULL;

    freeClientArgv(c);
    c->reqtype = 0;
    c->multibulklen = 0;
    c->bulklen = -1;

    /* We clear the ASKING flag as well if we are not inside a MULTI, and
     * if what we just executed is not the ASKING command itself. */
    if (!(c->flags & CLIENT_MULTI) && prevcmd != askingCommand)
        c->flags &= ~CLIENT_ASKING;

    /* We do the same for the CACHING command as well. It also affects
     * the next command or transaction executed, in a way very similar
     * to ASKING. */
    if (!(c->flags & CLIENT_MULTI) && prevcmd != clientCommand)
        c->flags &= ~CLIENT_TRACKING_CACHING;

    /* Remove the CLIENT_REPLY_SKIP flag if any so that the reply
     * to the next command will be sent, but set the flag if the command
     * we just processed was "CLIENT REPLY SKIP". */
    c->flags &= ~CLIENT_REPLY_SKIP;
    if (c->flags & CLIENT_REPLY_SKIP_NEXT) {
        c->flags |= CLIENT_REPLY_SKIP;
        c->flags &= ~CLIENT_REPLY_SKIP_NEXT;
    }
}

/* This function is used when we want to re-enter the event loop but there
 * is the risk that the client we are dealing with will be freed in some
 * way. This happens for instance in:
 *
 * * DEBUG RELOAD and similar.
 * * When a Lua script is in -BUSY state.
 *
 * So the function will protect the client by doing two things:
 *
 * 1) It removes the file events. This way it is not possible that an
 *    error is signaled on the socket, freeing the client.
 * 2) Moreover it makes sure that if the client is freed in a different code
 *    path, it is not really released, but only marked for later release. */
void protectClient(client *c) {
    c->flags |= CLIENT_PROTECTED;
    if (c->conn) {
        connSetReadHandler(c->conn,NULL);
        connSetWriteHandler(c->conn,NULL);
    }
}

/* This will undo the client protection done by protectClient() */
void unprotectClient(client *c) {
    if (c->flags & CLIENT_PROTECTED) {
        c->flags &= ~CLIENT_PROTECTED;
        if (c->conn) {
            connSetReadHandler(c->conn,readQueryFromClient);
            if (clientHasPendingReplies(c)) clientInstallWriteHandler(c);
        }
    }
}

/* Like processMultibulkBuffer(), but for the inline protocol instead of RESP,
 * this function consumes the client query buffer and creates a command ready
 * to be executed inside the client structure. Returns C_OK if the command
 * is ready to be executed, or C_ERR if there is still protocol to read to
 * have a well formed command. The function also returns C_ERR when there is
 * a protocol error: in such a case the client structure is setup to reply
 * with the error and close the connection. */
int processInlineBuffer(client *c) {
    char *newline;
    int argc, j, linefeed_chars = 1;
    sds *argv, aux;
    size_t querylen;

    /* Search for end of line */
    newline = strchr(c->querybuf+c->qb_pos,'\n');

    /* Nothing to do without a \r\n */
    if (newline == NULL) {
        if (sdslen(c->querybuf)-c->qb_pos > PROTO_INLINE_MAX_SIZE) {
            addReplyError(c,"Protocol error: too big inline request");
            setProtocolError("too big inline request",c);
        }
        return C_ERR;
    }

    /* Handle the \r\n case. */
    if (newline != c->querybuf+c->qb_pos && *(newline-1) == '\r')
        newline--, linefeed_chars++;

    /* Split the input buffer up to the \r\n */
    querylen = newline-(c->querybuf+c->qb_pos);
    aux = sdsnewlen(c->querybuf+c->qb_pos,querylen);
    argv = sdssplitargs(aux,&argc);
    sdsfree(aux);
    if (argv == NULL) {
        addReplyError(c,"Protocol error: unbalanced quotes in request");
        setProtocolError("unbalanced quotes in inline request",c);
        return C_ERR;
    }

    /* Newline from slaves can be used to refresh the last ACK time.
     * This is useful for a slave to ping back while loading a big
     * RDB file. */
    if (querylen == 0 && getClientType(c) == CLIENT_TYPE_SLAVE)
        c->repl_ack_time = server.unixtime;

    /* Masters should never send us inline protocol to run actual
     * commands. If this happens, it is likely due to a bug in Redis where
     * we got some desynchronization in the protocol, for example
     * beause of a PSYNC gone bad.
     *
     * However the is an exception: masters may send us just a newline
     * to keep the connection active. */
    if (querylen != 0 && c->flags & CLIENT_MASTER) {
        sdsfreesplitres(argv,argc);
        serverLog(LL_WARNING,"WARNING: Receiving inline protocol from master, master stream corruption? Closing the master connection and discarding the cached master.");
        setProtocolError("Master using the inline protocol. Desync?",c);
        return C_ERR;
    }

    /* Move querybuffer position to the next query in the buffer. */
    c->qb_pos += querylen+linefeed_chars;

    /* Setup argv array on client structure */
    if (argc) {
        if (c->argv) zfree(c->argv);
        c->argv = zmalloc(sizeof(robj*)*argc);
        c->argv_len_sum = 0;
    }

    /* Create redis objects for all arguments. */
    for (c->argc = 0, j = 0; j < argc; j++) {
        c->argv[c->argc] = createObject(OBJ_STRING,argv[j]);
        c->argc++;
        c->argv_len_sum += sdslen(argv[j]);
    }
    zfree(argv);
    return C_OK;
}

/* Helper function. Record protocol erro details in server log,
 * and set the client as CLIENT_CLOSE_AFTER_REPLY and
 * CLIENT_PROTOCOL_ERROR. */
#define PROTO_DUMP_LEN 128
static void setProtocolError(const char *errstr, client *c) {
    if (server.verbosity <= LL_VERBOSE || c->flags & CLIENT_MASTER) {
        sds client = catClientInfoString(sdsempty(),c);

        /* Sample some protocol to given an idea about what was inside. */
        char buf[256];
        if (sdslen(c->querybuf)-c->qb_pos < PROTO_DUMP_LEN) {
            snprintf(buf,sizeof(buf),"Query buffer during protocol error: '%s'", c->querybuf+c->qb_pos);
        } else {
            snprintf(buf,sizeof(buf),"Query buffer during protocol error: '%.*s' (... more %zu bytes ...) '%.*s'", PROTO_DUMP_LEN/2, c->querybuf+c->qb_pos, sdslen(c->querybuf)-c->qb_pos-PROTO_DUMP_LEN, PROTO_DUMP_LEN/2, c->querybuf+sdslen(c->querybuf)-PROTO_DUMP_LEN/2);
        }

        /* Remove non printable chars. */
        char *p = buf;
        while (*p != '\0') {
            if (!isprint(*p)) *p = '.';
            p++;
        }

        /* Log all the client and protocol info. */
        int loglevel = (c->flags & CLIENT_MASTER) ? LL_WARNING :
                                                    LL_VERBOSE;
        serverLog(loglevel,
            "Protocol error (%s) from client: %s. %s", errstr, client, buf);
        sdsfree(client);
    }
    c->flags |= (CLIENT_CLOSE_AFTER_REPLY|CLIENT_PROTOCOL_ERROR);
}

/* Process the query buffer for client 'c', setting up the client argument
 * vector for command execution. Returns C_OK if after running the function
 * the client has a well-formed ready to be processed command, otherwise
 * C_ERR if there is still to read more buffer to get the full command.
 * The function also returns C_ERR when there is a protocol error: in such a
 * case the client structure is setup to reply with the error and close
 * the connection.
 *
 * This function is called if processInputBuffer() detects that the next
 * command is in RESP format, so the first byte in the command is found
 * to be '*'. Otherwise for inline commands processInlineBuffer() is called. */
int processMultibulkBuffer(client *c) {
    char *newline = NULL;
    int ok;
    long long ll;

    if (c->multibulklen == 0) {
        /* The client should have been reset */
        serverAssertWithInfo(c,NULL,c->argc == 0);

        /* Multi bulk length cannot be read without a \r\n */
        newline = strchr(c->querybuf+c->qb_pos,'\r');
        if (newline == NULL) {
            if (sdslen(c->querybuf)-c->qb_pos > PROTO_INLINE_MAX_SIZE) {
                addReplyError(c,"Protocol error: too big mbulk count string");
                setProtocolError("too big mbulk count string",c);
            }
            return C_ERR;
        }

        /* Buffer should also contain \n */
        if (newline-(c->querybuf+c->qb_pos) > (ssize_t)(sdslen(c->querybuf)-c->qb_pos-2))
            return C_ERR;

        /* We know for sure there is a whole line since newline != NULL,
         * so go ahead and find out the multi bulk length. */
        serverAssertWithInfo(c,NULL,c->querybuf[c->qb_pos] == '*');
        ok = string2ll(c->querybuf+1+c->qb_pos,newline-(c->querybuf+1+c->qb_pos),&ll);
        if (!ok || ll > 1024*1024) {
            addReplyError(c,"Protocol error: invalid multibulk length");
            setProtocolError("invalid mbulk count",c);
            return C_ERR;
        }

        c->qb_pos = (newline-c->querybuf)+2;

        if (ll <= 0) return C_OK;

        c->multibulklen = ll;

        /* Setup argv array on client structure */
        if (c->argv) zfree(c->argv);
        c->argv = zmalloc(sizeof(robj*)*c->multibulklen);
        c->argv_len_sum = 0;
    }

    serverAssertWithInfo(c,NULL,c->multibulklen > 0);
    while(c->multibulklen) {
        /* Read bulk length if unknown */
        if (c->bulklen == -1) {
            newline = strchr(c->querybuf+c->qb_pos,'\r');
            if (newline == NULL) {
                if (sdslen(c->querybuf)-c->qb_pos > PROTO_INLINE_MAX_SIZE) {
                    addReplyError(c,
                        "Protocol error: too big bulk count string");
                    setProtocolError("too big bulk count string",c);
                    return C_ERR;
                }
                break;
            }

            /* Buffer should also contain \n */
            if (newline-(c->querybuf+c->qb_pos) > (ssize_t)(sdslen(c->querybuf)-c->qb_pos-2))
                break;

            if (c->querybuf[c->qb_pos] != '$') {
                addReplyErrorFormat(c,
                    "Protocol error: expected '$', got '%c'",
                    c->querybuf[c->qb_pos]);
                setProtocolError("expected $ but got something else",c);
                return C_ERR;
            }

            ok = string2ll(c->querybuf+c->qb_pos+1,newline-(c->querybuf+c->qb_pos+1),&ll);
            if (!ok || ll < 0 ||
                (!(c->flags & CLIENT_MASTER) && ll > server.proto_max_bulk_len)) {
                addReplyError(c,"Protocol error: invalid bulk length");
                setProtocolError("invalid bulk length",c);
                return C_ERR;
            }

            c->qb_pos = newline-c->querybuf+2;
            if (ll >= PROTO_MBULK_BIG_ARG) {
                /* If we are going to read a large object from network
                 * try to make it likely that it will start at c->querybuf
                 * boundary so that we can optimize object creation
                 * avoiding a large copy of data.
                 *
                 * But only when the data we have not parsed is less than
                 * or equal to ll+2. If the data length is greater than
                 * ll+2, trimming querybuf is just a waste of time, because
                 * at this time the querybuf contains not only our bulk. */
                if (sdslen(c->querybuf)-c->qb_pos <= (size_t)ll+2) {
                    sdsrange(c->querybuf,c->qb_pos,-1);
                    c->qb_pos = 0;
                    /* Hint the sds library about the amount of bytes this string is
                     * going to contain. */
                    c->querybuf = sdsMakeRoomFor(c->querybuf,ll+2-sdslen(c->querybuf));
                }
            }
            c->bulklen = ll;
        }

        /* Read bulk argument */
        if (sdslen(c->querybuf)-c->qb_pos < (size_t)(c->bulklen+2)) {
            /* Not enough data (+2 == trailing \r\n) */
            break;
        } else {
            /* Optimization: if the buffer contains JUST our bulk element
             * instead of creating a new object by *copying* the sds we
             * just use the current sds string. */
            if (c->qb_pos == 0 &&
                c->bulklen >= PROTO_MBULK_BIG_ARG &&
                sdslen(c->querybuf) == (size_t)(c->bulklen+2))
            {
                c->argv[c->argc++] = createObject(OBJ_STRING,c->querybuf);
                c->argv_len_sum += c->bulklen;
                sdsIncrLen(c->querybuf,-2); /* remove CRLF */
                /* Assume that if we saw a fat argument we'll see another one
                 * likely... */
                c->querybuf = sdsnewlen(SDS_NOINIT,c->bulklen+2);
                sdsclear(c->querybuf);
            } else {
                c->argv[c->argc++] =
                    createStringObject(c->querybuf+c->qb_pos,c->bulklen);
                c->argv_len_sum += c->bulklen;
                c->qb_pos += c->bulklen+2;
            }
            c->bulklen = -1;
            c->multibulklen--;
        }
    }

    /* We're done when c->multibulk == 0 */
    if (c->multibulklen == 0) return C_OK;

    /* Still not ready to process the command */
    return C_ERR;
}

/* Perform necessary tasks after a command was executed:
 * 命令被执行后，必须要执行的任务：
 * 1. The client is reset unless there are reasons to avoid doing it.
 * 除非有其它原因，否则客户端需要被重置
 * 2. In the case of master clients, the replication offset is updated.
 * 如果是主节点客户端，需要更新复制偏移量
 * 3. Propagate commands we got from our master to replicas down the line. 
 * 把从主节点得到的命令同步到备库
 * */
void commandProcessed(client *c) {
    long long prev_offset = c->reploff;
    // 主客户端，且客户端不处于事务上下文中
    if (c->flags & CLIENT_MASTER && !(c->flags & CLIENT_MULTI)) {
        /* Update the applied replication offset of our master. */
        // 更新客户端复制偏移量
        c->reploff = c->read_reploff - sdslen(c->querybuf) + c->qb_pos;
    }

    /* Don't reset the client structure for clients blocked in a
     * module blocking command, so that the reply callback will
     * still be able to access the client argv and argc field.
     * The client will be reset in unblockClientFromModule(). */
    /**
     * 客户端不处于阻塞等待状态或
     * 客户端没有被加载模块或暂停阻塞
     */
    if (!(c->flags & CLIENT_BLOCKED) ||
        (c->btype != BLOCKED_MODULE && c->btype != BLOCKED_PAUSE))
    {
        resetClient(c);
    }

    /* If the client is a master we need to compute the difference
     * between the applied offset before and after processing the buffer,
     * to understand how much of the replication stream was actually
     * applied to the master state: this quantity, and its corresponding
     * part of the replication stream, will be propagated to the
     * sub-replicas and to the replication backlog. */
    if (c->flags & CLIENT_MASTER) {
        long long applied = c->reploff - prev_offset;
        if (applied) {
            replicationFeedSlavesFromMasterStream(server.slaves,
                    c->pending_querybuf, applied);
            sdsrange(c->pending_querybuf,applied,-1);
        }
    }
}

/* This function calls processCommand(), but also performs a few sub tasks
 * for the client that are useful in that context:
 * 
 * 调用 processCommand() 函数执行命令和为客户端执行一些子任务
 * 
 * 1. It sets the current client to the client 'c'.
 * 2. calls commandProcessed() if the command was handled.
 * 
 * 1.调用 processCommand() 之前将 current_client 设置为 c
 * 2.如果命令被执行，则调用 commandProcessed() 函数
 *
 * The function returns C_ERR in case the client was freed as a side effect
 * of processing the command, otherwise C_OK is returned. 
 * 
 * 在处理命令的时候，如果客户端被释放，此函数返回 C_ERR，否则返回 C_OK
 * */
int processCommandAndResetClient(client *c) {
    int deadclient = 0;
    // 将客户端 C 保存为当前客户端
    server.current_client = c;
    // 处理命令
    if (processCommand(c) == C_OK) {
        // 处理命令后，需要处理的事情
        commandProcessed(c);
    }
    if (server.current_client == NULL) deadclient = 1;
    server.current_client = NULL;
    /* performEvictions may flush slave output buffers. This may
     * result in a slave, that may be the active client, to be
     * freed. */
    return deadclient ? C_ERR : C_OK;
}


/* This function will execute any fully parsed commands pending on
 * the client. Returns C_ERR if the client is no longer valid after executing
 * the command, and C_OK for all other cases. 
 * 
 * 此函数将在挂起的客户端上执行已经完全解析的命令
 * 如果此客户端不在有效，执行命令后返回 C_ERR，
 * 其它情况都返回 C_OK
 * */
int processPendingCommandsAndResetClient(client *c) {
    if (c->flags & CLIENT_PENDING_COMMAND) {
        // 如果客户端被标记为 CLIENT_PENDING_COMMAND 状态
        // 则将客户端标记为非 CLIENT_PENDING_COMMAND 状态
        c->flags &= ~CLIENT_PENDING_COMMAND;
        // 执行命令，并重置客户端
        if (processCommandAndResetClient(c) == C_ERR) {
            return C_ERR;
        }
    }
    return C_OK;
}

/* This function is called every time, in the client structure 'c', there is
 * more query buffer to process, because we read more data from the socket
 * or because a client was blocked and later reactivated, so there could be
 * pending query buffer, already representing a full command, to process.
 * 
 * 从客户端输入缓冲区中取出数据，并解析出参数，
 * 直到输入缓冲区中的数据被处理完，函数才返回
 */
void processInputBuffer(client *c) {
    /* Keep processing while there is something in the input buffer 
     * 处理输入缓冲区中的数据，知道缓冲区中的数据被处理完
     */
    while(c->qb_pos < sdslen(c->querybuf)) {
        /* Immediately abort if the client is in the middle of something. 
         * 如果客户端正在处理其它事情，立刻中止
         */
        if (c->flags & CLIENT_BLOCKED) break;

        /* Don't process more buffers from clients that have already pending
         * commands to execute in c->argv. 
         * 如果客户端正准备执行解析好的命令，立刻中止
         */
        if (c->flags & CLIENT_PENDING_COMMAND) break;

        /* Don't process input from the master while there is a busy script
         * condition on the slave. We want just to accumulate the replication
         * stream (instead of replying -BUSY like we do with other clients) and
         * later resume the processing. 
         * 
         * 当 slave 节点正在处理一个脚本，立刻中止
         * */
        if (server.lua_timedout && c->flags & CLIENT_MASTER) break;

        /* CLIENT_CLOSE_AFTER_REPLY closes the connection once the reply is
         * written to the client. Make sure to not let the reply grow after
         * this flag has been set (i.e. don't process more commands).
         *
         * The same applies for clients we want to terminate ASAP. 
         * 
         * 客户端已经设置了关闭 FLAG ，没有必要处理命令了
         * 
         * */
        if (c->flags & (CLIENT_CLOSE_AFTER_REPLY|CLIENT_CLOSE_ASAP)) break;

        /* Determine request type when unknown. */
        /**
         * 判断请求的类型
         * 简单来说，多条查询是一般客户端发送来的，
         * 而内联查询则是 TELNET 发送来的
         */
        if (!c->reqtype) {
            if (c->querybuf[c->qb_pos] == '*') {
                // 多条查询
                c->reqtype = PROTO_REQ_MULTIBULK;
            } else {
                // 内联查询
                c->reqtype = PROTO_REQ_INLINE;
            }
        }

        // 将缓冲区中的内容解析成命令，以及命令参数
        // 内联查询
        if (c->reqtype == PROTO_REQ_INLINE) {
            if (processInlineBuffer(c) != C_OK) break;
            /* If the Gopher mode and we got zero or one argument, process
             * the request in Gopher mode. To avoid data race, Redis won't
             * support Gopher if enable io threads to read queries. */
            if (server.gopher_enabled && !server.io_threads_do_reads &&
                ((c->argc == 1 && ((char*)(c->argv[0]->ptr))[0] == '/') ||
                  c->argc == 0))
            {
                processGopherRequest(c);
                resetClient(c);
                c->flags |= CLIENT_CLOSE_AFTER_REPLY;
                break;
            }
        // 多条查询
        } else if (c->reqtype == PROTO_REQ_MULTIBULK) {
            if (processMultibulkBuffer(c) != C_OK) break;
        } else {
            serverPanic("Unknown request type");
        }

        /* Multibulk processing could see a <= 0 length. */
        // 多批量处理情况下可能出现 a<=0 
        if (c->argc == 0) {
            resetClient(c);
        } else {
            /* If we are in the context of an I/O thread, we can't really
             * execute the command here. All we can do is to flag the client
             * as one that needs to process the command. 
             * 
             * 如果当前是在 I/O 线程上下文中，客户端命令不能被执行，
             * 只能将客户端标记为已经准备好执行命令的状态，等主线程来执行该命令
             * */
            if (c->flags & CLIENT_PENDING_READ) {
                // 将客户端标记为已经准备好执行命令的状态
                c->flags |= CLIENT_PENDING_COMMAND;
                break;
            }

            /* We are finally ready to execute the command. 
             * 执行命令并重置客户端
             */
            if (processCommandAndResetClient(c) == C_ERR) {
                /* If the client is no longer valid, we avoid exiting this
                 * loop and trimming the client buffer later. So we return
                 * ASAP in that case. */
                return;
            }
        }
    }

    /* Trim to pos */
    if (c->qb_pos) {
        // 保留SDS给定区间内的数据，不在区间内的数据会被覆盖或清除
        sdsrange(c->querybuf,c->qb_pos,-1);
        c->qb_pos = 0;
    }
}
/**
 * 读取客户端的输入缓冲区内容
 */
void readQueryFromClient(connection *conn) {
    client *c = connGetPrivateData(conn);
    int nread, readlen;
    size_t qblen;

    /* Check if we want to read from the client later when exiting from
     * the event loop. This is the case if threaded I/O is enabled. 
     * 
     * 如果是稍后在退出事件循环时从客户端读取数据，则直接返回
     * 如果启动了线程 I/O，则会出现这种情况。
     * 如果是这种情况，postponeClientRead() 
     * 函数会将客户端放入 clients_pending_read 列表
     */
    if (postponeClientRead(c)) return;

    /* Update total number of reads on server */
    /**
     * 更新 server.stat_total_reads_processed 的值
     */
    atomicIncr(server.stat_total_reads_processed, 1);

    // 读入长度（默认为 16 MB）
    readlen = PROTO_IOBUF_LEN;
    /* If this is a multi bulk request, and we are processing a bulk reply
     * that is large enough, try to maximize the probability that the query
     * buffer contains exactly the SDS string representing the object, even
     * at the risk of requiring more read(2) calls. This way the function
     * processMultiBulkBuffer() can avoid copying buffers to create the
     * Redis Object representing the argument. */
    if (c->reqtype == PROTO_REQ_MULTIBULK && c->multibulklen && c->bulklen != -1
        && c->bulklen >= PROTO_MBULK_BIG_ARG)
    {
        ssize_t remaining = (size_t)(c->bulklen+2)-sdslen(c->querybuf);

        /* Note that the 'remaining' variable may be zero in some edge case,
         * for example once we resume a blocked client after CLIENT PAUSE. */
        if (remaining > 0 && remaining < readlen) readlen = remaining;
    }
    // 获取输入缓冲区当前内容长度
    qblen = sdslen(c->querybuf);
    // 更新输入缓冲区峰值大小
    if (c->querybuf_peak < qblen) c->querybuf_peak = qblen;
    // 扩大输入缓冲区的空间
    c->querybuf = sdsMakeRoomFor(c->querybuf, readlen);
    // 读取内容到输入缓冲区
    nread = connRead(c->conn, c->querybuf+qblen, readlen);

    // 读入出错
    if (nread == -1) {
        if (connGetState(conn) == CONN_STATE_CONNECTED) {
            return;
        } else {
            serverLog(LL_VERBOSE, "Reading from client: %s",connGetLastError(c->conn));
            freeClientAsync(c);
            return;
        }
    // 遇到 EOF
    } else if (nread == 0) {
        serverLog(LL_VERBOSE, "Client closed connection");
        freeClientAsync(c);
        return;
    } else if (c->flags & CLIENT_MASTER) {
        /* Append the query buffer to the pending (not applied) buffer
         * of the master. We'll use this buffer later in order to have a
         * copy of the string applied by the last command executed. */
        c->pending_querybuf = sdscatlen(c->pending_querybuf,
                                        c->querybuf+qblen,nread);
    }
    // 更新输入缓冲区 SDS 的 len 字段的值
    sdsIncrLen(c->querybuf,nread);
    // 客户端和服务端最后一次交互时间
    c->lastinteraction = server.unixtime;
    // 如果服务端是主，更新主服务器读复制偏移量
    if (c->flags & CLIENT_MASTER) c->read_reploff += nread;
    atomicIncr(server.stat_net_input_bytes, nread);
    // 输入缓冲区长度超出服务器最大缓冲区长度
    // 清空缓冲区并释放客户端
    if (sdslen(c->querybuf) > server.client_max_querybuf_len) {
        sds ci = catClientInfoString(sdsempty(),c), bytes = sdsempty();

        bytes = sdscatrepr(bytes,c->querybuf,64);
        serverLog(LL_WARNING,"Closing client that reached max query buffer length: %s (qbuf initial bytes: %s)", ci, bytes);
        sdsfree(ci);
        sdsfree(bytes);
        freeClientAsync(c);
        return;
    }

    /* There is more data in the client input buffer, continue parsing it
     * in case to check if there is a full command to execute. 
     *
     * 从输入缓冲区读取数据，解析参数，并执行命令
     * 
     * 函数会执行到缓存中的所有内容都被处理完为止
     */
     processInputBuffer(c);
}

void getClientsMaxBuffers(unsigned long *longest_output_list,
                          unsigned long *biggest_input_buffer) {
    client *c;
    listNode *ln;
    listIter li;
    unsigned long lol = 0, bib = 0;

    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        c = listNodeValue(ln);

        if (listLength(c->reply) > lol) lol = listLength(c->reply);
        if (sdslen(c->querybuf) > bib) bib = sdslen(c->querybuf);
    }
    *longest_output_list = lol;
    *biggest_input_buffer = bib;
}

/* A Redis "Address String" is a colon separated ip:port pair.
 * For IPv4 it's in the form x.y.z.k:port, example: "127.0.0.1:1234".
 * For IPv6 addresses we use [] around the IP part, like in "[::1]:1234".
 * For Unix sockets we use path:0, like in "/tmp/redis:0".
 *
 * An Address String always fits inside a buffer of NET_ADDR_STR_LEN bytes,
 * including the null term.
 *
 * On failure the function still populates 'addr' with the "?:0" string in case
 * you want to relax error checking or need to display something anyway (see
 * anetFdToString implementation for more info). */
void genClientAddrString(client *client, char *addr,
                         size_t addr_len, int fd_to_str_type) {
    if (client->flags & CLIENT_UNIX_SOCKET) {
        /* Unix socket client. */
        snprintf(addr,addr_len,"%s:0",server.unixsocket);
    } else {
        /* TCP client. */
        connFormatFdAddr(client->conn,addr,addr_len,fd_to_str_type);
    }
}

/* This function returns the client peer id, by creating and caching it
 * if client->peerid is NULL, otherwise returning the cached value.
 * The Peer ID never changes during the life of the client, however it
 * is expensive to compute. */
char *getClientPeerId(client *c) {
    char peerid[NET_ADDR_STR_LEN];

    if (c->peerid == NULL) {
        genClientAddrString(c,peerid,sizeof(peerid),FD_TO_PEER_NAME);
        c->peerid = sdsnew(peerid);
    }
    return c->peerid;
}

/* This function returns the client bound socket name, by creating and caching
 * it if client->sockname is NULL, otherwise returning the cached value.
 * The Socket Name never changes during the life of the client, however it
 * is expensive to compute. */
char *getClientSockname(client *c) {
    char sockname[NET_ADDR_STR_LEN];

    if (c->sockname == NULL) {
        genClientAddrString(c,sockname,sizeof(sockname),FD_TO_SOCK_NAME);
        c->sockname = sdsnew(sockname);
    }
    return c->sockname;
}

/* Concatenate a string representing the state of a client in a human
 * readable format, into the sds string 's'. */
sds catClientInfoString(sds s, client *client) {
    char flags[16], events[3], conninfo[CONN_INFO_LEN], *p;

    p = flags;
    if (client->flags & CLIENT_SLAVE) {
        if (client->flags & CLIENT_MONITOR)
            *p++ = 'O';
        else
            *p++ = 'S';
    }
    if (client->flags & CLIENT_MASTER) *p++ = 'M';
    if (client->flags & CLIENT_PUBSUB) *p++ = 'P';
    if (client->flags & CLIENT_MULTI) *p++ = 'x';
    if (client->flags & CLIENT_BLOCKED) *p++ = 'b';
    if (client->flags & CLIENT_TRACKING) *p++ = 't';
    if (client->flags & CLIENT_TRACKING_BROKEN_REDIR) *p++ = 'R';
    if (client->flags & CLIENT_TRACKING_BCAST) *p++ = 'B';
    if (client->flags & CLIENT_DIRTY_CAS) *p++ = 'd';
    if (client->flags & CLIENT_CLOSE_AFTER_REPLY) *p++ = 'c';
    if (client->flags & CLIENT_UNBLOCKED) *p++ = 'u';
    if (client->flags & CLIENT_CLOSE_ASAP) *p++ = 'A';
    if (client->flags & CLIENT_UNIX_SOCKET) *p++ = 'U';
    if (client->flags & CLIENT_READONLY) *p++ = 'r';
    if (p == flags) *p++ = 'N';
    *p++ = '\0';

    p = events;
    if (client->conn) {
        if (connHasReadHandler(client->conn)) *p++ = 'r';
        if (connHasWriteHandler(client->conn)) *p++ = 'w';
    }
    *p = '\0';

    /* Compute the total memory consumed by this client. */
    size_t obufmem = getClientOutputBufferMemoryUsage(client);
    size_t total_mem = obufmem;
    total_mem += zmalloc_size(client); /* includes client->buf */
    total_mem += sdsZmallocSize(client->querybuf);
    /* For efficiency (less work keeping track of the argv memory), it doesn't include the used memory
     * i.e. unused sds space and internal fragmentation, just the string length. but this is enough to
     * spot problematic clients. */
    total_mem += client->argv_len_sum;
    if (client->argv)
        total_mem += zmalloc_size(client->argv);

    return sdscatfmt(s,
        "id=%U addr=%s laddr=%s %s name=%s age=%I idle=%I flags=%s db=%i sub=%i psub=%i multi=%i qbuf=%U qbuf-free=%U argv-mem=%U obl=%U oll=%U omem=%U tot-mem=%U events=%s cmd=%s user=%s redir=%I",
        (unsigned long long) client->id,
        getClientPeerId(client),
        getClientSockname(client),
        connGetInfo(client->conn, conninfo, sizeof(conninfo)),
        client->name ? (char*)client->name->ptr : "",
        (long long)(server.unixtime - client->ctime),
        (long long)(server.unixtime - client->lastinteraction),
        flags,
        client->db->id,
        (int) dictSize(client->pubsub_channels),
        (int) listLength(client->pubsub_patterns),
        (client->flags & CLIENT_MULTI) ? client->mstate.count : -1,
        (unsigned long long) sdslen(client->querybuf),
        (unsigned long long) sdsavail(client->querybuf),
        (unsigned long long) client->argv_len_sum,
        (unsigned long long) client->bufpos,
        (unsigned long long) listLength(client->reply),
        (unsigned long long) obufmem, /* should not include client->buf since we want to see 0 for static clients. */
        (unsigned long long) total_mem,
        events,
        client->lastcmd ? client->lastcmd->name : "NULL",
        client->user ? client->user->name : "(superuser)",
        (client->flags & CLIENT_TRACKING) ? (long long) client->client_tracking_redirection : -1);
}

sds getAllClientsInfoString(int type) {
    listNode *ln;
    listIter li;
    client *client;
    sds o = sdsnewlen(SDS_NOINIT,200*listLength(server.clients));
    sdsclear(o);
    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        client = listNodeValue(ln);
        if (type != -1 && getClientType(client) != type) continue;
        o = catClientInfoString(o,client);
        o = sdscatlen(o,"\n",1);
    }
    return o;
}

/* This function implements CLIENT SETNAME, including replying to the
 * user with an error if the charset is wrong (in that case C_ERR is
 * returned). If the function succeeeded C_OK is returned, and it's up
 * to the caller to send a reply if needed.
 *
 * Setting an empty string as name has the effect of unsetting the
 * currently set name: the client will remain unnamed.
 *
 * This function is also used to implement the HELLO SETNAME option. */
int clientSetNameOrReply(client *c, robj *name) {
    int len = sdslen(name->ptr);
    char *p = name->ptr;

    /* Setting the client name to an empty string actually removes
     * the current name. */
    if (len == 0) {
        if (c->name) decrRefCount(c->name);
        c->name = NULL;
        return C_OK;
    }

    /* Otherwise check if the charset is ok. We need to do this otherwise
     * CLIENT LIST format will break. You should always be able to
     * split by space to get the different fields. */
    for (int j = 0; j < len; j++) {
        if (p[j] < '!' || p[j] > '~') { /* ASCII is assumed. */
            addReplyError(c,
                "Client names cannot contain spaces, "
                "newlines or special characters.");
            return C_ERR;
        }
    }
    if (c->name) decrRefCount(c->name);
    c->name = name;
    incrRefCount(name);
    return C_OK;
}

/* Reset the client state to resemble a newly connected client.
 */
void resetCommand(client *c) {
    listNode *ln;

    /* MONITOR clients are also marked with CLIENT_SLAVE, we need to
     * distinguish between the two.
     */
    if (c->flags & CLIENT_MONITOR) {
        ln = listSearchKey(server.monitors,c);
        serverAssert(ln != NULL);
        listDelNode(server.monitors,ln);

        c->flags &= ~(CLIENT_MONITOR|CLIENT_SLAVE);
    }

    if (c->flags & (CLIENT_SLAVE|CLIENT_MASTER|CLIENT_MODULE)) {
        addReplyError(c,"can only reset normal client connections");
        return;
    }

    if (c->flags & CLIENT_TRACKING) disableTracking(c);
    selectDb(c,0);
    c->resp = 2;

    clientSetDefaultAuth(c);
    moduleNotifyUserChanged(c);
    discardTransaction(c);

    pubsubUnsubscribeAllChannels(c,0);
    pubsubUnsubscribeAllPatterns(c,0);

    if (c->name) {
        decrRefCount(c->name);
        c->name = NULL;
    }

    /* Selectively clear state flags not covered above */
    c->flags &= ~(CLIENT_ASKING|CLIENT_READONLY|CLIENT_PUBSUB|
            CLIENT_REPLY_OFF|CLIENT_REPLY_SKIP_NEXT);

    addReplyStatus(c,"RESET");
}

void clientCommand(client *c) {
    listNode *ln;
    listIter li;

    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"CACHING (YES|NO)",
"    Enable/disable tracking of the keys for next command in OPTIN/OPTOUT modes.",
"GETREDIR",
"    Return the client ID we are redirecting to when tracking is enabled.",
"GETNAME",
"    Return the name of the current connection.",
"ID",
"    Return the ID of the current connection.",
"INFO",
"    Return information about the current client connection.",
"KILL <ip:port>",
"    Kill connection made from <ip:port>.",
"KILL <option> <value> [<option> <value> [...]]",
"    Kill connections. Options are:",
"    * ADDR (<ip:port>|<unixsocket>:0)",
"      Kill connections made from the specified address",
"    * LADDR (<ip:port>|<unixsocket>:0)",
"      Kill connections made to specified local address",
"    * TYPE (normal|master|replica|pubsub)",
"      Kill connections by type.",
"    * USER <username>",
"      Kill connections authenticated by <username>.",
"    * SKIPME (YES|NO)",
"      Skip killing current connection (default: yes).",
"LIST [options ...]",
"    Return information about client connections. Options:",
"    * TYPE (NORMAL|MASTER|REPLICA|PUBSUB)",
"      Return clients of specified type.",
"UNPAUSE",
"    Stop the current client pause, resuming traffic.",
"PAUSE <timeout> [WRITE|ALL]",
"    Suspend all, or just write, clients for <timout> milliseconds.",
"REPLY (ON|OFF|SKIP)",
"    Control the replies sent to the current connection.",
"SETNAME <name>",
"    Assign the name <name> to the current connection.",
"UNBLOCK <clientid> [TIMEOUT|ERROR]",
"    Unblock the specified blocked client.",
"TRACKING (ON|OFF) [REDIRECT <id>] [BCAST] [PREFIX <prefix> [...]]",
"         [OPTIN] [OPTOUT]",
"    Control server assisted client side caching.",
"TRACKINGINFO",
"    Report tracking status for the current connection.",
NULL
        };
        addReplyHelp(c, help);
    } else if (!strcasecmp(c->argv[1]->ptr,"id") && c->argc == 2) {
        /* CLIENT ID */
        addReplyLongLong(c,c->id);
    } else if (!strcasecmp(c->argv[1]->ptr,"info") && c->argc == 2) {
        /* CLIENT INFO */
        sds o = catClientInfoString(sdsempty(), c);
        o = sdscatlen(o,"\n",1);
        addReplyVerbatim(c,o,sdslen(o),"txt");
        sdsfree(o);
    } else if (!strcasecmp(c->argv[1]->ptr,"list")) {
        /* CLIENT LIST */
        int type = -1;
        sds o = NULL;
        if (c->argc == 4 && !strcasecmp(c->argv[2]->ptr,"type")) {
            type = getClientTypeByName(c->argv[3]->ptr);
            if (type == -1) {
                addReplyErrorFormat(c,"Unknown client type '%s'",
                    (char*) c->argv[3]->ptr);
                return;
            }
        } else if (c->argc > 3 && !strcasecmp(c->argv[2]->ptr,"id")) {
            int j;
            o = sdsempty();
            for (j = 3; j < c->argc; j++) {
                long long cid;
                if (getLongLongFromObjectOrReply(c, c->argv[j], &cid,
                            "Invalid client ID")) {
                    sdsfree(o);
                    return;
                }
                client *cl = lookupClientByID(cid);
                if (cl) {
                    o = catClientInfoString(o, cl);
                    o = sdscatlen(o, "\n", 1);
                }
            }
        } else if (c->argc != 2) {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }

        if (!o)
            o = getAllClientsInfoString(type);
        addReplyVerbatim(c,o,sdslen(o),"txt");
        sdsfree(o);
    } else if (!strcasecmp(c->argv[1]->ptr,"reply") && c->argc == 3) {
        /* CLIENT REPLY ON|OFF|SKIP */
        if (!strcasecmp(c->argv[2]->ptr,"on")) {
            c->flags &= ~(CLIENT_REPLY_SKIP|CLIENT_REPLY_OFF);
            addReply(c,shared.ok);
        } else if (!strcasecmp(c->argv[2]->ptr,"off")) {
            c->flags |= CLIENT_REPLY_OFF;
        } else if (!strcasecmp(c->argv[2]->ptr,"skip")) {
            if (!(c->flags & CLIENT_REPLY_OFF))
                c->flags |= CLIENT_REPLY_SKIP_NEXT;
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"kill")) {
        /* CLIENT KILL <ip:port>
         * CLIENT KILL <option> [value] ... <option> [value] */
        char *addr = NULL;
        char *laddr = NULL;
        user *user = NULL;
        int type = -1;
        uint64_t id = 0;
        int skipme = 1;
        int killed = 0, close_this_client = 0;

        if (c->argc == 3) {
            /* Old style syntax: CLIENT KILL <addr> */
            addr = c->argv[2]->ptr;
            skipme = 0; /* With the old form, you can kill yourself. */
        } else if (c->argc > 3) {
            int i = 2; /* Next option index. */

            /* New style syntax: parse options. */
            while(i < c->argc) {
                int moreargs = c->argc > i+1;

                if (!strcasecmp(c->argv[i]->ptr,"id") && moreargs) {
                    long long tmp;

                    if (getLongLongFromObjectOrReply(c,c->argv[i+1],&tmp,NULL)
                        != C_OK) return;
                    id = tmp;
                } else if (!strcasecmp(c->argv[i]->ptr,"type") && moreargs) {
                    type = getClientTypeByName(c->argv[i+1]->ptr);
                    if (type == -1) {
                        addReplyErrorFormat(c,"Unknown client type '%s'",
                            (char*) c->argv[i+1]->ptr);
                        return;
                    }
                } else if (!strcasecmp(c->argv[i]->ptr,"addr") && moreargs) {
                    addr = c->argv[i+1]->ptr;
                } else if (!strcasecmp(c->argv[i]->ptr,"laddr") && moreargs) {
                    laddr = c->argv[i+1]->ptr;
                } else if (!strcasecmp(c->argv[i]->ptr,"user") && moreargs) {
                    user = ACLGetUserByName(c->argv[i+1]->ptr,
                                            sdslen(c->argv[i+1]->ptr));
                    if (user == NULL) {
                        addReplyErrorFormat(c,"No such user '%s'",
                            (char*) c->argv[i+1]->ptr);
                        return;
                    }
                } else if (!strcasecmp(c->argv[i]->ptr,"skipme") && moreargs) {
                    if (!strcasecmp(c->argv[i+1]->ptr,"yes")) {
                        skipme = 1;
                    } else if (!strcasecmp(c->argv[i+1]->ptr,"no")) {
                        skipme = 0;
                    } else {
                        addReplyErrorObject(c,shared.syntaxerr);
                        return;
                    }
                } else {
                    addReplyErrorObject(c,shared.syntaxerr);
                    return;
                }
                i += 2;
            }
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }

        /* Iterate clients killing all the matching clients. */
        listRewind(server.clients,&li);
        while ((ln = listNext(&li)) != NULL) {
            client *client = listNodeValue(ln);
            if (addr && strcmp(getClientPeerId(client),addr) != 0) continue;
            if (laddr && strcmp(getClientSockname(client),laddr) != 0) continue;
            if (type != -1 && getClientType(client) != type) continue;
            if (id != 0 && client->id != id) continue;
            if (user && client->user != user) continue;
            if (c == client && skipme) continue;

            /* Kill it. */
            if (c == client) {
                close_this_client = 1;
            } else {
                freeClient(client);
            }
            killed++;
        }

        /* Reply according to old/new format. */
        if (c->argc == 3) {
            if (killed == 0)
                addReplyError(c,"No such client");
            else
                addReply(c,shared.ok);
        } else {
            addReplyLongLong(c,killed);
        }

        /* If this client has to be closed, flag it as CLOSE_AFTER_REPLY
         * only after we queued the reply to its output buffers. */
        if (close_this_client) c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    } else if (!strcasecmp(c->argv[1]->ptr,"unblock") && (c->argc == 3 ||
                                                          c->argc == 4))
    {
        /* CLIENT UNBLOCK <id> [timeout|error] */
        long long id;
        int unblock_error = 0;

        if (c->argc == 4) {
            if (!strcasecmp(c->argv[3]->ptr,"timeout")) {
                unblock_error = 0;
            } else if (!strcasecmp(c->argv[3]->ptr,"error")) {
                unblock_error = 1;
            } else {
                addReplyError(c,
                    "CLIENT UNBLOCK reason should be TIMEOUT or ERROR");
                return;
            }
        }
        if (getLongLongFromObjectOrReply(c,c->argv[2],&id,NULL)
            != C_OK) return;
        struct client *target = lookupClientByID(id);
        if (target && target->flags & CLIENT_BLOCKED) {
            if (unblock_error)
                addReplyError(target,
                    "-UNBLOCKED client unblocked via CLIENT UNBLOCK");
            else
                replyToBlockedClientTimedOut(target);
            unblockClient(target);
            addReply(c,shared.cone);
        } else {
            addReply(c,shared.czero);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"setname") && c->argc == 3) {
        /* CLIENT SETNAME */
        if (clientSetNameOrReply(c,c->argv[2]) == C_OK)
            addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"getname") && c->argc == 2) {
        /* CLIENT GETNAME */
        if (c->name)
            addReplyBulk(c,c->name);
        else
            addReplyNull(c);
    } else if (!strcasecmp(c->argv[1]->ptr,"unpause") && c->argc == 2) {
        /* CLIENT UNPAUSE */
        unpauseClients();
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"pause") && (c->argc == 3 ||
                                                        c->argc == 4))
    {
        /* CLIENT PAUSE TIMEOUT [WRITE|ALL] */
        mstime_t end;
        int type = CLIENT_PAUSE_ALL;
        if (c->argc == 4) {
            if (!strcasecmp(c->argv[3]->ptr,"write")) {
                type = CLIENT_PAUSE_WRITE;
            } else if (!strcasecmp(c->argv[3]->ptr,"all")) {
                type = CLIENT_PAUSE_ALL;
            } else {
                addReplyError(c,
                    "CLIENT PAUSE mode must be WRITE or ALL");  
                return;       
            }
        }

        if (getTimeoutFromObjectOrReply(c,c->argv[2],&end,
            UNIT_MILLISECONDS) != C_OK) return;
        pauseClients(end, type);
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"tracking") && c->argc >= 3) {
        /* CLIENT TRACKING (on|off) [REDIRECT <id>] [BCAST] [PREFIX first]
         *                          [PREFIX second] [OPTIN] [OPTOUT] ... */
        long long redir = 0;
        uint64_t options = 0;
        robj **prefix = NULL;
        size_t numprefix = 0;

        /* Parse the options. */
        for (int j = 3; j < c->argc; j++) {
            int moreargs = (c->argc-1) - j;

            if (!strcasecmp(c->argv[j]->ptr,"redirect") && moreargs) {
                j++;
                if (redir != 0) {
                    addReplyError(c,"A client can only redirect to a single "
                                    "other client");
                    zfree(prefix);
                    return;
                }

                if (getLongLongFromObjectOrReply(c,c->argv[j],&redir,NULL) !=
                    C_OK)
                {
                    zfree(prefix);
                    return;
                }
                /* We will require the client with the specified ID to exist
                 * right now, even if it is possible that it gets disconnected
                 * later. Still a valid sanity check. */
                if (lookupClientByID(redir) == NULL) {
                    addReplyError(c,"The client ID you want redirect to "
                                    "does not exist");
                    zfree(prefix);
                    return;
                }
            } else if (!strcasecmp(c->argv[j]->ptr,"bcast")) {
                options |= CLIENT_TRACKING_BCAST;
            } else if (!strcasecmp(c->argv[j]->ptr,"optin")) {
                options |= CLIENT_TRACKING_OPTIN;
            } else if (!strcasecmp(c->argv[j]->ptr,"optout")) {
                options |= CLIENT_TRACKING_OPTOUT;
            } else if (!strcasecmp(c->argv[j]->ptr,"noloop")) {
                options |= CLIENT_TRACKING_NOLOOP;
            } else if (!strcasecmp(c->argv[j]->ptr,"prefix") && moreargs) {
                j++;
                prefix = zrealloc(prefix,sizeof(robj*)*(numprefix+1));
                prefix[numprefix++] = c->argv[j];
            } else {
                zfree(prefix);
                addReplyErrorObject(c,shared.syntaxerr);
                return;
            }
        }

        /* Options are ok: enable or disable the tracking for this client. */
        if (!strcasecmp(c->argv[2]->ptr,"on")) {
            /* Before enabling tracking, make sure options are compatible
             * among each other and with the current state of the client. */
            if (!(options & CLIENT_TRACKING_BCAST) && numprefix) {
                addReplyError(c,
                    "PREFIX option requires BCAST mode to be enabled");
                zfree(prefix);
                return;
            }

            if (c->flags & CLIENT_TRACKING) {
                int oldbcast = !!(c->flags & CLIENT_TRACKING_BCAST);
                int newbcast = !!(options & CLIENT_TRACKING_BCAST);
                if (oldbcast != newbcast) {
                    addReplyError(c,
                    "You can't switch BCAST mode on/off before disabling "
                    "tracking for this client, and then re-enabling it with "
                    "a different mode.");
                    zfree(prefix);
                    return;
                }
            }

            if (options & CLIENT_TRACKING_BCAST &&
                options & (CLIENT_TRACKING_OPTIN|CLIENT_TRACKING_OPTOUT))
            {
                addReplyError(c,
                "OPTIN and OPTOUT are not compatible with BCAST");
                zfree(prefix);
                return;
            }

            if (options & CLIENT_TRACKING_OPTIN && options & CLIENT_TRACKING_OPTOUT)
            {
                addReplyError(c,
                "You can't specify both OPTIN mode and OPTOUT mode");
                zfree(prefix);
                return;
            }

            if ((options & CLIENT_TRACKING_OPTIN && c->flags & CLIENT_TRACKING_OPTOUT) ||
                (options & CLIENT_TRACKING_OPTOUT && c->flags & CLIENT_TRACKING_OPTIN))
            {
                addReplyError(c,
                "You can't switch OPTIN/OPTOUT mode before disabling "
                "tracking for this client, and then re-enabling it with "
                "a different mode.");
                zfree(prefix);
                return;
            }

            if (options & CLIENT_TRACKING_BCAST) {
                if (!checkPrefixCollisionsOrReply(c,prefix,numprefix)) {
                    zfree(prefix);
                    return;
                }
            }

            enableTracking(c,redir,options,prefix,numprefix);
        } else if (!strcasecmp(c->argv[2]->ptr,"off")) {
            disableTracking(c);
        } else {
            zfree(prefix);
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }
        zfree(prefix);
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"caching") && c->argc >= 3) {
        if (!(c->flags & CLIENT_TRACKING)) {
            addReplyError(c,"CLIENT CACHING can be called only when the "
                            "client is in tracking mode with OPTIN or "
                            "OPTOUT mode enabled");
            return;
        }

        char *opt = c->argv[2]->ptr;
        if (!strcasecmp(opt,"yes")) {
            if (c->flags & CLIENT_TRACKING_OPTIN) {
                c->flags |= CLIENT_TRACKING_CACHING;
            } else {
                addReplyError(c,"CLIENT CACHING YES is only valid when tracking is enabled in OPTIN mode.");
                return;
            }
        } else if (!strcasecmp(opt,"no")) {
            if (c->flags & CLIENT_TRACKING_OPTOUT) {
                c->flags |= CLIENT_TRACKING_CACHING;
            } else {
                addReplyError(c,"CLIENT CACHING NO is only valid when tracking is enabled in OPTOUT mode.");
                return;
            }
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }

        /* Common reply for when we succeeded. */
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"getredir") && c->argc == 2) {
        /* CLIENT GETREDIR */
        if (c->flags & CLIENT_TRACKING) {
            addReplyLongLong(c,c->client_tracking_redirection);
        } else {
            addReplyLongLong(c,-1);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"trackinginfo") && c->argc == 2) {
        addReplyMapLen(c,3);

        /* Flags */
        addReplyBulkCString(c,"flags");
        void *arraylen_ptr = addReplyDeferredLen(c);
        int numflags = 0;
        addReplyBulkCString(c,c->flags & CLIENT_TRACKING ? "on" : "off");
        numflags++;
        if (c->flags & CLIENT_TRACKING_BCAST) {
            addReplyBulkCString(c,"bcast");
            numflags++;
        }
        if (c->flags & CLIENT_TRACKING_OPTIN) {
            addReplyBulkCString(c,"optin");
            numflags++;
            if (c->flags & CLIENT_TRACKING_CACHING) {
                addReplyBulkCString(c,"caching-yes");
                numflags++;        
            }
        }
        if (c->flags & CLIENT_TRACKING_OPTOUT) {
            addReplyBulkCString(c,"optout");
            numflags++;
            if (c->flags & CLIENT_TRACKING_CACHING) {
                addReplyBulkCString(c,"caching-no");
                numflags++;        
            }
        }
        if (c->flags & CLIENT_TRACKING_NOLOOP) {
            addReplyBulkCString(c,"noloop");
            numflags++;
        }
        if (c->flags & CLIENT_TRACKING_BROKEN_REDIR) {
            addReplyBulkCString(c,"broken_redirect");
            numflags++;
        }
        setDeferredSetLen(c,arraylen_ptr,numflags);

        /* Redirect */
        addReplyBulkCString(c,"redirect");
        if (c->flags & CLIENT_TRACKING) {
            addReplyLongLong(c,c->client_tracking_redirection);
        } else {
            addReplyLongLong(c,-1);
        }

        /* Prefixes */
        addReplyBulkCString(c,"prefixes");
        if (c->client_tracking_prefixes) {
            addReplyArrayLen(c,raxSize(c->client_tracking_prefixes));
            raxIterator ri;
            raxStart(&ri,c->client_tracking_prefixes);
            raxSeek(&ri,"^",NULL,0);
            while(raxNext(&ri)) {
                addReplyBulkCBuffer(c,ri.key,ri.key_len);
            }
            raxStop(&ri);
        } else {
            addReplyArrayLen(c,0);
        }
    } else {
        addReplySubcommandSyntaxError(c);
    }
}

/* HELLO [<protocol-version> [AUTH <user> <password>] [SETNAME <name>] ] */
void helloCommand(client *c) {
    long long ver = 0;
    int next_arg = 1;

    if (c->argc >= 2) {
        if (getLongLongFromObjectOrReply(c, c->argv[next_arg++], &ver,
            "Protocol version is not an integer or out of range") != C_OK) {
            return;
        }

        if (ver < 2 || ver > 3) {
            addReplyError(c,"-NOPROTO unsupported protocol version");
            return;
        }
    }

    for (int j = next_arg; j < c->argc; j++) {
        int moreargs = (c->argc-1) - j;
        const char *opt = c->argv[j]->ptr;
        if (!strcasecmp(opt,"AUTH") && moreargs >= 2) {
            if (ACLAuthenticateUser(c, c->argv[j+1], c->argv[j+2]) == C_ERR) {
                addReplyError(c,"-WRONGPASS invalid username-password pair or user is disabled.");
                return;
            }
            j += 2;
        } else if (!strcasecmp(opt,"SETNAME") && moreargs) {
            if (clientSetNameOrReply(c, c->argv[j+1]) == C_ERR) return;
            j++;
        } else {
            addReplyErrorFormat(c,"Syntax error in HELLO option '%s'",opt);
            return;
        }
    }

    /* At this point we need to be authenticated to continue. */
    if (!c->authenticated) {
        addReplyError(c,"-NOAUTH HELLO must be called with the client already "
                        "authenticated, otherwise the HELLO AUTH <user> <pass> "
                        "option can be used to authenticate the client and "
                        "select the RESP protocol version at the same time");
        return;
    }

    /* Let's switch to the specified RESP mode. */
    if (ver) c->resp = ver;
    addReplyMapLen(c,6 + !server.sentinel_mode);

    addReplyBulkCString(c,"server");
    addReplyBulkCString(c,"redis");

    addReplyBulkCString(c,"version");
    addReplyBulkCString(c,REDIS_VERSION);

    addReplyBulkCString(c,"proto");
    addReplyLongLong(c,c->resp);

    addReplyBulkCString(c,"id");
    addReplyLongLong(c,c->id);

    addReplyBulkCString(c,"mode");
    if (server.sentinel_mode) addReplyBulkCString(c,"sentinel");
    else if (server.cluster_enabled) addReplyBulkCString(c,"cluster");
    else addReplyBulkCString(c,"standalone");

    if (!server.sentinel_mode) {
        addReplyBulkCString(c,"role");
        addReplyBulkCString(c,server.masterhost ? "replica" : "master");
    }

    addReplyBulkCString(c,"modules");
    addReplyLoadedModules(c);
}

/* This callback is bound to POST and "Host:" command names. Those are not
 * really commands, but are used in security attacks in order to talk to
 * Redis instances via HTTP, with a technique called "cross protocol scripting"
 * which exploits the fact that services like Redis will discard invalid
 * HTTP headers and will process what follows.
 *
 * As a protection against this attack, Redis will terminate the connection
 * when a POST or "Host:" header is seen, and will log the event from
 * time to time (to avoid creating a DOS as a result of too many logs). */
void securityWarningCommand(client *c) {
    static time_t logged_time;
    time_t now = time(NULL);

    if (labs(now-logged_time) > 60) {
        serverLog(LL_WARNING,"Possible SECURITY ATTACK detected. It looks like somebody is sending POST or Host: commands to Redis. This is likely due to an attacker attempting to use Cross Protocol Scripting to compromise your Redis instance. Connection aborted.");
        logged_time = now;
    }
    freeClientAsync(c);
}

/* Keep track of the original command arguments so that we can generate
 * an accurate slowlog entry after the command has been executed. */
static void retainOriginalCommandVector(client *c) {
    /* We already rewrote this command, so don't rewrite it again */
    if (c->original_argv) return;
    c->original_argc = c->argc;
    c->original_argv = zmalloc(sizeof(robj*)*(c->argc));
    for (int j = 0; j < c->argc; j++) {
        c->original_argv[j] = c->argv[j];
        incrRefCount(c->argv[j]);
    }
}

/* Rewrite the command vector of the client. All the new objects ref count
 * is incremented. The old command vector is freed, and the old objects
 * ref count is decremented. */
void rewriteClientCommandVector(client *c, int argc, ...) {
    va_list ap;
    int j;
    robj **argv; /* The new argument vector */

    argv = zmalloc(sizeof(robj*)*argc);
    va_start(ap,argc);
    for (j = 0; j < argc; j++) {
        robj *a;

        a = va_arg(ap, robj*);
        argv[j] = a;
        incrRefCount(a);
    }
    replaceClientCommandVector(c, argc, argv);
    va_end(ap);
}

/* Completely replace the client command vector with the provided one. */
void replaceClientCommandVector(client *c, int argc, robj **argv) {
    int j;
    retainOriginalCommandVector(c);
    freeClientArgv(c);
    zfree(c->argv);
    c->argv = argv;
    c->argc = argc;
    c->argv_len_sum = 0;
    for (j = 0; j < c->argc; j++)
        if (c->argv[j])
            c->argv_len_sum += getStringObjectLen(c->argv[j]);
    c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
    serverAssertWithInfo(c,NULL,c->cmd != NULL);
}

/* Rewrite a single item in the command vector.
 * The new val ref count is incremented, and the old decremented.
 *
 * It is possible to specify an argument over the current size of the
 * argument vector: in this case the array of objects gets reallocated
 * and c->argc set to the max value. However it's up to the caller to
 *
 * 1. Make sure there are no "holes" and all the arguments are set.
 * 2. If the original argument vector was longer than the one we
 *    want to end with, it's up to the caller to set c->argc and
 *    free the no longer used objects on c->argv. */
void rewriteClientCommandArgument(client *c, int i, robj *newval) {
    robj *oldval;
    retainOriginalCommandVector(c);
    if (i >= c->argc) {
        c->argv = zrealloc(c->argv,sizeof(robj*)*(i+1));
        c->argc = i+1;
        c->argv[i] = NULL;
    }
    oldval = c->argv[i];
    if (oldval) c->argv_len_sum -= getStringObjectLen(oldval);
    if (newval) c->argv_len_sum += getStringObjectLen(newval);
    c->argv[i] = newval;
    incrRefCount(newval);
    if (oldval) decrRefCount(oldval);

    /* If this is the command name make sure to fix c->cmd. */
    if (i == 0) {
        c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
        serverAssertWithInfo(c,NULL,c->cmd != NULL);
    }
}

/* This function returns the number of bytes that Redis is
 * using to store the reply still not read by the client.
 *
 * Note: this function is very fast so can be called as many time as
 * the caller wishes. The main usage of this function currently is
 * enforcing the client output length limits. */
unsigned long getClientOutputBufferMemoryUsage(client *c) {
    unsigned long list_item_size = sizeof(listNode) + sizeof(clientReplyBlock);
    return c->reply_bytes + (list_item_size*listLength(c->reply));
}

/* Get the class of a client, used in order to enforce limits to different
 * classes of clients.
 *
 * The function will return one of the following:
 * CLIENT_TYPE_NORMAL -> Normal client
 * CLIENT_TYPE_SLAVE  -> Slave
 * CLIENT_TYPE_PUBSUB -> Client subscribed to Pub/Sub channels
 * CLIENT_TYPE_MASTER -> The client representing our replication master.
 */
int getClientType(client *c) {
    if (c->flags & CLIENT_MASTER) return CLIENT_TYPE_MASTER;
    /* Even though MONITOR clients are marked as replicas, we
     * want the expose them as normal clients. */
    if ((c->flags & CLIENT_SLAVE) && !(c->flags & CLIENT_MONITOR))
        return CLIENT_TYPE_SLAVE;
    if (c->flags & CLIENT_PUBSUB) return CLIENT_TYPE_PUBSUB;
    return CLIENT_TYPE_NORMAL;
}

int getClientTypeByName(char *name) {
    if (!strcasecmp(name,"normal")) return CLIENT_TYPE_NORMAL;
    else if (!strcasecmp(name,"slave")) return CLIENT_TYPE_SLAVE;
    else if (!strcasecmp(name,"replica")) return CLIENT_TYPE_SLAVE;
    else if (!strcasecmp(name,"pubsub")) return CLIENT_TYPE_PUBSUB;
    else if (!strcasecmp(name,"master")) return CLIENT_TYPE_MASTER;
    else return -1;
}

char *getClientTypeName(int class) {
    switch(class) {
    case CLIENT_TYPE_NORMAL: return "normal";
    case CLIENT_TYPE_SLAVE:  return "slave";
    case CLIENT_TYPE_PUBSUB: return "pubsub";
    case CLIENT_TYPE_MASTER: return "master";
    default:                       return NULL;
    }
}

/* The function checks if the client reached output buffer soft or hard
 * limit, and also update the state needed to check the soft limit as
 * a side effect.
 *
 * Return value: non-zero if the client reached the soft or the hard limit.
 *               Otherwise zero is returned. */
int checkClientOutputBufferLimits(client *c) {
    int soft = 0, hard = 0, class;
    unsigned long used_mem = getClientOutputBufferMemoryUsage(c);

    class = getClientType(c);
    /* For the purpose of output buffer limiting, masters are handled
     * like normal clients. */
    if (class == CLIENT_TYPE_MASTER) class = CLIENT_TYPE_NORMAL;

    if (server.client_obuf_limits[class].hard_limit_bytes &&
        used_mem >= server.client_obuf_limits[class].hard_limit_bytes)
        hard = 1;
    if (server.client_obuf_limits[class].soft_limit_bytes &&
        used_mem >= server.client_obuf_limits[class].soft_limit_bytes)
        soft = 1;

    /* We need to check if the soft limit is reached continuously for the
     * specified amount of seconds. */
    if (soft) {
        if (c->obuf_soft_limit_reached_time == 0) {
            c->obuf_soft_limit_reached_time = server.unixtime;
            soft = 0; /* First time we see the soft limit reached */
        } else {
            time_t elapsed = server.unixtime - c->obuf_soft_limit_reached_time;

            if (elapsed <=
                server.client_obuf_limits[class].soft_limit_seconds) {
                soft = 0; /* The client still did not reached the max number of
                             seconds for the soft limit to be considered
                             reached. */
            }
        }
    } else {
        c->obuf_soft_limit_reached_time = 0;
    }
    return soft || hard;
}

/* Asynchronously close a client if soft or hard limit is reached on the
 * output buffer size. The caller can check if the client will be closed
 * checking if the client CLIENT_CLOSE_ASAP flag is set.
 *
 * Note: we need to close the client asynchronously because this function is
 * called from contexts where the client can't be freed safely, i.e. from the
 * lower level functions pushing data inside the client output buffers. */
void asyncCloseClientOnOutputBufferLimitReached(client *c) {
    if (!c->conn) return; /* It is unsafe to free fake clients. */
    serverAssert(c->reply_bytes < SIZE_MAX-(1024*64));
    if (c->reply_bytes == 0 || c->flags & CLIENT_CLOSE_ASAP) return;
    if (checkClientOutputBufferLimits(c)) {
        sds client = catClientInfoString(sdsempty(),c);

        freeClientAsync(c);
        serverLog(LL_WARNING,"Client %s scheduled to be closed ASAP for overcoming of output buffer limits.", client);
        sdsfree(client);
    }
}

/* Helper function used by performEvictions() in order to flush slaves
 * output buffers without returning control to the event loop.
 * This is also called by SHUTDOWN for a best-effort attempt to send
 * slaves the latest writes. */
void flushSlavesOutputBuffers(void) {
    listIter li;
    listNode *ln;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = listNodeValue(ln);
        int can_receive_writes = connHasWriteHandler(slave->conn) ||
                                 (slave->flags & CLIENT_PENDING_WRITE);

        /* We don't want to send the pending data to the replica in a few
         * cases:
         *
         * 1. For some reason there is neither the write handler installed
         *    nor the client is flagged as to have pending writes: for some
         *    reason this replica may not be set to receive data. This is
         *    just for the sake of defensive programming.
         *
         * 2. The put_online_on_ack flag is true. To know why we don't want
         *    to send data to the replica in this case, please grep for the
         *    flag for this flag.
         *
         * 3. Obviously if the slave is not ONLINE.
         */
        if (slave->replstate == SLAVE_STATE_ONLINE &&
            can_receive_writes &&
            !slave->repl_put_online_on_ack &&
            clientHasPendingReplies(slave))
        {
            writeToClient(slave,0);
        }
    }
}

/* Pause clients up to the specified unixtime (in ms) for a given type of
 * commands.
 *
 * A main use case of this function is to allow pausing replication traffic
 * so that a failover without data loss to occur. Replicas will continue to receive
 * traffic to faciliate this functionality.
 * 
 * This function is also internally used by Redis Cluster for the manual
 * failover procedure implemented by CLUSTER FAILOVER.
 *
 * The function always succeed, even if there is already a pause in progress.
 * In such a case, the duration is set to the maximum and new end time and the
 * type is set to the more restrictive type of pause. */
void pauseClients(mstime_t end, pause_type type) {
    if (type > server.client_pause_type) {
        server.client_pause_type = type;
    }

    if (end > server.client_pause_end_time) {
        server.client_pause_end_time = end;
    }

    /* We allow write commands that were queued
     * up before and after to execute. We need
     * to track this state so that we don't assert
     * in propagate(). */
    if (server.in_exec) {
        server.client_pause_in_transaction = 1;
    }
}

/* Unpause clients and queue them for reprocessing. */
void unpauseClients(void) {
    listNode *ln;
    listIter li;
    client *c;
    
    server.client_pause_type = CLIENT_PAUSE_OFF;

    /* Unblock all of the clients so they are reprocessed. */
    listRewind(server.paused_clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        c = listNodeValue(ln);
        unblockClient(c);
    }
}

/* Returns true if clients are paused and false otherwise. */ 
int areClientsPaused(void) {
    return server.client_pause_type != CLIENT_PAUSE_OFF;
}

/* Checks if the current client pause has elapsed and unpause clients
 * if it has. Also returns true if clients are now paused and false 
 * otherwise. */
int checkClientPauseTimeoutAndReturnIfPaused(void) {
    if (server.client_pause_end_time < server.mstime) {
        unpauseClients();
    }
    return areClientsPaused();
}

/* This function is called by Redis in order to process a few events from
 * time to time while blocked into some not interruptible operation.
 * 
 * 当某些事件偶尔被阻塞在一些不可中断的操作中时，Redis 调用这个函数来处理这些事件。
 * 
 * This allows to reply to clients with the -LOADING error while loading the
 * data set at startup or after a full resynchronization with the master
 * and so forth.
 *
 * It calls the event loop in order to process a few events. Specifically we
 * try to call the event loop 4 times as long as we receive acknowledge that
 * some event was processed, in order to go forward with the accept, read,
 * write, close sequence needed to serve a client.
 *
 * The function returns the total number of events processed. */
void processEventsWhileBlocked(void) {
    int iterations = 4; /* See the function top-comment. */

    /* Update our cached time since it is used to create and update the last
     * interaction time with clients and for other important things. */
    updateCachedTime(0);

    /* Note: when we are processing events while blocked (for instance during
     * busy Lua scripts), we set a global flag. When such flag is set, we
     * avoid handling the read part of clients using threaded I/O.
     * See https://github.com/antirez/redis/issues/6988 for more info. 
     * 
     * 注意:当在阻塞的时候处理事件时，将全局变量 ProcessingEventsWhileBlocked 的
     * 设置为 1，此时不能使用 IO 线程来处理客户端的读操作
     * */
    ProcessingEventsWhileBlocked = 1;
    while (iterations--) {
        long long startval = server.events_processed_while_blocked;
        long long ae_events = aeProcessEvents(server.el,
            AE_FILE_EVENTS|AE_DONT_WAIT|
            AE_CALL_BEFORE_SLEEP|AE_CALL_AFTER_SLEEP);
        /* Note that server.events_processed_while_blocked will also get
         * incremeted by callbacks called by the event loop handlers. */
        server.events_processed_while_blocked += ae_events;
        long long events = server.events_processed_while_blocked - startval;
        if (!events) break;
    }

    whileBlockedCron();

    ProcessingEventsWhileBlocked = 0;
}

/* ==========================================================================
 * Threaded I/O
 * ========================================================================== */

#define IO_THREADS_MAX_NUM 128
#define IO_THREADS_OP_READ 0
#define IO_THREADS_OP_WRITE 1

pthread_t io_threads[IO_THREADS_MAX_NUM];
pthread_mutex_t io_threads_mutex[IO_THREADS_MAX_NUM];
// 保存 IO 线程对应的任务
redisAtomic unsigned long io_threads_pending[IO_THREADS_MAX_NUM];
int io_threads_op;      /* IO_THREADS_OP_WRITE or IO_THREADS_OP_READ. */

/* This is the list of clients each thread will serve when threaded I/O is
 * used. We spawn io_threads_num-1 threads, since one is the main thread
 * itself. 
 * 
 * 当 IO 线程被使用的时候，该列表数组用于保存每个 IO 线程要处理的客户端。
 * 数组大小为 IO_THREADS_MAX_NUM=128
 * 其中用于处理客户端的线程数为 io_threads_num，有一个是主线程自己，
 * 其余 io_threads_num - 1 个线程是 Redis 生成的
 * */
list *io_threads_list[IO_THREADS_MAX_NUM];

static inline unsigned long getIOPendingCount(int i) {
    unsigned long count = 0;
    // 原子获取 IO 线程任务
    atomicGetWithSync(io_threads_pending[i], count);
    return count;
}

static inline void setIOPendingCount(int i, unsigned long count) {
    // 原子设置 IO 线程的任务
    atomicSetWithSync(io_threads_pending[i], count);
}
/**
 * I/O 线程主函数
 */
void *IOThreadMain(void *myid) {
    /* The ID is the thread number (from 0 to server.iothreads_num-1), and is
     * used by the thread to just manipulate a single sub-array of clients. */
    /**
     * ID 是线程编号，从 0 到 server.iothreads_num-1
     * ID 被使用来获取线程对应的客户端列表
     */
    long id = (unsigned long)myid;
    char thdname[16];

    snprintf(thdname, sizeof(thdname), "io_thd_%ld", id);
    // 设置 I/O 线程标题
    redis_set_thread_title(thdname);
    redisSetCpuAffinity(server.server_cpulist);
    // 确保 I/O 线程随时可以被杀掉
    makeThreadKillable();

    while(1) {
        /* Wait for start 
         * 进行 100W 次忙轮询，判断是否有任务
         */
        for (int j = 0; j < 1000000; j++) {
            if (getIOPendingCount(id) != 0) break;
        }

        /* Give the main thread a chance to stop this thread. 
         * 如果进行 100W 次忙轮询后，线程还是没有任务，
         * 则执行一次加锁和释放锁操作，
         * 这样做的目的是给主线程一次停止本线程的机会
         */
        if (getIOPendingCount(id) == 0) {
            pthread_mutex_lock(&io_threads_mutex[id]);
            pthread_mutex_unlock(&io_threads_mutex[id]);
            continue;
        }

        serverAssert(getIOPendingCount(id) != 0);

        /* Process: note that the main thread will never touch our list
         * before we drop the pending count to 0. */
        listIter li;
        listNode *ln;
        listRewind(io_threads_list[id],&li);
        while((ln = listNext(&li))) {
            client *c = listNodeValue(ln);
            // 如果 IO 线程的操作被设置为 WRITE,则执行客户端写
            if (io_threads_op == IO_THREADS_OP_WRITE) {
                writeToClient(c,0);
            // 如果 IO 线程的操作被设置为 READ,则执行客户端读
            } else if (io_threads_op == IO_THREADS_OP_READ) {
                readQueryFromClient(c->conn);
            } else {
                serverPanic("io_threads_op value is unknown");
            }
        }
        listEmpty(io_threads_list[id]);
        setIOPendingCount(id, 0);
    }
}

/* Initialize the data structures needed for threaded I/O.
 * 初始化 I/O 线程
 */
void initThreadedIO(void) {
    // 默认不启用 I/O 线程
    server.io_threads_active = 0; /* We start with threads not active. */

    /* Don't spawn any thread if the user selected a single thread:
     * we'll handle I/O directly from the main thread. 
     * 如果使用单线程，则不需要创建任何线程
     * 将直接使用主线程处理 I/O
     */
    if (server.io_threads_num == 1) return;

    // I/O 线程数量最多不能超过 IO_THREADS_MAX_NUM=128
    if (server.io_threads_num > IO_THREADS_MAX_NUM) {
        serverLog(LL_WARNING,"Fatal: too many I/O threads configured. "
                             "The maximum number is %d.", IO_THREADS_MAX_NUM);
        exit(1);
    }

    /* Spawn and initialize the I/O threads. 
     * 
     * 创建 I/O 线程，并初始化线程列表
     */
    for (int i = 0; i < server.io_threads_num; i++) {
        /* Things we do for all the threads including the main thread. */
        /* 创建 I/O 线程和主线程的任务列表*/
        io_threads_list[i] = listCreate();
        // 0 代表主线程
        if (i == 0) continue; /* Thread 0 is the main thread. */

        /* Things we do only for the additional threads.
         * 创建 I/O 线程
         */
        pthread_t tid;
        // 创建互斥锁
        pthread_mutex_init(&io_threads_mutex[i],NULL);
        // 初始化 I/O 线程的任务个数为 0，表示当前 I/O 线程无任务
        setIOPendingCount(i, 0);
        // 加锁，如果互斥锁已经被另外一个线程锁定或拥有，则当前线程将被阻塞，
        // 直到互斥锁变得可用为止
        pthread_mutex_lock(&io_threads_mutex[i]); /* Thread will be stopped. */
        // 创建 I/O 线程，并启动 IOThreadMain 方法。
        if (pthread_create(&tid,NULL,IOThreadMain,(void*)(long)i) != 0) {
            serverLog(LL_WARNING,"Fatal: Can't initialize IO thread.");
            exit(1);
        }
        io_threads[i] = tid;
    }
}

void killIOThreads(void) {
    int err, j;
    for (j = 0; j < server.io_threads_num; j++) {
        if (io_threads[j] == pthread_self()) continue;
        if (io_threads[j] && pthread_cancel(io_threads[j]) == 0) {
            if ((err = pthread_join(io_threads[j],NULL)) != 0) {
                serverLog(LL_WARNING,
                    "IO thread(tid:%lu) can not be joined: %s",
                        (unsigned long)io_threads[j], strerror(err));
            } else {
                serverLog(LL_WARNING,
                    "IO thread(tid:%lu) terminated",(unsigned long)io_threads[j]);
            }
        }
    }
}

void startThreadedIO(void) {
    serverAssert(server.io_threads_active == 0);
    for (int j = 1; j < server.io_threads_num; j++)
        pthread_mutex_unlock(&io_threads_mutex[j]);
    server.io_threads_active = 1;
}

void stopThreadedIO(void) {
    /* We may have still clients with pending reads when this function
     * is called: handle them before stopping the threads. */
    handleClientsWithPendingReadsUsingThreads();
    serverAssert(server.io_threads_active == 1);
    for (int j = 1; j < server.io_threads_num; j++)
        pthread_mutex_lock(&io_threads_mutex[j]);
    server.io_threads_active = 0;
}

/* This function checks if there are not enough pending clients to justify
 * taking the I/O threads active: in that case I/O threads are stopped if
 * currently active. We track the pending writes as a measure of clients
 * we need to handle in parallel, however the I/O threading is disabled
 * globally for reads as well if we have too little pending clients.
 *
 * The function returns 0 if the I/O threading should be used because there
 * are enough active threads, otherwise 1 is returned and the I/O threads
 * could be possibly stopped (if already active) as a side effect. 
 * 
 * 判断是否需要停止 I/O 线程
 * 需要则返回 1 
 * 不需要则返回 0
 * */
int stopThreadedIOIfNeeded(void) {
    int pending = listLength(server.clients_pending_write);

    /* Return ASAP if IO threads are disabled (single threaded mode). */
    if (server.io_threads_num == 1) return 1;

    if (pending < (server.io_threads_num*2)) {
        if (server.io_threads_active) stopThreadedIO();
        return 1;
    } else {
        return 0;
    }
}
/**
 * 处理挂起的写客户端列表
 */
int handleClientsWithPendingWritesUsingThreads(void) {
    int processed = listLength(server.clients_pending_write);
    // 没有要处理的客户端，立即返回
    if (processed == 0) return 0; /* Return ASAP if there are no clients. */

    /* If I/O threads are disabled or we have few clients to serve, don't
     * use I/O threads, but the boring synchronous code. 
     * 
     * 如果 I/O 线程数为 1 或只要少量的客户端需要处理，则不使用 I/O 线程进行处理，
     * 而是由主线程同步处理
     */
    if (server.io_threads_num == 1 || stopThreadedIOIfNeeded()) {
        return handleClientsWithPendingWrites();
    }

    /* Start threads if needed. 
     * 运行到此处说明需要 I/O 线程进行处理
     * 检查 I/O 线程是否启动，没启动则启动 I/O 线程
     */
    if (!server.io_threads_active) startThreadedIO();

    /* Distribute the clients across N different lists. */
    listIter li;
    listNode *ln;
    listRewind(server.clients_pending_write,&li);
    int item_id = 0;
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        // 将客户端标记为非 CLIENT_PENDING_WRITE 状态
        c->flags &= ~CLIENT_PENDING_WRITE;

        /* Remove clients from the list of pending writes since
         * they are going to be closed ASAP. 
         * 从挂起的写入列表中删除客户端，因为它们将尽快关闭
         */
        if (c->flags & CLIENT_CLOSE_ASAP) {
            listDelNode(server.clients_pending_write, ln);
            continue;
        }

        int target_id = item_id % server.io_threads_num;
        listAddNodeTail(io_threads_list[target_id],c);
        item_id++;
    }

    /* Give the start condition to the waiting threads, by setting the
     * start condition atomic var. 
     * 
     * 设置 I/O 线程进行的操作为 WRITE，原子设置每个 I/O 线程的任务个数
     */
    io_threads_op = IO_THREADS_OP_WRITE;
    for (int j = 1; j < server.io_threads_num; j++) {
        int count = listLength(io_threads_list[j]);
        setIOPendingCount(j, count);
    }

    /* Also use the main thread to process a slice of clients. */
    // 主线程处理一部分客户端
    listRewind(io_threads_list[0],&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        writeToClient(c,0);
    }
    listEmpty(io_threads_list[0]);

    /* Wait for all the other threads to end their work. 
     * 
     * 主线程等待其它 I/O 线程完成任务
     */
    while(1) {
        unsigned long pending = 0;
        for (int j = 1; j < server.io_threads_num; j++)
            pending += getIOPendingCount(j);
        if (pending == 0) break;
    }

    /* Run the list of clients again to install the write handler where
     * needed. 
     * 再次访问挂起的写客户端列表
     */
    listRewind(server.clients_pending_write,&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);

        /* Install the write handler if there are pending writes in some
         * of the clients. 
         *
         * 如果某些挂起的写客户端还有回复数据没有写入到输出缓冲区，
         * 则注册写处理器
         */
        if (clientHasPendingReplies(c) &&
                connSetWriteHandler(c->conn, sendReplyToClient) == AE_ERR)
        {
            freeClientAsync(c);
        }
    }
    listEmpty(server.clients_pending_write);

    /* Update processed count on server */
    server.stat_io_writes_processed += processed;

    return processed;
}

/* Return 1 if we want to handle the client read later using threaded I/O.
 * 
 * 如果是稍后使用 I/O 线程来处理客户端读，则返回 1
 * 
 * This is called by the readable handler of the event loop.
 * 
 * 该函数被事件循环的可读处理器调用
 * 
 * As a side effect of calling this function the client is put in the
 * pending read clients and flagged as such. 
 * 
 * 调用这个函数可以将客户端放入挂起的可读客户端列表 
 * server.clients_pending_read 中
 * */
int postponeClientRead(client *c) {
    // 如果启用了 IO 线程
    // 且在 IO 线程中读和解析
    // 且此时没有阻塞时的事件要处理
    // 且客户端没被标记为 CLIENT_MASTER、CLIENT_SLAVE 和 CLIENT_PENDING_READ
    // 则将客户端标记为 CLIENT_PENDING_READ， 
    // 并将其加入到 server.clients_pending_read 列表中
    if (server.io_threads_active &&
        server.io_threads_do_reads &&
        !ProcessingEventsWhileBlocked &&
        !(c->flags & (CLIENT_MASTER|CLIENT_SLAVE|CLIENT_PENDING_READ)))
    {
        // 将客户端标记为 CLIENT_PENDING_READ
        c->flags |= CLIENT_PENDING_READ;
        // 将客户端加入到 server.clients_pending_read 列表中
        listAddNodeHead(server.clients_pending_read,c);
        return 1;
    } else {
        return 0;
    }
}

/* When threaded I/O is also enabled for the reading + parsing side, the
 * readable handler will just put normal clients into a queue of clients to
 * process (instead of serving them synchronously). This function runs
 * the queue using the I/O threads, and process them in order to accumulate
 * the reads in the buffers, and also parse the first command available
 * rendering it in the client structures. 
 * 
 * 当 IO 线程被启用时，可读处理器将客户端放入队列中，
 * 并用 IO 线程来处理队列中客户端，对客户端进行读操作，
 * 将读取出来的数据解析成命令。
 * 
 * */
int handleClientsWithPendingReadsUsingThreads(void) {
    // 如果 IO 线程或 IO 线程读没有启用，则直接返回
    if (!server.io_threads_active || !server.io_threads_do_reads) return 0;
    // 获取挂起读客户端队列中客户端的数量
    int processed = listLength(server.clients_pending_read);
    // 如果队列中客户端数量为 0，则直接返回
    if (processed == 0) return 0;

    /* Distribute the clients across N different lists. */
    // 将客户端列表中客户端分配给 N 个线程的客户端处理列表
    listIter li;
    listNode *ln;
    listRewind(server.clients_pending_read,&li);
    int item_id = 0;
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        int target_id = item_id % server.io_threads_num;
        listAddNodeTail(io_threads_list[target_id],c);
        item_id++;
    }

    /* Give the start condition to the waiting threads, by setting the
     * start condition atomic var. 
     * 为等待的 IO 线程设置启动条件，原子设置每个 IO 线程的任务
     */
    io_threads_op = IO_THREADS_OP_READ;
    for (int j = 1; j < server.io_threads_num; j++) {
        int count = listLength(io_threads_list[j]);
        // 原子设置 IO 线程的任务
        setIOPendingCount(j, count);
    }

    /* Also use the main thread to process a slice of clients. 
     *
     * 使用主线程处理一部分客户端
     */
    listRewind(io_threads_list[0],&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        // 读取客户端数据，解析成命令，并执行命令
        readQueryFromClient(c->conn);
    }
    // 清空列表
    listEmpty(io_threads_list[0]);

    /* Wait for all the other threads to end their work. 
     * 若主线程提前完任务，需要等待其它 IO 线程完成任务
     */
    while(1) {
        unsigned long pending = 0;
        for (int j = 1; j < server.io_threads_num; j++)
            pending += getIOPendingCount(j);
        // 当所有 IO 线程都没有任务后，跳出循环
        if (pending == 0) break;
    }

    /* Run the list of clients again to process the new buffers. 
     * 再次访问挂起的读客户端列表，这样做的目的有两个：
     * 1.IO 线程处理完客户端数据的读取和解析后，主线程执行命令
     * 2.处理缓冲区中的剩余数据，主要是针对那些缓冲区还有数据的 client，
     *   一般都是 client 发生了半包的数据，再次执行尝试读取完整的数据，
     *   看看是否能够解析出完整的命令
     */
    while(listLength(server.clients_pending_read)) {
        ln = listFirst(server.clients_pending_read);
        client *c = listNodeValue(ln);
        // 将客户端标记为非 CLIENT_PENDING_READ 状态
        c->flags &= ~CLIENT_PENDING_READ;
        // 从列表中删除指定的节点
        listDelNode(server.clients_pending_read,ln);

        // IO 线程将从缓冲区中读取的数据解析成完整的命令后，
        // 主线程执行挂起的客户端上已经解析完成的命令
        if (processPendingCommandsAndResetClient(c) == C_ERR) {
            /* If the client is no longer valid, we avoid
             * processing the client later. So we just go
             * to the next. */
            continue;
        }
        // 从客户端输入缓冲区中读取数据
        // 并解析成完整的命令
        // 最后执行命令
        processInputBuffer(c);

        /* We may have pending replies if a thread readQueryFromClient() produced
         * replies and did not install a write handler (it can't).
         * 如果线程调用 readQueryFromClient() 函数后，客户端的回复缓冲区中
         * 有数据要回复，且客户端没有被标记为 CLIENT_PENDING_WRITE 状态，
         * 则将客户端添加到 server.clients_pending_write 列表中
         */
        if (!(c->flags & CLIENT_PENDING_WRITE) && clientHasPendingReplies(c))
            clientInstallWriteHandler(c);
    }

    /* Update processed count on server */
    // 更新服务器处理的读事件数
    server.stat_io_reads_processed += processed;

    return processed;
}
