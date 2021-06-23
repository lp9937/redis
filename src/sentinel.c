/* Redis Sentinel implementation
 *
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
#include "hiredis.h"
#ifdef USE_OPENSSL
#include "openssl/ssl.h"
#include "hiredis_ssl.h"
#endif
#include "async.h"

#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>

extern char **environ;

#ifdef USE_OPENSSL
extern SSL_CTX *redis_tls_ctx;
extern SSL_CTX *redis_tls_client_ctx;
#endif

#define REDIS_SENTINEL_PORT 26379

/* ======================== Sentinel global state =========================== */

/* Address object, used to describe an ip:port pair. */
typedef struct sentinelAddr {
    char *hostname;         /* Hostname OR address, as specified */
    char *ip;               /* Always a resolved address */
    int port;
} sentinelAddr;

/* A Sentinel Redis Instance object is monitoring. */
#define SRI_MASTER  (1<<0)
#define SRI_SLAVE   (1<<1)
#define SRI_SENTINEL (1<<2)
#define SRI_S_DOWN (1<<3)   /* Subjectively down (no quorum). */
#define SRI_O_DOWN (1<<4)   /* Objectively down (confirmed by others). */
#define SRI_MASTER_DOWN (1<<5) /* A Sentinel with this flag set thinks that
                                   its master is down. */
#define SRI_FAILOVER_IN_PROGRESS (1<<6) /* Failover is in progress for
                                           this master. */
#define SRI_PROMOTED (1<<7)            /* Slave selected for promotion. */
#define SRI_RECONF_SENT (1<<8)     /* SLAVEOF <newmaster> sent. */
#define SRI_RECONF_INPROG (1<<9)   /* Slave synchronization in progress. */
#define SRI_RECONF_DONE (1<<10)     /* Slave synchronized with new master. */
#define SRI_FORCE_FAILOVER (1<<11)  /* Force failover with master up. */
#define SRI_SCRIPT_KILL_SENT (1<<12) /* SCRIPT KILL already sent on -BUSY */

/* Note: times are in milliseconds. */
#define SENTINEL_INFO_PERIOD 10000
#define SENTINEL_PING_PERIOD 1000
#define SENTINEL_ASK_PERIOD 1000
#define SENTINEL_PUBLISH_PERIOD 2000
#define SENTINEL_DEFAULT_DOWN_AFTER 30000
#define SENTINEL_HELLO_CHANNEL "__sentinel__:hello"
#define SENTINEL_TILT_TRIGGER 2000
#define SENTINEL_TILT_PERIOD (SENTINEL_PING_PERIOD*30)
#define SENTINEL_DEFAULT_SLAVE_PRIORITY 100
#define SENTINEL_SLAVE_RECONF_TIMEOUT 10000
#define SENTINEL_DEFAULT_PARALLEL_SYNCS 1
#define SENTINEL_MIN_LINK_RECONNECT_PERIOD 15000
#define SENTINEL_DEFAULT_FAILOVER_TIMEOUT (60*3*1000)
#define SENTINEL_MAX_PENDING_COMMANDS 100
#define SENTINEL_ELECTION_TIMEOUT 10000
#define SENTINEL_MAX_DESYNC 1000
#define SENTINEL_DEFAULT_DENY_SCRIPTS_RECONFIG 1
#define SENTINEL_DEFAULT_RESOLVE_HOSTNAMES 0
#define SENTINEL_DEFAULT_ANNOUNCE_HOSTNAMES 0

/* Failover machine different states. 
 * 故障转移相关的不同状态
 */
#define SENTINEL_FAILOVER_STATE_NONE 0                // 没有进行故障转移 /* No failover in progress. */
#define SENTINEL_FAILOVER_STATE_WAIT_START 1          // 等待故障转移开始 /* Wait for failover_start_time*/
#define SENTINEL_FAILOVER_STATE_SELECT_SLAVE 2        // 选择要升级为 master 的 slave /* Select slave to promote */
#define SENTINEL_FAILOVER_STATE_SEND_SLAVEOF_NOONE 3  // 向该从节点发送 SLAVEOF NO ONE 命令/* Slave -> Master */
#define SENTINEL_FAILOVER_STATE_WAIT_PROMOTION 4      // 等待 slave 晋升为 master /* Wait slave to change role */
#define SENTINEL_FAILOVER_STATE_RECONF_SLAVES 5       // 向其它 slave 节点发送 SLAVEOF 命令，使它们与新的主节点进行同步/* SLAVEOF newmaster */
#define SENTINEL_FAILOVER_STATE_UPDATE_CONFIG 6       // 更新当前哨兵节点中的 master 实例，及其下属 slave 实例的信息 /* Monitor promoted slave. */

#define SENTINEL_MASTER_LINK_STATUS_UP 0
#define SENTINEL_MASTER_LINK_STATUS_DOWN 1

/* Generic flags that can be used with different functions.
 * They use higher bits to avoid colliding with the function specific
 * flags. */
#define SENTINEL_NO_FLAGS 0
#define SENTINEL_GENERATE_EVENT (1<<16)
#define SENTINEL_LEADER (1<<17)
#define SENTINEL_OBSERVER (1<<18)

/* Script execution flags and limits. */
#define SENTINEL_SCRIPT_NONE 0
#define SENTINEL_SCRIPT_RUNNING 1
#define SENTINEL_SCRIPT_MAX_QUEUE 256
#define SENTINEL_SCRIPT_MAX_RUNNING 16
#define SENTINEL_SCRIPT_MAX_RUNTIME 60000 /* 60 seconds max exec time. */
#define SENTINEL_SCRIPT_MAX_RETRY 10
#define SENTINEL_SCRIPT_RETRY_DELAY 30000 /* 30 seconds between retries. */

/* SENTINEL SIMULATE-FAILURE command flags. */
#define SENTINEL_SIMFAILURE_NONE 0
#define SENTINEL_SIMFAILURE_CRASH_AFTER_ELECTION (1<<0)
#define SENTINEL_SIMFAILURE_CRASH_AFTER_PROMOTION (1<<1)

/* The link to a sentinelRedisInstance. When we have the same set of Sentinels
 * monitoring many masters, we have different instances representing the
 * same Sentinels, one per master, and we need to share the hiredis connections
 * among them. Otherwise if 5 Sentinels are monitoring 100 masters we create
 * 500 outgoing connections instead of 5.
 *
 * So this structure represents a reference counted link in terms of the two
 * hiredis connections for commands and Pub/Sub, and the fields needed for
 * failure detection, since the ping/pong time are now local to the link: if
 * the link is available, the instance is available. This way we don't just
 * have 5 connections instead of 500, we also send 5 pings instead of 500.
 *
 * Links are shared only for Sentinels: master and slave instances have
 * a link with refcount = 1, always. */
typedef struct instanceLink {
    int refcount;          /* Number of sentinelRedisInstance owners. */
    int disconnected;      /* Non-zero if we need to reconnect cc or pc. */
    // 命令发送了，等待回复的命令数
    int pending_commands;  /* Number of commands sent waiting for a reply. */
    redisAsyncContext *cc; /* Hiredis context for commands. */
    redisAsyncContext *pc; /* Hiredis context for Pub / Sub. */
    mstime_t cc_conn_time; /* cc connection time. */
    mstime_t pc_conn_time; /* pc connection time. */
    mstime_t pc_last_activity; /* Last time we received any message. */
    mstime_t last_avail_time; /* Last time the instance replied to ping with
                                 a reply we consider valid. */

    mstime_t act_ping_time;   /* Time at which the last pending ping (no pong
                                 received after it) was sent. This field is
                                 set to 0 when a pong is received, and set again
                                 to the current time if the value is 0 and a new
                                 ping is sent. */
    mstime_t last_ping_time;  /* Time at which we sent the last ping. This is
                                 only used to avoid sending too many pings
                                 during failure. Idle time is computed using
                                 the act_ping_time field. */
    mstime_t last_pong_time;  /* Last time the instance replied to ping,
                                 whatever the reply was. That's used to check
                                 if the link is idle and must be reconnected. */
    mstime_t last_reconn_time;  /* Last reconnection attempt performed when
                                   the link was down. */
} instanceLink;

typedef struct sentinelRedisInstance {
    int flags;      /* See SRI_... defines */
    char *name;     /* Master name from the point of view of this sentinel. */
    char *runid;    /* Run ID of this instance, or unique ID if is a Sentinel.*/
    uint64_t config_epoch;  /* Configuration epoch. */
    sentinelAddr *addr; /* Master host. */
    instanceLink *link; /* Link to the instance, may be shared for Sentinels. */
    mstime_t last_pub_time;   /* Last time we sent hello via Pub/Sub. */
    mstime_t last_hello_time; /* Only used if SRI_SENTINEL is set. Last time
                                 we received a hello from this Sentinel
                                 via Pub/Sub. */
    mstime_t last_master_down_reply_time; /* Time of last reply to
                                             SENTINEL is-master-down command. */
    mstime_t s_down_since_time; /* Subjectively down since time. */
    mstime_t o_down_since_time; /* Objectively down since time. */
    mstime_t down_after_period; /* Consider it down after that period. */
    mstime_t info_refresh;  /* Time at which we received INFO output from it. */
    dict *renamed_commands;     /* Commands renamed in this instance:
                                   Sentinel will use the alternative commands
                                   mapped on this table to send things like
                                   SLAVEOF, CONFING, INFO, ... */

    /* Role and the first time we observed it.
     * This is useful in order to delay replacing what the instance reports
     * with our own configuration. We need to always wait some time in order
     * to give a chance to the leader to report the new configuration before
     * we do silly things. */
    int role_reported;
    mstime_t role_reported_time;
    mstime_t slave_conf_change_time; /* Last time slave master addr changed. */

    /* Master specific. */
    dict *sentinels;    /* Other sentinels monitoring the same master. */
    dict *slaves;       /* Slaves for this master instance. */
    // 在投票的过程中，最少需要获得这么多个 sentinel 的投票
    unsigned int quorum;/* Number of sentinels that need to agree on failure. */
    int parallel_syncs; /* How many slaves to reconfigure at same time. */
    char *auth_pass;    /* Password to use for AUTH against master & replica. */
    char *auth_user;    /* Username for ACLs AUTH against master & replica. */

    /* Slave specific. */
    mstime_t master_link_down_time; /* Slave replication link down time. */
    int slave_priority; /* Slave priority according to its INFO output. */
    mstime_t slave_reconf_sent_time; /* Time at which we sent SLAVE OF <new> */
    struct sentinelRedisInstance *master; /* Master instance if it's slave. */
    char *slave_master_host;    /* Master host as reported by INFO */
    int slave_master_port;      /* Master port as reported by INFO */
    int slave_master_link_status; /* Master link status as reported by INFO */
    unsigned long long slave_repl_offset; /* Slave replication offset. */
    /* Failover */
    char *leader;       /* If this is a master instance, this is the runid of
                           the Sentinel that should perform the failover. If
                           this is a Sentinel, this is the runid of the Sentinel
                           that this Sentinel voted as leader. */
    uint64_t leader_epoch; /* Epoch of the 'leader' field. */
    uint64_t failover_epoch; /* Epoch of the currently started failover. */
    int failover_state; /* See SENTINEL_FAILOVER_STATE_* defines. */
    mstime_t failover_state_change_time;
    mstime_t failover_start_time;   /* Last failover attempt start time. */
    mstime_t failover_timeout;      /* Max time to refresh failover state. */
    mstime_t failover_delay_logged; /* For what failover_start_time value we
                                       logged the failover delay. */
    struct sentinelRedisInstance *promoted_slave; /* Promoted slave instance. */
    /* Scripts executed to notify admin or reconfigure clients: when they
     * are set to NULL no script is executed. */
    char *notification_script;
    char *client_reconfig_script;
    sds info; /* cached INFO output */
} sentinelRedisInstance;

/* Main state. */
struct sentinelState {
    char myid[CONFIG_RUN_ID_SIZE+1]; /* This sentinel ID. */
    uint64_t current_epoch;         /* Current epoch. */
    // master 对应的 sentinelRedisInstances 字典
    dict *masters;      /* Dictionary of master sentinelRedisInstances.
                           Key is the instance name, value is the
                           sentinelRedisInstance structure pointer. */
    int tilt;           /* Are we in TILT mode? */
    int running_scripts;    /* Number of scripts in execution right now. */
    mstime_t tilt_start_time;       /* When TITL started. */
    mstime_t previous_time;         /* Last time we ran the time handler. */
    list *scripts_queue;            /* Queue of user scripts to execute. */
    char *announce_ip;  /* IP addr that is gossiped to other sentinels if
                           not NULL. */
    int announce_port;  /* Port that is gossiped to other sentinels if
                           non zero. */
    unsigned long simfailure_flags; /* Failures simulation. */
    int deny_scripts_reconfig; /* Allow SENTINEL SET ... to change script
                                  paths at runtime? */
    char *sentinel_auth_pass;    /* Password to use for AUTH against other sentinel */
    char *sentinel_auth_user;    /* Username for ACLs AUTH against other sentinel. */
    int resolve_hostnames;       /* Support use of hostnames, assuming DNS is well configured. */
    int announce_hostnames;      /* Announce hostnames instead of IPs when we have them. */
} sentinel;

/* A script execution job. */
typedef struct sentinelScriptJob {
    int flags;              /* Script job flags: SENTINEL_SCRIPT_* */
    int retry_num;          /* Number of times we tried to execute it. */
    char **argv;            /* Arguments to call the script. */
    mstime_t start_time;    /* Script execution time if the script is running,
                               otherwise 0 if we are allowed to retry the
                               execution at any time. If the script is not
                               running and it's not 0, it means: do not run
                               before the specified time. */
    pid_t pid;              /* Script execution pid. */
} sentinelScriptJob;

/* ======================= hiredis ae.c adapters =============================
 * Note: this implementation is taken from hiredis/adapters/ae.h, however
 * we have our modified copy for Sentinel in order to use our allocator
 * and to have full control over how the adapter works. */

typedef struct redisAeEvents {
    redisAsyncContext *context;
    aeEventLoop *loop;
    int fd;
    int reading, writing;
} redisAeEvents;

static void redisAeReadEvent(aeEventLoop *el, int fd, void *privdata, int mask) {
    ((void)el); ((void)fd); ((void)mask);

    redisAeEvents *e = (redisAeEvents*)privdata;
    redisAsyncHandleRead(e->context);
}

static void redisAeWriteEvent(aeEventLoop *el, int fd, void *privdata, int mask) {
    ((void)el); ((void)fd); ((void)mask);

    redisAeEvents *e = (redisAeEvents*)privdata;
    redisAsyncHandleWrite(e->context);
}

static void redisAeAddRead(void *privdata) {
    redisAeEvents *e = (redisAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (!e->reading) {
        e->reading = 1;
        aeCreateFileEvent(loop,e->fd,AE_READABLE,redisAeReadEvent,e);
    }
}

static void redisAeDelRead(void *privdata) {
    redisAeEvents *e = (redisAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (e->reading) {
        e->reading = 0;
        aeDeleteFileEvent(loop,e->fd,AE_READABLE);
    }
}

static void redisAeAddWrite(void *privdata) {
    redisAeEvents *e = (redisAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (!e->writing) {
        e->writing = 1;
        aeCreateFileEvent(loop,e->fd,AE_WRITABLE,redisAeWriteEvent,e);
    }
}

static void redisAeDelWrite(void *privdata) {
    redisAeEvents *e = (redisAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (e->writing) {
        e->writing = 0;
        aeDeleteFileEvent(loop,e->fd,AE_WRITABLE);
    }
}

static void redisAeCleanup(void *privdata) {
    redisAeEvents *e = (redisAeEvents*)privdata;
    redisAeDelRead(privdata);
    redisAeDelWrite(privdata);
    zfree(e);
}

static int redisAeAttach(aeEventLoop *loop, redisAsyncContext *ac) {
    redisContext *c = &(ac->c);
    redisAeEvents *e;

    /* Nothing should be attached when something is already attached */
    if (ac->ev.data != NULL)
        return C_ERR;

    /* Create container for context and r/w events */
    e = (redisAeEvents*)zmalloc(sizeof(*e));
    e->context = ac;
    e->loop = loop;
    e->fd = c->fd;
    e->reading = e->writing = 0;

    /* Register functions to start/stop listening for events */
    ac->ev.addRead = redisAeAddRead;
    ac->ev.delRead = redisAeDelRead;
    ac->ev.addWrite = redisAeAddWrite;
    ac->ev.delWrite = redisAeDelWrite;
    ac->ev.cleanup = redisAeCleanup;
    ac->ev.data = e;

    return C_OK;
}

/* ============================= Prototypes ================================= */

void sentinelLinkEstablishedCallback(const redisAsyncContext *c, int status);
void sentinelDisconnectCallback(const redisAsyncContext *c, int status);
void sentinelReceiveHelloMessages(redisAsyncContext *c, void *reply, void *privdata);
sentinelRedisInstance *sentinelGetMasterByName(char *name);
char *sentinelGetSubjectiveLeader(sentinelRedisInstance *master);
char *sentinelGetObjectiveLeader(sentinelRedisInstance *master);
int yesnotoi(char *s);
void instanceLinkConnectionError(const redisAsyncContext *c);
const char *sentinelRedisInstanceTypeStr(sentinelRedisInstance *ri);
void sentinelAbortFailover(sentinelRedisInstance *ri);
void sentinelEvent(int level, char *type, sentinelRedisInstance *ri, const char *fmt, ...);
sentinelRedisInstance *sentinelSelectSlave(sentinelRedisInstance *master);
void sentinelScheduleScriptExecution(char *path, ...);
void sentinelStartFailover(sentinelRedisInstance *master);
void sentinelDiscardReplyCallback(redisAsyncContext *c, void *reply, void *privdata);
int sentinelSendSlaveOf(sentinelRedisInstance *ri, const sentinelAddr *addr);
char *sentinelVoteLeader(sentinelRedisInstance *master, uint64_t req_epoch, char *req_runid, uint64_t *leader_epoch);
void sentinelFlushConfig(void);
void sentinelGenerateInitialMonitorEvents(void);
int sentinelSendPing(sentinelRedisInstance *ri);
int sentinelForceHelloUpdateForMaster(sentinelRedisInstance *master);
sentinelRedisInstance *getSentinelRedisInstanceByAddrAndRunID(dict *instances, char *ip, int port, char *runid);
void sentinelSimFailureCrash(void);

/* ========================= Dictionary types =============================== */

uint64_t dictSdsHash(const void *key);
uint64_t dictSdsCaseHash(const void *key);
int dictSdsKeyCompare(void *privdata, const void *key1, const void *key2);
int dictSdsKeyCaseCompare(void *privdata, const void *key1, const void *key2);
void releaseSentinelRedisInstance(sentinelRedisInstance *ri);

void dictInstancesValDestructor (void *privdata, void *obj) {
    UNUSED(privdata);
    releaseSentinelRedisInstance(obj);
}

/* Instance name (sds) -> instance (sentinelRedisInstance pointer)
 *
 * also used for: sentinelRedisInstance->sentinels dictionary that maps
 * sentinels ip:port to last seen time in Pub/Sub hello message. */
dictType instancesDictType = {
    dictSdsHash,               /* hash function */
    NULL,                      /* key dup */
    NULL,                      /* val dup */
    dictSdsKeyCompare,         /* key compare */
    NULL,                      /* key destructor */
    dictInstancesValDestructor,/* val destructor */
    NULL                       /* allow to expand */
};

/* Instance runid (sds) -> votes (long casted to void*)
 *
 * This is useful into sentinelGetObjectiveLeader() function in order to
 * count the votes and understand who is the leader. */
dictType leaderVotesDictType = {
    dictSdsHash,               /* hash function */
    NULL,                      /* key dup */
    NULL,                      /* val dup */
    dictSdsKeyCompare,         /* key compare */
    NULL,                      /* key destructor */
    NULL,                      /* val destructor */
    NULL                       /* allow to expand */
};

/* Instance renamed commands table. */
dictType renamedCommandsDictType = {
    dictSdsCaseHash,           /* hash function */
    NULL,                      /* key dup */
    NULL,                      /* val dup */
    dictSdsKeyCaseCompare,     /* key compare */
    dictSdsDestructor,         /* key destructor */
    dictSdsDestructor,         /* val destructor */
    NULL                       /* allow to expand */
};

/* =========================== Initialization =============================== */

void sentinelCommand(client *c);
void sentinelInfoCommand(client *c);
void sentinelSetCommand(client *c);
void sentinelPublishCommand(client *c);
void sentinelRoleCommand(client *c);
void sentinelConfigGetCommand(client *c);
void sentinelConfigSetCommand(client *c);

struct redisCommand sentinelcmds[] = {
    {"ping",pingCommand,1,"fast @connection",0,NULL,0,0,0,0,0},
    {"sentinel",sentinelCommand,-2,"admin",0,NULL,0,0,0,0,0},
    {"subscribe",subscribeCommand,-2,"pub-sub",0,NULL,0,0,0,0,0},
    {"unsubscribe",unsubscribeCommand,-1,"pub-sub",0,NULL,0,0,0,0,0},
    {"psubscribe",psubscribeCommand,-2,"pub-sub",0,NULL,0,0,0,0,0},
    {"punsubscribe",punsubscribeCommand,-1,"pub-sub",0,NULL,0,0,0,0,0},
    {"publish",sentinelPublishCommand,3,"pub-sub fast",0,NULL,0,0,0,0,0},
    {"info",sentinelInfoCommand,-1,"random @dangerous",0,NULL,0,0,0,0,0},
    {"role",sentinelRoleCommand,1,"fast read-only @dangerous",0,NULL,0,0,0,0,0},
    {"client",clientCommand,-2,"admin random @connection",0,NULL,0,0,0,0,0},
    {"shutdown",shutdownCommand,-1,"admin",0,NULL,0,0,0,0,0},
    {"auth",authCommand,-2,"no-auth fast @connection",0,NULL,0,0,0,0,0},
    {"hello",helloCommand,-1,"no-auth fast @connection",0,NULL,0,0,0,0,0},
    {"acl",aclCommand,-2,"admin",0,NULL,0,0,0,0,0,0},
    {"command",commandCommand,-1, "random @connection", 0,NULL,0,0,0,0,0,0}
};

/* this array is used for sentinel config lookup, which need to be loaded
 * before monitoring masters config to avoid dependency issues */
const char *preMonitorCfgName[] = { 
    "announce-ip",
    "announce-port",
    "deny-scripts-reconfig",
    "sentinel-user",
    "sentinel-pass",
    "current-epoch",
    "myid",
    "resolve-hostnames",
    "announce-hostnames"
};

/* This function overwrites a few normal Redis config default with Sentinel
 * specific defaults. */
void initSentinelConfig(void) {
    server.port = REDIS_SENTINEL_PORT;
    server.protected_mode = 0; /* Sentinel must be exposed. */
}

void freeSentinelLoadQueueEntry(void *item);

/* Perform the Sentinel mode initialization. */
void initSentinel(void) {
    unsigned int j;

    /* Remove usual Redis commands from the command table, then just add
     * the SENTINEL command. */
    dictEmpty(server.commands,NULL);
    dictEmpty(server.orig_commands,NULL);
    ACLClearCommandID();
    for (j = 0; j < sizeof(sentinelcmds)/sizeof(sentinelcmds[0]); j++) {
        int retval;
        struct redisCommand *cmd = sentinelcmds+j;
        cmd->id = ACLGetCommandID(cmd->name); /* Assign the ID used for ACL. */
        retval = dictAdd(server.commands, sdsnew(cmd->name), cmd);
        serverAssert(retval == DICT_OK);
        retval = dictAdd(server.orig_commands, sdsnew(cmd->name), cmd);
        serverAssert(retval == DICT_OK);

        /* Translate the command string flags description into an actual
         * set of flags. */
        if (populateCommandTableParseFlags(cmd,cmd->sflags) == C_ERR)
            serverPanic("Unsupported command flag");
    }

    /* Initialize various data structures. */
    sentinel.current_epoch = 0;
    sentinel.masters = dictCreate(&instancesDictType,NULL);
    sentinel.tilt = 0;
    sentinel.tilt_start_time = 0;
    sentinel.previous_time = mstime();
    sentinel.running_scripts = 0;
    sentinel.scripts_queue = listCreate();
    sentinel.announce_ip = NULL;
    sentinel.announce_port = 0;
    sentinel.simfailure_flags = SENTINEL_SIMFAILURE_NONE;
    sentinel.deny_scripts_reconfig = SENTINEL_DEFAULT_DENY_SCRIPTS_RECONFIG;
    sentinel.sentinel_auth_pass = NULL;
    sentinel.sentinel_auth_user = NULL;
    sentinel.resolve_hostnames = SENTINEL_DEFAULT_RESOLVE_HOSTNAMES;
    sentinel.announce_hostnames = SENTINEL_DEFAULT_ANNOUNCE_HOSTNAMES;
    memset(sentinel.myid,0,sizeof(sentinel.myid));
    server.sentinel_config = NULL;
}

/* This function gets called when the server is in Sentinel mode, started,
 * loaded the configuration, and is ready for normal operations. */
void sentinelIsRunning(void) {
    int j;

    if (server.configfile == NULL) {
        serverLog(LL_WARNING,
            "Sentinel started without a config file. Exiting...");
        exit(1);
    } else if (access(server.configfile,W_OK) == -1) {
        serverLog(LL_WARNING,
            "Sentinel config file %s is not writable: %s. Exiting...",
            server.configfile,strerror(errno));
        exit(1);
    }

    /* If this Sentinel has yet no ID set in the configuration file, we
     * pick a random one and persist the config on disk. From now on this
     * will be this Sentinel ID across restarts. */
    for (j = 0; j < CONFIG_RUN_ID_SIZE; j++)
        if (sentinel.myid[j] != 0) break;

    if (j == CONFIG_RUN_ID_SIZE) {
        /* Pick ID and persist the config. */
        getRandomHexChars(sentinel.myid,CONFIG_RUN_ID_SIZE);
        sentinelFlushConfig();
    }

    /* Log its ID to make debugging of issues simpler. */
    serverLog(LL_WARNING,"Sentinel ID is %s", sentinel.myid);

    /* We want to generate a +monitor event for every configured master
     * at startup. */
    sentinelGenerateInitialMonitorEvents();
}

/* ============================== sentinelAddr ============================== */

/* Create a sentinelAddr object and return it on success.
 * On error NULL is returned and errno is set to:
 *  ENOENT: Can't resolve the hostname.
 *  EINVAL: Invalid port number.
 * 
 * 创建一个 sentinelAddr 对象，如果创建成功，则返回这个对象
 * 如果失败，则返回 NULL，并将 errno 变量的值设置为：
 * 1) ENOENT：不能解析 hostname
 * 2) EINVAL：无效的 port
 */
sentinelAddr *createSentinelAddr(char *hostname, int port) {
    char ip[NET_IP_STR_LEN];
    sentinelAddr *sa;

    if (port < 0 || port > 65535) {
        errno = EINVAL;
        return NULL;
    }
    if (anetResolve(NULL,hostname,ip,sizeof(ip),
                    sentinel.resolve_hostnames ? ANET_NONE : ANET_IP_ONLY) == ANET_ERR) {
        errno = ENOENT;
        return NULL;
    }
    sa = zmalloc(sizeof(*sa));
    sa->hostname = sdsnew(hostname);
    sa->ip = sdsnew(ip);
    sa->port = port;
    return sa;
}

/* Return a duplicate of the source address. */
sentinelAddr *dupSentinelAddr(sentinelAddr *src) {
    sentinelAddr *sa;

    sa = zmalloc(sizeof(*sa));
    sa->hostname = sdsnew(src->hostname);
    sa->ip = sdsnew(src->ip);
    sa->port = src->port;
    return sa;
}

/* Free a Sentinel address. Can't fail. */
void releaseSentinelAddr(sentinelAddr *sa) {
    sdsfree(sa->hostname);
    sdsfree(sa->ip);
    zfree(sa);
}

/* Return non-zero if two addresses are equal. */
int sentinelAddrIsEqual(sentinelAddr *a, sentinelAddr *b) {
    return a->port == b->port && !strcasecmp(a->ip,b->ip);
}

/* Return non-zero if a hostname matches an address. */
int sentinelAddrEqualsHostname(sentinelAddr *a, char *hostname) {
    char ip[NET_IP_STR_LEN];

    /* We always resolve the hostname and compare it to the address */
    if (anetResolve(NULL, hostname, ip, sizeof(ip),
                    sentinel.resolve_hostnames ? ANET_NONE : ANET_IP_ONLY) == ANET_ERR)
        return 0;
    return !strcasecmp(a->ip, ip);
}

const char *announceSentinelAddr(const sentinelAddr *a) {
    return sentinel.announce_hostnames ? a->hostname : a->ip;
}

/* Return an allocated sds with hostname/address:port. IPv6
 * addresses are bracketed the same way anetFormatAddr() does.
 */
sds announceSentinelAddrAndPort(const sentinelAddr *a) {
    const char *addr = announceSentinelAddr(a);
    if (strchr(addr, ':') != NULL)
        return sdscatprintf(sdsempty(), "[%s]:%d", addr, a->port);
    else
        return sdscatprintf(sdsempty(), "%s:%d", addr, a->port);
}

/* =========================== Events notification ========================== */

/* Send an event to log, pub/sub, user notification script.
 *
 * 'level' is the log level for logging. Only LL_WARNING events will trigger
 * the execution of the user notification script.
 *
 * 'type' is the message type, also used as a pub/sub channel name.
 *
 * 'ri', is the redis instance target of this event if applicable, and is
 * used to obtain the path of the notification script to execute.
 *
 * The remaining arguments are printf-alike.
 * If the format specifier starts with the two characters "%@" then ri is
 * not NULL, and the message is prefixed with an instance identifier in the
 * following format:
 *
 *  <instance type> <instance name> <ip> <port>
 *
 *  If the instance type is not master, than the additional string is
 *  added to specify the originating master:
 *
 *  @ <master name> <master ip> <master port>
 *
 *  Any other specifier after "%@" is processed by printf itself.
 */
void sentinelEvent(int level, char *type, sentinelRedisInstance *ri,
                   const char *fmt, ...) {
    va_list ap;
    char msg[LOG_MAX_LEN];
    robj *channel, *payload;

    /* Handle %@ */
    if (fmt[0] == '%' && fmt[1] == '@') {
        sentinelRedisInstance *master = (ri->flags & SRI_MASTER) ?
                                         NULL : ri->master;

        if (master) {
            snprintf(msg, sizeof(msg), "%s %s %s %d @ %s %s %d",
                sentinelRedisInstanceTypeStr(ri),
                ri->name, announceSentinelAddr(ri->addr), ri->addr->port,
                master->name, announceSentinelAddr(master->addr), master->addr->port);
        } else {
            snprintf(msg, sizeof(msg), "%s %s %s %d",
                sentinelRedisInstanceTypeStr(ri),
                ri->name, announceSentinelAddr(ri->addr), ri->addr->port);
        }
        fmt += 2;
    } else {
        msg[0] = '\0';
    }

    /* Use vsprintf for the rest of the formatting if any. */
    if (fmt[0] != '\0') {
        va_start(ap, fmt);
        vsnprintf(msg+strlen(msg), sizeof(msg)-strlen(msg), fmt, ap);
        va_end(ap);
    }

    /* Log the message if the log level allows it to be logged. */
    if (level >= server.verbosity)
        serverLog(level,"%s %s",type,msg);

    /* Publish the message via Pub/Sub if it's not a debugging one. */
    if (level != LL_DEBUG) {
        channel = createStringObject(type,strlen(type));
        payload = createStringObject(msg,strlen(msg));
        pubsubPublishMessage(channel,payload);
        decrRefCount(channel);
        decrRefCount(payload);
    }

    /* Call the notification script if applicable. */
    if (level == LL_WARNING && ri != NULL) {
        sentinelRedisInstance *master = (ri->flags & SRI_MASTER) ?
                                         ri : ri->master;
        if (master && master->notification_script) {
            sentinelScheduleScriptExecution(master->notification_script,
                type,msg,NULL);
        }
    }
}

/* This function is called only at startup and is used to generate a
 * +monitor event for every configured master. The same events are also
 * generated when a master to monitor is added at runtime via the
 * SENTINEL MONITOR command. */
void sentinelGenerateInitialMonitorEvents(void) {
    dictIterator *di;
    dictEntry *de;

    di = dictGetIterator(sentinel.masters);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        sentinelEvent(LL_WARNING,"+monitor",ri,"%@ quorum %d",ri->quorum);
    }
    dictReleaseIterator(di);
}

/* ============================ script execution ============================ */

/* Release a script job structure and all the associated data. */
void sentinelReleaseScriptJob(sentinelScriptJob *sj) {
    int j = 0;

    while(sj->argv[j]) sdsfree(sj->argv[j++]);
    zfree(sj->argv);
    zfree(sj);
}

#define SENTINEL_SCRIPT_MAX_ARGS 16
void sentinelScheduleScriptExecution(char *path, ...) {
    va_list ap;
    char *argv[SENTINEL_SCRIPT_MAX_ARGS+1];
    int argc = 1;
    sentinelScriptJob *sj;

    va_start(ap, path);
    while(argc < SENTINEL_SCRIPT_MAX_ARGS) {
        argv[argc] = va_arg(ap,char*);
        if (!argv[argc]) break;
        argv[argc] = sdsnew(argv[argc]); /* Copy the string. */
        argc++;
    }
    va_end(ap);
    argv[0] = sdsnew(path);

    sj = zmalloc(sizeof(*sj));
    sj->flags = SENTINEL_SCRIPT_NONE;
    sj->retry_num = 0;
    sj->argv = zmalloc(sizeof(char*)*(argc+1));
    sj->start_time = 0;
    sj->pid = 0;
    memcpy(sj->argv,argv,sizeof(char*)*(argc+1));

    listAddNodeTail(sentinel.scripts_queue,sj);

    /* Remove the oldest non running script if we already hit the limit. */
    if (listLength(sentinel.scripts_queue) > SENTINEL_SCRIPT_MAX_QUEUE) {
        listNode *ln;
        listIter li;

        listRewind(sentinel.scripts_queue,&li);
        while ((ln = listNext(&li)) != NULL) {
            sj = ln->value;

            if (sj->flags & SENTINEL_SCRIPT_RUNNING) continue;
            /* The first node is the oldest as we add on tail. */
            listDelNode(sentinel.scripts_queue,ln);
            sentinelReleaseScriptJob(sj);
            break;
        }
        serverAssert(listLength(sentinel.scripts_queue) <=
                    SENTINEL_SCRIPT_MAX_QUEUE);
    }
}

/* Lookup a script in the scripts queue via pid, and returns the list node
 * (so that we can easily remove it from the queue if needed). */
listNode *sentinelGetScriptListNodeByPid(pid_t pid) {
    listNode *ln;
    listIter li;

    listRewind(sentinel.scripts_queue,&li);
    while ((ln = listNext(&li)) != NULL) {
        sentinelScriptJob *sj = ln->value;

        if ((sj->flags & SENTINEL_SCRIPT_RUNNING) && sj->pid == pid)
            return ln;
    }
    return NULL;
}

/* Run pending scripts if we are not already at max number of running
 * scripts. 
 * 如果还没有达到最大运行的脚本数量，则运行脚本
 */
void sentinelRunPendingScripts(void) {
    listNode *ln;
    listIter li;
    mstime_t now = mstime();

    /* Find jobs that are not running and run them, from the top to the
     * tail of the queue, so we run older jobs first. 
     * 先进先出队列，从队列头部取出待运行的脚本
     */
    listRewind(sentinel.scripts_queue,&li);
    /*
     * 当正在运行的脚本小于最大允许运行的脚本数时，运行取出的脚本
     */
    while (sentinel.running_scripts < SENTINEL_SCRIPT_MAX_RUNNING &&
           (ln = listNext(&li)) != NULL)
    {
        sentinelScriptJob *sj = ln->value;
        pid_t pid;

        /* Skip if already running. 
         * 如果正在运行则跳过
         */
        if (sj->flags & SENTINEL_SCRIPT_RUNNING) continue;

        /* Skip if it's a retry, but not enough time has elapsed. 
         * 如果是重试，但没有足够的时间，则跳过
         */
        if (sj->start_time && sj->start_time > now) continue;

        sj->flags |= SENTINEL_SCRIPT_RUNNING;
        sj->start_time = mstime();
        sj->retry_num++;
        /*
         * 负值：创建子进程失败
         * 零：返回到新创建的子进程
         * 正值：返回父进程或调用者。该值包含新创建的子进程的进程ID
         */
        pid = fork();

        if (pid == -1) {
            /* Parent (fork error).
             * We report fork errors as signal 99, in order to unify the
             * reporting with other kind of errors. */
            sentinelEvent(LL_WARNING,"-script-error",NULL,
                          "%s %d %d", sj->argv[0], 99, 0);
            sj->flags &= ~SENTINEL_SCRIPT_RUNNING;
            sj->pid = 0;
        } else if (pid == 0) {
            /* Child */
            /*
             * 子进程执行脚本
             */
            tlsCleanup();
            execve(sj->argv[0],sj->argv,environ);
            /* If we are here an error occurred. */
            _exit(2); /* Don't retry execution. */
        } else {
            // 父进程
            // 增加执行脚本的计数器
            sentinel.running_scripts++;
            // 纪录 pid
            sj->pid = pid;
            // 发送脚本运行信号
            sentinelEvent(LL_DEBUG,"+script-child",NULL,"%ld",(long)pid);
        }
    }
}

/* How much to delay the execution of a script that we need to retry after
 * an error?
 *
 * We double the retry delay for every further retry we do. So for instance
 * if RETRY_DELAY is set to 30 seconds and the max number of retries is 10
 * starting from the second attempt to execute the script the delays are:
 * 30 sec, 60 sec, 2 min, 4 min, 8 min, 16 min, 32 min, 64 min, 128 min. */
mstime_t sentinelScriptRetryDelay(int retry_num) {
    mstime_t delay = SENTINEL_SCRIPT_RETRY_DELAY;

    while (retry_num-- > 1) delay *= 2;
    return delay;
}

/* Check for scripts that terminated, and remove them from the queue if the
 * script terminated successfully. If instead the script was terminated by
 * a signal, or returned exit code "1", it is scheduled to run again if
 * the max number of retries did not already elapsed. 
 * 
 * 检查脚本是否执行完，
 */
void sentinelCollectTerminatedScripts(void) {
    int statloc;
    pid_t pid;

    // 等待所有子进程
    while ((pid = wait3(&statloc,WNOHANG,NULL)) > 0) {
        int exitcode = WEXITSTATUS(statloc);
        int bysignal = 0;
        listNode *ln;
        sentinelScriptJob *sj;

        // 发送脚本终结信号
        if (WIFSIGNALED(statloc)) bysignal = WTERMSIG(statloc);
        sentinelEvent(LL_DEBUG,"-script-child",NULL,"%ld %d %d",
            (long)pid, exitcode, bysignal);
        
        // 在队列中按 pid 查找脚本
        ln = sentinelGetScriptListNodeByPid(pid);
        if (ln == NULL) {
            serverLog(LL_WARNING,"wait3() returned a pid (%ld) we can't find in our scripts execution queue!", (long)pid);
            continue;
        }
        sj = ln->value;

        /* If the script was terminated by a signal or returns an
         * exit code of "1" (that means: please retry), we reschedule it
         * if the max number of retries is not already reached. 
         * 如果脚本被信号终止或返回 1 的结束码，
         * 且重试次数还没有达到最大重试次数，则延迟重试
         */
        if ((bysignal || exitcode == 1) &&
            sj->retry_num != SENTINEL_SCRIPT_MAX_RETRY)
        {
            // 标记脚本为未执行状态
            sj->flags &= ~SENTINEL_SCRIPT_RUNNING;
            // 重置执行子进程 pid
            sj->pid = 0;
            // 指定时间之后重试
            sj->start_time = mstime() +
                             sentinelScriptRetryDelay(sj->retry_num);
        } else {
            /* Otherwise let's remove the script, but log the event if the
             * execution did not terminated in the best of the ways. 
             * 否则从队列中删除这个脚本
             * 如果执行没有以最佳方式终止，则记录事件
             */
            if (bysignal || exitcode != 0) {
                sentinelEvent(LL_WARNING,"-script-error",NULL,
                              "%s %d %d", sj->argv[0], bysignal, exitcode);
            }
            listDelNode(sentinel.scripts_queue,ln);
            sentinelReleaseScriptJob(sj);
        }
        sentinel.running_scripts--;
    }
}

/* Kill scripts in timeout, they'll be collected by the
 * sentinelCollectTerminatedScripts() function. 
 * 杀死运行超时的脚本
 */
void sentinelKillTimedoutScripts(void) {
    listNode *ln;
    listIter li;
    mstime_t now = mstime();

    listRewind(sentinel.scripts_queue,&li);
    while ((ln = listNext(&li)) != NULL) {
        sentinelScriptJob *sj = ln->value;

        if (sj->flags & SENTINEL_SCRIPT_RUNNING &&
            (now - sj->start_time) > SENTINEL_SCRIPT_MAX_RUNTIME)
        {
            sentinelEvent(LL_WARNING,"-script-timeout",NULL,"%s %ld",
                sj->argv[0], (long)sj->pid);
            kill(sj->pid,SIGKILL);
        }
    }
}

/* Implements SENTINEL PENDING-SCRIPTS command. */
void sentinelPendingScriptsCommand(client *c) {
    listNode *ln;
    listIter li;

    addReplyArrayLen(c,listLength(sentinel.scripts_queue));
    listRewind(sentinel.scripts_queue,&li);
    while ((ln = listNext(&li)) != NULL) {
        sentinelScriptJob *sj = ln->value;
        int j = 0;

        addReplyMapLen(c,5);

        addReplyBulkCString(c,"argv");
        while (sj->argv[j]) j++;
        addReplyArrayLen(c,j);
        j = 0;
        while (sj->argv[j]) addReplyBulkCString(c,sj->argv[j++]);

        addReplyBulkCString(c,"flags");
        addReplyBulkCString(c,
            (sj->flags & SENTINEL_SCRIPT_RUNNING) ? "running" : "scheduled");

        addReplyBulkCString(c,"pid");
        addReplyBulkLongLong(c,sj->pid);

        if (sj->flags & SENTINEL_SCRIPT_RUNNING) {
            addReplyBulkCString(c,"run-time");
            addReplyBulkLongLong(c,mstime() - sj->start_time);
        } else {
            mstime_t delay = sj->start_time ? (sj->start_time-mstime()) : 0;
            if (delay < 0) delay = 0;
            addReplyBulkCString(c,"run-delay");
            addReplyBulkLongLong(c,delay);
        }

        addReplyBulkCString(c,"retry-num");
        addReplyBulkLongLong(c,sj->retry_num);
    }
}

/* This function calls, if any, the client reconfiguration script with the
 * following parameters:
 *
 * <master-name> <role> <state> <from-ip> <from-port> <to-ip> <to-port>
 *
 * It is called every time a failover is performed.
 *
 * <state> is currently always "failover".
 * <role> is either "leader" or "observer".
 *
 * from/to fields are respectively master -> promoted slave addresses for
 * "start" and "end". */
void sentinelCallClientReconfScript(sentinelRedisInstance *master, int role, char *state, sentinelAddr *from, sentinelAddr *to) {
    char fromport[32], toport[32];

    if (master->client_reconfig_script == NULL) return;
    ll2string(fromport,sizeof(fromport),from->port);
    ll2string(toport,sizeof(toport),to->port);
    sentinelScheduleScriptExecution(master->client_reconfig_script,
        master->name,
        (role == SENTINEL_LEADER) ? "leader" : "observer",
        state, announceSentinelAddr(from), fromport,
        announceSentinelAddr(to), toport, NULL);
}

/* =============================== instanceLink ============================= */

/* Create a not yet connected link object. 
 * 创建一个尚未连接的连接对象
 */
instanceLink *createInstanceLink(void) {
    instanceLink *link = zmalloc(sizeof(*link));

    link->refcount = 1;
    link->disconnected = 1;
    link->pending_commands = 0;
    link->cc = NULL;
    link->pc = NULL;
    link->cc_conn_time = 0;
    link->pc_conn_time = 0;
    link->last_reconn_time = 0;
    link->pc_last_activity = 0;
    /* We set the act_ping_time to "now" even if we actually don't have yet
     * a connection with the node, nor we sent a ping.
     * This is useful to detect a timeout in case we'll not be able to connect
     * with the node at all. */
    link->act_ping_time = mstime();
    link->last_ping_time = 0;
    link->last_avail_time = mstime();
    link->last_pong_time = mstime();
    return link;
}

/* Disconnect a hiredis connection in the context of an instance link. */
void instanceLinkCloseConnection(instanceLink *link, redisAsyncContext *c) {
    if (c == NULL) return;

    if (link->cc == c) {
        link->cc = NULL;
        link->pending_commands = 0;
    }
    if (link->pc == c) link->pc = NULL;
    c->data = NULL;
    link->disconnected = 1;
    redisAsyncFree(c);
}

/* Decrement the refcount of a link object, if it drops to zero, actually
 * free it and return NULL. Otherwise don't do anything and return the pointer
 * to the object.
 *
 * If we are not going to free the link and ri is not NULL, we rebind all the
 * pending requests in link->cc (hiredis connection for commands) to a
 * callback that will just ignore them. This is useful to avoid processing
 * replies for an instance that no longer exists. */
instanceLink *releaseInstanceLink(instanceLink *link, sentinelRedisInstance *ri)
{
    serverAssert(link->refcount > 0);
    link->refcount--;
    if (link->refcount != 0) {
        if (ri && ri->link->cc) {
            /* This instance may have pending callbacks in the hiredis async
             * context, having as 'privdata' the instance that we are going to
             * free. Let's rewrite the callback list, directly exploiting
             * hiredis internal data structures, in order to bind them with
             * a callback that will ignore the reply at all. */
            redisCallback *cb;
            redisCallbackList *callbacks = &link->cc->replies;

            cb = callbacks->head;
            while(cb) {
                if (cb->privdata == ri) {
                    cb->fn = sentinelDiscardReplyCallback;
                    cb->privdata = NULL; /* Not strictly needed. */
                }
                cb = cb->next;
            }
        }
        return link; /* Other active users. */
    }

    instanceLinkCloseConnection(link,link->cc);
    instanceLinkCloseConnection(link,link->pc);
    zfree(link);
    return NULL;
}

/* This function will attempt to share the instance link we already have
 * for the same Sentinel in the context of a different master, with the
 * instance we are passing as argument.
 *
 * This way multiple Sentinel objects that refer all to the same physical
 * Sentinel instance but in the context of different masters will use
 * a single connection, will send a single PING per second for failure
 * detection and so forth.
 *
 * Return C_OK if a matching Sentinel was found in the context of a
 * different master and sharing was performed. Otherwise C_ERR
 * is returned. */
int sentinelTryConnectionSharing(sentinelRedisInstance *ri) {
    serverAssert(ri->flags & SRI_SENTINEL);
    dictIterator *di;
    dictEntry *de;

    if (ri->runid == NULL) return C_ERR; /* No way to identify it. */
    if (ri->link->refcount > 1) return C_ERR; /* Already shared. */

    di = dictGetIterator(sentinel.masters);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *master = dictGetVal(de), *match;
        /* We want to share with the same physical Sentinel referenced
         * in other masters, so skip our master. */
        if (master == ri->master) continue;
        match = getSentinelRedisInstanceByAddrAndRunID(master->sentinels,
                                                       NULL,0,ri->runid);
        if (match == NULL) continue; /* No match. */
        if (match == ri) continue; /* Should never happen but... safer. */

        /* We identified a matching Sentinel, great! Let's free our link
         * and use the one of the matching Sentinel. */
        releaseInstanceLink(ri->link,NULL);
        ri->link = match->link;
        match->link->refcount++;
        dictReleaseIterator(di);
        return C_OK;
    }
    dictReleaseIterator(di);
    return C_ERR;
}

/* Drop all connections to other sentinels. Returns the number of connections
 * dropped.*/
int sentinelDropConnections(void) {
    dictIterator *di;
    dictEntry *de;
    int dropped = 0;

    di = dictGetIterator(sentinel.masters);
    while ((de = dictNext(di)) != NULL) {
        dictIterator *sdi;
        dictEntry *sde;

        sentinelRedisInstance *ri = dictGetVal(de);
        sdi = dictGetIterator(ri->sentinels);
        while ((sde = dictNext(sdi)) != NULL) {
            sentinelRedisInstance *si = dictGetVal(sde);
            if (!si->link->disconnected) {
                instanceLinkCloseConnection(si->link, si->link->pc);
                instanceLinkCloseConnection(si->link, si->link->cc);
                dropped++;
            }
        }
        dictReleaseIterator(sdi);
    }
    dictReleaseIterator(di);

    return dropped;
}

/* When we detect a Sentinel to switch address (reporting a different IP/port
 * pair in Hello messages), let's update all the matching Sentinels in the
 * context of other masters as well and disconnect the links, so that everybody
 * will be updated.
 *
 * Return the number of updated Sentinel addresses. */
int sentinelUpdateSentinelAddressInAllMasters(sentinelRedisInstance *ri) {
    serverAssert(ri->flags & SRI_SENTINEL);
    dictIterator *di;
    dictEntry *de;
    int reconfigured = 0;

    di = dictGetIterator(sentinel.masters);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *master = dictGetVal(de), *match;
        match = getSentinelRedisInstanceByAddrAndRunID(master->sentinels,
                                                       NULL,0,ri->runid);
        /* If there is no match, this master does not know about this
         * Sentinel, try with the next one. */
        if (match == NULL) continue;

        /* Disconnect the old links if connected. */
        if (match->link->cc != NULL)
            instanceLinkCloseConnection(match->link,match->link->cc);
        if (match->link->pc != NULL)
            instanceLinkCloseConnection(match->link,match->link->pc);

        if (match == ri) continue; /* Address already updated for it. */

        /* Update the address of the matching Sentinel by copying the address
         * of the Sentinel object that received the address update. */
        releaseSentinelAddr(match->addr);
        match->addr = dupSentinelAddr(ri->addr);
        reconfigured++;
    }
    dictReleaseIterator(di);
    if (reconfigured)
        sentinelEvent(LL_NOTICE,"+sentinel-address-update", ri,
                    "%@ %d additional matching instances", reconfigured);
    return reconfigured;
}

/* This function is called when a hiredis connection reported an error.
 * We set it to NULL and mark the link as disconnected so that it will be
 * reconnected again.
 *
 * Note: we don't free the hiredis context as hiredis will do it for us
 * for async connections. */
void instanceLinkConnectionError(const redisAsyncContext *c) {
    instanceLink *link = c->data;
    int pubsub;

    if (!link) return;

    pubsub = (link->pc == c);
    if (pubsub)
        link->pc = NULL;
    else
        link->cc = NULL;
    link->disconnected = 1;
}

/* Hiredis connection established / disconnected callbacks. We need them
 * just to cleanup our link state. */
void sentinelLinkEstablishedCallback(const redisAsyncContext *c, int status) {
    if (status != C_OK) instanceLinkConnectionError(c);
}

void sentinelDisconnectCallback(const redisAsyncContext *c, int status) {
    UNUSED(status);
    instanceLinkConnectionError(c);
}

/* ========================== sentinelRedisInstance ========================= */

/* Create a redis instance, the following fields must be populated by the
 * caller if needed:
 *
 * 创建一个 redis 实例，如果需要，调用者必须提供以下字段：
 *
 * runid: set to NULL but will be populated once INFO output is received.
 *        设置为 NULL，但在接收到 INFO 命令回复后将被设置
 * 
 * info_refresh: is set to 0 to mean that we never received INFO so far.
 *               如果设置为 0，表示迄今为止从未收到过 INFO 信息
 * 
 * If SRI_MASTER is set into initial flags the instance is added to
 * sentinel.masters table.
 * 
 * 如果 flags 参数为 SRI_MASTER，那个这个实例将被添加到 sentinel.masters 这个字典中
 *
 * if SRI_SLAVE or SRI_SENTINEL is set then 'master' must be not NULL and the
 * instance is added into master->slaves or master->sentinels table.
 * 
 * 如果 flags 参数为 SRI_SLAVE 或 SRI_SENTINEL，则 master 参数必须不为 NULL，
 * 这个实例将被添加到 master->slaves 或 master->sentinels 字典中
 *
 * If the instance is a slave or sentinel, the name parameter is ignored and
 * is created automatically as hostname:port.
 * 
 * 如果这个实例是 slave 或 sentinel，则 name 参数被忽略，
 * 实例的名字会被自动设置成 hostname:port
 *
 * The function fails if hostname can't be resolved or port is out of range.
 * When this happens NULL is returned and errno is set accordingly to the
 * createSentinelAddr() function.
 * 
 * 如果 hostname 参数不能被解析，或 post 参数超出范围，此函数将返回 NULL，
 * 并根据 createSentinelAddr() 函数设置 errno 变量的值
 *
 * The function may also fail and return NULL with errno set to EBUSY if
 * a master with the same name, a slave with the same address, or a sentinel
 * with the same ID already exists. 
 * 
 * 如果已经存在相同名字的 master 或相同地址的 slave 或相同 ID 的 sentinel，
 * 则此函数返回 NULL，并将 errno 变量的值设置成 EBUSY
 */
sentinelRedisInstance *createSentinelRedisInstance(char *name, int flags, char *hostname, int port, int quorum, sentinelRedisInstance *master) {
    sentinelRedisInstance *ri;
    sentinelAddr *addr;
    dict *table = NULL;
    sds sdsname;

    serverAssert(flags & (SRI_MASTER|SRI_SLAVE|SRI_SENTINEL));
    serverAssert((flags & SRI_MASTER) || master != NULL);

    /* Check address validity. 
     * 检查地址有效性
     */
    addr = createSentinelAddr(hostname,port);
    if (addr == NULL) return NULL;

    /* For slaves use ip/host:port as name. 
     * slave 使用 ip 或 host:port 作为名字
     */
    if (flags & SRI_SLAVE)
        sdsname = announceSentinelAddrAndPort(addr);
    else
        sdsname = sdsnew(name);

    /* Make sure the entry is not duplicated. This may happen when the same
     * name for a master is used multiple times inside the configuration or
     * if we try to add multiple times a slave or sentinel with same ip/port
     * to a master. */
    if (flags & SRI_MASTER) table = sentinel.masters;
    else if (flags & SRI_SLAVE) table = master->slaves;
    else if (flags & SRI_SENTINEL) table = master->sentinels;
    /*
     * 确保不会添加重复的实例
     */
    if (dictFind(table,sdsname)) {
        releaseSentinelAddr(addr);
        sdsfree(sdsname);
        errno = EBUSY;
        return NULL;
    }

    /* Create the instance object. 
     * 创建实例对象
     */
    ri = zmalloc(sizeof(*ri));
    /* Note that all the instances are started in the disconnected state,
     * the event loop will take care of connecting them. 
     * 注意: 所有的实例初始连接状态都是断开状态
     * 这事件循环将负责连接它们
     */
    ri->flags = flags;
    ri->name = sdsname;
    ri->runid = NULL;
    ri->config_epoch = 0;
    ri->addr = addr;
    ri->link = createInstanceLink();
    ri->last_pub_time = mstime();
    ri->last_hello_time = mstime();
    ri->last_master_down_reply_time = mstime();
    ri->s_down_since_time = 0;
    ri->o_down_since_time = 0;
    ri->down_after_period = master ? master->down_after_period :
                            SENTINEL_DEFAULT_DOWN_AFTER;
    ri->master_link_down_time = 0;
    ri->auth_pass = NULL;
    ri->auth_user = NULL;
    ri->slave_priority = SENTINEL_DEFAULT_SLAVE_PRIORITY;
    ri->slave_reconf_sent_time = 0;
    ri->slave_master_host = NULL;
    ri->slave_master_port = 0;
    ri->slave_master_link_status = SENTINEL_MASTER_LINK_STATUS_DOWN;
    ri->slave_repl_offset = 0;
    ri->sentinels = dictCreate(&instancesDictType,NULL);
    ri->quorum = quorum;
    ri->parallel_syncs = SENTINEL_DEFAULT_PARALLEL_SYNCS;
    ri->master = master;
    ri->slaves = dictCreate(&instancesDictType,NULL);
    ri->info_refresh = 0;
    ri->renamed_commands = dictCreate(&renamedCommandsDictType,NULL);

    /* Failover state. */
    ri->leader = NULL;
    ri->leader_epoch = 0;
    ri->failover_epoch = 0;
    ri->failover_state = SENTINEL_FAILOVER_STATE_NONE;
    ri->failover_state_change_time = 0;
    ri->failover_start_time = 0;
    ri->failover_timeout = SENTINEL_DEFAULT_FAILOVER_TIMEOUT;
    ri->failover_delay_logged = 0;
    ri->promoted_slave = NULL;
    ri->notification_script = NULL;
    ri->client_reconfig_script = NULL;
    ri->info = NULL;

    /* Role */
    ri->role_reported = ri->flags & (SRI_MASTER|SRI_SLAVE);
    ri->role_reported_time = mstime();
    ri->slave_conf_change_time = mstime();

    /* Add into the right table. 
     * 将创建的 master 或 slave 或 sentinel 实例添加到
     * sentinel.masters 或 master->slaves 或 master->sentinels 字典中
     */
    dictAdd(table, ri->name, ri);
    return ri;
}

/* Release this instance and all its slaves, sentinels, hiredis connections.
 * This function does not take care of unlinking the instance from the main
 * masters table (if it is a master) or from its master sentinels/slaves table
 * if it is a slave or sentinel. */
void releaseSentinelRedisInstance(sentinelRedisInstance *ri) {
    /* Release all its slaves or sentinels if any. */
    dictRelease(ri->sentinels);
    dictRelease(ri->slaves);

    /* Disconnect the instance. */
    releaseInstanceLink(ri->link,ri);

    /* Free other resources. */
    sdsfree(ri->name);
    sdsfree(ri->runid);
    sdsfree(ri->notification_script);
    sdsfree(ri->client_reconfig_script);
    sdsfree(ri->slave_master_host);
    sdsfree(ri->leader);
    sdsfree(ri->auth_pass);
    sdsfree(ri->auth_user);
    sdsfree(ri->info);
    releaseSentinelAddr(ri->addr);
    dictRelease(ri->renamed_commands);

    /* Clear state into the master if needed. */
    if ((ri->flags & SRI_SLAVE) && (ri->flags & SRI_PROMOTED) && ri->master)
        ri->master->promoted_slave = NULL;

    zfree(ri);
}

/* Lookup a slave in a master Redis instance, by ip and port. */
sentinelRedisInstance *sentinelRedisInstanceLookupSlave(
                sentinelRedisInstance *ri, char *slave_addr, int port)
{
    sds key;
    sentinelRedisInstance *slave;
    sentinelAddr *addr;

    serverAssert(ri->flags & SRI_MASTER);

    /* We need to handle a slave_addr that is potentially a hostname.
     * If that is the case, depending on configuration we either resolve
     * it and use the IP addres or fail.
     */
    addr = createSentinelAddr(slave_addr, port);
    if (!addr) return NULL;
    key = announceSentinelAddrAndPort(addr);
    releaseSentinelAddr(addr);

    slave = dictFetchValue(ri->slaves,key);
    sdsfree(key);
    return slave;
}

/* Return the name of the type of the instance as a string. */
const char *sentinelRedisInstanceTypeStr(sentinelRedisInstance *ri) {
    if (ri->flags & SRI_MASTER) return "master";
    else if (ri->flags & SRI_SLAVE) return "slave";
    else if (ri->flags & SRI_SENTINEL) return "sentinel";
    else return "unknown";
}

/* This function remove the Sentinel with the specified ID from the
 * specified master.
 *
 * If "runid" is NULL the function returns ASAP.
 *
 * This function is useful because on Sentinels address switch, we want to
 * remove our old entry and add a new one for the same ID but with the new
 * address.
 *
 * The function returns 1 if the matching Sentinel was removed, otherwise
 * 0 if there was no Sentinel with this ID. */
int removeMatchingSentinelFromMaster(sentinelRedisInstance *master, char *runid) {
    dictIterator *di;
    dictEntry *de;
    int removed = 0;

    if (runid == NULL) return 0;

    di = dictGetSafeIterator(master->sentinels);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        if (ri->runid && strcmp(ri->runid,runid) == 0) {
            dictDelete(master->sentinels,ri->name);
            removed++;
        }
    }
    dictReleaseIterator(di);
    return removed;
}

/* Search an instance with the same runid, ip and port into a dictionary
 * of instances. Return NULL if not found, otherwise return the instance
 * pointer.
 *
 * runid or addr can be NULL. In such a case the search is performed only
 * by the non-NULL field. */
sentinelRedisInstance *getSentinelRedisInstanceByAddrAndRunID(dict *instances, char *addr, int port, char *runid) {
    dictIterator *di;
    dictEntry *de;
    sentinelRedisInstance *instance = NULL;
    sentinelAddr *ri_addr = NULL;

    serverAssert(addr || runid);   /* User must pass at least one search param. */
    if (addr != NULL) {
        /* Resolve addr, we use the IP as a key even if a hostname is used */
        ri_addr = createSentinelAddr(addr, port);
        if (!ri_addr) return NULL;
    }
    di = dictGetIterator(instances);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        if (runid && !ri->runid) continue;
        if ((runid == NULL || strcmp(ri->runid, runid) == 0) &&
            (addr == NULL || (strcmp(ri->addr->ip, ri_addr->ip) == 0 &&
                            ri->addr->port == port)))
        {
            instance = ri;
            break;
        }
    }
    dictReleaseIterator(di);
    if (ri_addr != NULL)
        releaseSentinelAddr(ri_addr);

    return instance;
}

/* Master lookup by name */
sentinelRedisInstance *sentinelGetMasterByName(char *name) {
    sentinelRedisInstance *ri;
    sds sdsname = sdsnew(name);

    ri = dictFetchValue(sentinel.masters,sdsname);
    sdsfree(sdsname);
    return ri;
}

/* Add the specified flags to all the instances in the specified dictionary. */
void sentinelAddFlagsToDictOfRedisInstances(dict *instances, int flags) {
    dictIterator *di;
    dictEntry *de;

    di = dictGetIterator(instances);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        ri->flags |= flags;
    }
    dictReleaseIterator(di);
}

/* Remove the specified flags to all the instances in the specified
 * dictionary. */
void sentinelDelFlagsToDictOfRedisInstances(dict *instances, int flags) {
    dictIterator *di;
    dictEntry *de;

    di = dictGetIterator(instances);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        ri->flags &= ~flags;
    }
    dictReleaseIterator(di);
}

/* Reset the state of a monitored master:
 * 重置被监视 master 的状态
 * 1) Remove all slaves.
 *    移除所有的 slave
 * 2) Remove all sentinels.
 *    移除所有的 sentinel
 * 3) Remove most of the flags resulting from runtime operations.
 *    删除运行时操作产生的大多数 flag
 * 4) Reset timers to their default value. For example after a reset it will be
 *    possible to failover again the same master ASAP, without waiting the
 *    failover timeout delay.
 *    将计时器重置为默认值
 * 5) In the process of doing this undo the failover if in progress.
 *    如果在此过程中正在执行故障转移，那么取消它
 * 6) Disconnect the connections with the master (will reconnect automatically).
 *    断开 sentinel 与 master 之间的连接，之后会自动重连
 */

#define SENTINEL_RESET_NO_SENTINELS (1<<0)
void sentinelResetMaster(sentinelRedisInstance *ri, int flags) {
    serverAssert(ri->flags & SRI_MASTER);
    dictRelease(ri->slaves);
    ri->slaves = dictCreate(&instancesDictType,NULL);
    if (!(flags & SENTINEL_RESET_NO_SENTINELS)) {
        dictRelease(ri->sentinels);
        ri->sentinels = dictCreate(&instancesDictType,NULL);
    }
    instanceLinkCloseConnection(ri->link,ri->link->cc);
    instanceLinkCloseConnection(ri->link,ri->link->pc);
    ri->flags &= SRI_MASTER;
    if (ri->leader) {
        sdsfree(ri->leader);
        ri->leader = NULL;
    }
    ri->failover_state = SENTINEL_FAILOVER_STATE_NONE;
    ri->failover_state_change_time = 0;
    ri->failover_start_time = 0; /* We can failover again ASAP. */
    ri->promoted_slave = NULL;
    sdsfree(ri->runid);
    sdsfree(ri->slave_master_host);
    ri->runid = NULL;
    ri->slave_master_host = NULL;
    ri->link->act_ping_time = mstime();
    ri->link->last_ping_time = 0;
    ri->link->last_avail_time = mstime();
    ri->link->last_pong_time = mstime();
    ri->role_reported_time = mstime();
    ri->role_reported = SRI_MASTER;
    if (flags & SENTINEL_GENERATE_EVENT)
        sentinelEvent(LL_WARNING,"+reset-master",ri,"%@");
}

/* Call sentinelResetMaster() on every master with a name matching the specified
 * pattern. */
int sentinelResetMastersByPattern(char *pattern, int flags) {
    dictIterator *di;
    dictEntry *de;
    int reset = 0;

    di = dictGetIterator(sentinel.masters);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        if (ri->name) {
            if (stringmatch(pattern,ri->name,0)) {
                sentinelResetMaster(ri,flags);
                reset++;
            }
        }
    }
    dictReleaseIterator(di);
    return reset;
}

/* Reset the specified master with sentinelResetMaster(), and also change
 * the ip:port address, but take the name of the instance unmodified.
 * 
 * 调用 sentinelResetMaster() 函数重置 master，
 * 同时将 master 实例的 ip 和端口号修改成指定的 ip 和端口，
 * 但不修改 master 实例的名字
 * 
 * This is used to handle the +switch-master event.
 * 
 * 这个函数被用于处理 +switch-master 事件
 *
 * The function returns C_ERR if the address can't be resolved for some
 * reason. Otherwise C_OK is returned.  
 * 如果因为某些原因地址不能被解析，则返回 C_ERR
 * 否则返回 C_OK
 */
int sentinelResetMasterAndChangeAddress(sentinelRedisInstance *master, char *hostname, int port) {
    sentinelAddr *oldaddr, *newaddr;
    sentinelAddr **slaves = NULL;
    int numslaves = 0, j;
    dictIterator *di;
    dictEntry *de;

    // 新 master 的地址
    newaddr = createSentinelAddr(hostname,port);
    if (newaddr == NULL) return C_ERR;

    /* There can be only 0 or 1 slave that has the newaddr.
     * and It can add old master 1 more slave. 
     * so It allocates dictSize(master->slaves) + 1          
     * 
     * 新 master 可能不在旧 master 的 slave 中，
     * 并且要将旧 master 添加到 slaves 中，所以申请的时候加 1
     */
    slaves = zmalloc(sizeof(sentinelAddr*)*(dictSize(master->slaves) + 1));
    
    /* Don't include the one having the address we are switching to. 
     * 不包括新 master
     */
    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);

        // 跳过新 master
        if (sentinelAddrIsEqual(slave->addr,newaddr)) continue;
        slaves[numslaves++] = dupSentinelAddr(slave->addr);
    }
    dictReleaseIterator(di);

    /* If we are switching to a different address, include the old address
     * as a slave as well, so that we'll be able to sense / reconfigure
     * the old master. 
     *
     * 如果新地址和旧 master 的地址不相同
     * 将旧 master 的地址也作为 slave 的地址添加到保存了所有 slave 地址的数组中
     * 这样相当于将下线 master 设置为新 master 的 slave
     */
    if (!sentinelAddrIsEqual(newaddr,master->addr)) {
        slaves[numslaves++] = dupSentinelAddr(master->addr);
    }

    /* Reset and switch address. 
     * 重置 master 并修改地址
     */
    sentinelResetMaster(master,SENTINEL_RESET_NO_SENTINELS);
    oldaddr = master->addr;
    // 为 master 设置新地址
    master->addr = newaddr;
    master->o_down_since_time = 0;
    master->s_down_since_time = 0;

    /* Add slaves back. 
     * 为 master 加回 slave
     */
    for (j = 0; j < numslaves; j++) {
        sentinelRedisInstance *slave;
        // 创建 slave，并将 slave 添加到 master->slaves 字典中
        slave = createSentinelRedisInstance(NULL,SRI_SLAVE,slaves[j]->hostname,
                    slaves[j]->port, master->quorum, master);
        releaseSentinelAddr(slaves[j]);
        if (slave) sentinelEvent(LL_NOTICE,"+slave",slave,"%@");
    }
    zfree(slaves);

    /* Release the old address at the end so we are safe even if the function
     * gets the master->addr->ip and master->addr->port as arguments. 
     * 释放 master 的旧地址
     */
    releaseSentinelAddr(oldaddr);
    /*
     * 将 Sentinel 的状态持久化到当前配置文件中
     */
    sentinelFlushConfig();
    return C_OK;
}

/* Return non-zero if there was no SDOWN or ODOWN error associated to this
 * instance in the latest 'ms' milliseconds. */
int sentinelRedisInstanceNoDownFor(sentinelRedisInstance *ri, mstime_t ms) {
    mstime_t most_recent;

    most_recent = ri->s_down_since_time;
    if (ri->o_down_since_time > most_recent)
        most_recent = ri->o_down_since_time;
    return most_recent == 0 || (mstime() - most_recent) > ms;
}

/* Return the current master address, that is, its address or the address
 * of the promoted slave if already operational. */
sentinelAddr *sentinelGetCurrentMasterAddress(sentinelRedisInstance *master) {
    /* If we are failing over the master, and the state is already
     * SENTINEL_FAILOVER_STATE_RECONF_SLAVES or greater, it means that we
     * already have the new configuration epoch in the master, and the
     * slave acknowledged the configuration switch. Advertise the new
     * address. */
    if ((master->flags & SRI_FAILOVER_IN_PROGRESS) &&
        master->promoted_slave &&
        master->failover_state >= SENTINEL_FAILOVER_STATE_RECONF_SLAVES)
    {
        return master->promoted_slave->addr;
    } else {
        return master->addr;
    }
}

/* This function sets the down_after_period field value in 'master' to all
 * the slaves and sentinel instances connected to this master. */
void sentinelPropagateDownAfterPeriod(sentinelRedisInstance *master) {
    dictIterator *di;
    dictEntry *de;
    int j;
    dict *d[] = {master->slaves, master->sentinels, NULL};

    for (j = 0; d[j]; j++) {
        di = dictGetIterator(d[j]);
        while((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *ri = dictGetVal(de);
            ri->down_after_period = master->down_after_period;
        }
        dictReleaseIterator(di);
    }
}

char *sentinelGetInstanceTypeString(sentinelRedisInstance *ri) {
    if (ri->flags & SRI_MASTER) return "master";
    else if (ri->flags & SRI_SLAVE) return "slave";
    else if (ri->flags & SRI_SENTINEL) return "sentinel";
    else return "unknown";
}

/* This function is used in order to send commands to Redis instances: the
 * commands we send from Sentinel may be renamed, a common case is a master
 * with CONFIG and SLAVEOF commands renamed for security concerns. In that
 * case we check the ri->renamed_command table (or if the instance is a slave,
 * we check the one of the master), and map the command that we should send
 * to the set of renamed commads. However, if the command was not renamed,
 * we just return "command" itself. 
 * 判断命令是否被重命名，如果重命名，返回重命名后的名字
 * 否则返回原名字
 */
char *sentinelInstanceMapCommand(sentinelRedisInstance *ri, char *command) {
    sds sc = sdsnew(command);
    if (ri->master) ri = ri->master;
    char *retval = dictFetchValue(ri->renamed_commands, sc);
    sdsfree(sc);
    return retval ? retval : command;
}

/* ============================ Config handling ============================= */

/* Generalise handling create instance error. Use SRI_MASTER, SRI_SLAVE or
 * SRI_SENTINEL as a role value. */
const char *sentinelCheckCreateInstanceErrors(int role) {
    switch(errno) {
    case EBUSY:
        switch (role) {
        case SRI_MASTER:
            return "Duplicate master name.";
        case SRI_SLAVE:
            return "Duplicate hostname and port for replica.";
        case SRI_SENTINEL:
            return "Duplicate runid for sentinel.";
        default:
            serverAssert(0);
            break;
        }
        break;
    case ENOENT:
        return "Can't resolve instance hostname.";
    case EINVAL:
        return "Invalid port number.";
    default:
        return "Unknown Error for creating instances.";
    }
}

/* init function for server.sentinel_config */
void initializeSentinelConfig() {
    server.sentinel_config = zmalloc(sizeof(struct sentinelConfig));
    server.sentinel_config->monitor_cfg = listCreate();
    server.sentinel_config->pre_monitor_cfg = listCreate();
    server.sentinel_config->post_monitor_cfg = listCreate();
    listSetFreeMethod(server.sentinel_config->monitor_cfg,freeSentinelLoadQueueEntry);
    listSetFreeMethod(server.sentinel_config->pre_monitor_cfg,freeSentinelLoadQueueEntry);
    listSetFreeMethod(server.sentinel_config->post_monitor_cfg,freeSentinelLoadQueueEntry);
}

/* destroy function for server.sentinel_config */
void freeSentinelConfig() {
    /* release these three config queues since we will not use it anymore */
    listRelease(server.sentinel_config->pre_monitor_cfg);
    listRelease(server.sentinel_config->monitor_cfg);
    listRelease(server.sentinel_config->post_monitor_cfg);
    zfree(server.sentinel_config);
    server.sentinel_config = NULL;
}

/* Search config name in pre monitor config name array, return 1 if found,
 * 0 if not found. */
int searchPreMonitorCfgName(const char *name) {
    for (unsigned int i = 0; i < sizeof(preMonitorCfgName)/sizeof(preMonitorCfgName[0]); i++) {
        if (!strcasecmp(preMonitorCfgName[i],name)) return 1;
    }
    return 0;
}

/* free method for sentinelLoadQueueEntry when release the list */
void freeSentinelLoadQueueEntry(void *item) {
    struct sentinelLoadQueueEntry *entry = item;
    sdsfreesplitres(entry->argv,entry->argc);
    sdsfree(entry->line);
    zfree(entry);
}

/* This function is used for queuing sentinel configuration, the main
 * purpose of this function is to delay parsing the sentinel config option
 * in order to avoid the order dependent issue from the config. */
void queueSentinelConfig(sds *argv, int argc, int linenum, sds line) {
    int i;
    struct sentinelLoadQueueEntry *entry;

    /* initialize sentinel_config for the first call */
    if (server.sentinel_config == NULL) initializeSentinelConfig();

    entry = zmalloc(sizeof(struct sentinelLoadQueueEntry));
    entry->argv = zmalloc(sizeof(char*)*argc);
    entry->argc = argc;
    entry->linenum = linenum;
    entry->line = sdsdup(line);
    for (i = 0; i < argc; i++) {
        entry->argv[i] = sdsdup(argv[i]);
    }
    /*  Separate config lines with pre monitor config, monitor config and
     *  post monitor config, in order to parsing config dependencies
     *  correctly. */
    if (!strcasecmp(argv[0],"monitor")) {
        listAddNodeTail(server.sentinel_config->monitor_cfg,entry);
    } else if (searchPreMonitorCfgName(argv[0])) {
        listAddNodeTail(server.sentinel_config->pre_monitor_cfg,entry);
    } else{
        listAddNodeTail(server.sentinel_config->post_monitor_cfg,entry);
    }
}

/* This function is used for loading the sentinel configuration from
 * pre_monitor_cfg, monitor_cfg and post_monitor_cfg list */
void loadSentinelConfigFromQueue(void) {
    const char *err = NULL;
    listIter li;
    listNode *ln;
    int linenum = 0;
    sds line = NULL;

    /* if there is no sentinel_config entry, we can return immediately */
    if (server.sentinel_config == NULL) return;

    /* loading from pre monitor config queue first to avoid dependency issues */
    listRewind(server.sentinel_config->pre_monitor_cfg,&li);
    while((ln = listNext(&li))) {
        struct sentinelLoadQueueEntry *entry = ln->value;
        err = sentinelHandleConfiguration(entry->argv,entry->argc);
        if (err) {
            linenum = entry->linenum;
            line = entry->line;
            goto loaderr;
        }
    }

    /* loading from monitor config queue */
    listRewind(server.sentinel_config->monitor_cfg,&li);
    while((ln = listNext(&li))) {
        struct sentinelLoadQueueEntry *entry = ln->value;
        err = sentinelHandleConfiguration(entry->argv,entry->argc);
        if (err) {
            linenum = entry->linenum;
            line = entry->line;
            goto loaderr;
        }
    }

    /* loading from the post monitor config queue */
    listRewind(server.sentinel_config->post_monitor_cfg,&li);
    while((ln = listNext(&li))) {
        struct sentinelLoadQueueEntry *entry = ln->value;
        err = sentinelHandleConfiguration(entry->argv,entry->argc);
        if (err) {
            linenum = entry->linenum;
            line = entry->line;
            goto loaderr;
        }
    }

    /* free sentinel_config when config loading is finished */
    freeSentinelConfig();
    return;

loaderr:
    fprintf(stderr, "\n*** FATAL CONFIG FILE ERROR (Redis %s) ***\n",
        REDIS_VERSION);
    fprintf(stderr, "Reading the configuration file, at line %d\n", linenum);
    fprintf(stderr, ">>> '%s'\n", line);
    fprintf(stderr, "%s\n", err);
    exit(1);
}

const char *sentinelHandleConfiguration(char **argv, int argc) {

    sentinelRedisInstance *ri;

    if (!strcasecmp(argv[0],"monitor") && argc == 5) {
        /* monitor <name> <host> <port> <quorum> */
        int quorum = atoi(argv[4]);

        if (quorum <= 0) return "Quorum must be 1 or greater.";
        if (createSentinelRedisInstance(argv[1],SRI_MASTER,argv[2],
                                        atoi(argv[3]),quorum,NULL) == NULL)
        {
            return sentinelCheckCreateInstanceErrors(SRI_MASTER);
        }
    } else if (!strcasecmp(argv[0],"down-after-milliseconds") && argc == 3) {
        /* down-after-milliseconds <name> <milliseconds> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->down_after_period = atoi(argv[2]);
        if (ri->down_after_period <= 0)
            return "negative or zero time parameter.";
        sentinelPropagateDownAfterPeriod(ri);
    } else if (!strcasecmp(argv[0],"failover-timeout") && argc == 3) {
        /* failover-timeout <name> <milliseconds> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->failover_timeout = atoi(argv[2]);
        if (ri->failover_timeout <= 0)
            return "negative or zero time parameter.";
    } else if (!strcasecmp(argv[0],"parallel-syncs") && argc == 3) {
        /* parallel-syncs <name> <milliseconds> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->parallel_syncs = atoi(argv[2]);
    } else if (!strcasecmp(argv[0],"notification-script") && argc == 3) {
        /* notification-script <name> <path> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        if (access(argv[2],X_OK) == -1)
            return "Notification script seems non existing or non executable.";
        ri->notification_script = sdsnew(argv[2]);
    } else if (!strcasecmp(argv[0],"client-reconfig-script") && argc == 3) {
        /* client-reconfig-script <name> <path> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        if (access(argv[2],X_OK) == -1)
            return "Client reconfiguration script seems non existing or "
                   "non executable.";
        ri->client_reconfig_script = sdsnew(argv[2]);
    } else if (!strcasecmp(argv[0],"auth-pass") && argc == 3) {
        /* auth-pass <name> <password> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->auth_pass = sdsnew(argv[2]);
    } else if (!strcasecmp(argv[0],"auth-user") && argc == 3) {
        /* auth-user <name> <username> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->auth_user = sdsnew(argv[2]);
    } else if (!strcasecmp(argv[0],"current-epoch") && argc == 2) {
        /* current-epoch <epoch> */
        unsigned long long current_epoch = strtoull(argv[1],NULL,10);
        if (current_epoch > sentinel.current_epoch)
            sentinel.current_epoch = current_epoch;
    } else if (!strcasecmp(argv[0],"myid") && argc == 2) {
        if (strlen(argv[1]) != CONFIG_RUN_ID_SIZE)
            return "Malformed Sentinel id in myid option.";
        memcpy(sentinel.myid,argv[1],CONFIG_RUN_ID_SIZE);
    } else if (!strcasecmp(argv[0],"config-epoch") && argc == 3) {
        /* config-epoch <name> <epoch> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->config_epoch = strtoull(argv[2],NULL,10);
        /* The following update of current_epoch is not really useful as
         * now the current epoch is persisted on the config file, but
         * we leave this check here for redundancy. */
        if (ri->config_epoch > sentinel.current_epoch)
            sentinel.current_epoch = ri->config_epoch;
    } else if (!strcasecmp(argv[0],"leader-epoch") && argc == 3) {
        /* leader-epoch <name> <epoch> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->leader_epoch = strtoull(argv[2],NULL,10);
    } else if ((!strcasecmp(argv[0],"known-slave") ||
                !strcasecmp(argv[0],"known-replica")) && argc == 4)
    {
        sentinelRedisInstance *slave;

        /* known-replica <name> <ip> <port> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        if ((slave = createSentinelRedisInstance(NULL,SRI_SLAVE,argv[2],
                    atoi(argv[3]), ri->quorum, ri)) == NULL)
        {
            return sentinelCheckCreateInstanceErrors(SRI_SLAVE);
        }
    } else if (!strcasecmp(argv[0],"known-sentinel") &&
               (argc == 4 || argc == 5)) {
        sentinelRedisInstance *si;

        if (argc == 5) { /* Ignore the old form without runid. */
            /* known-sentinel <name> <ip> <port> [runid] */
            ri = sentinelGetMasterByName(argv[1]);
            if (!ri) return "No such master with specified name.";
            if ((si = createSentinelRedisInstance(argv[4],SRI_SENTINEL,argv[2],
                        atoi(argv[3]), ri->quorum, ri)) == NULL)
            {
                return sentinelCheckCreateInstanceErrors(SRI_SENTINEL);
            }
            si->runid = sdsnew(argv[4]);
            sentinelTryConnectionSharing(si);
        }
    } else if (!strcasecmp(argv[0],"rename-command") && argc == 4) {
        /* rename-command <name> <command> <renamed-command> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        sds oldcmd = sdsnew(argv[2]);
        sds newcmd = sdsnew(argv[3]);
        if (dictAdd(ri->renamed_commands,oldcmd,newcmd) != DICT_OK) {
            sdsfree(oldcmd);
            sdsfree(newcmd);
            return "Same command renamed multiple times with rename-command.";
        }
    } else if (!strcasecmp(argv[0],"announce-ip") && argc == 2) {
        /* announce-ip <ip-address> */
        if (strlen(argv[1]))
            sentinel.announce_ip = sdsnew(argv[1]);
    } else if (!strcasecmp(argv[0],"announce-port") && argc == 2) {
        /* announce-port <port> */
        sentinel.announce_port = atoi(argv[1]);
    } else if (!strcasecmp(argv[0],"deny-scripts-reconfig") && argc == 2) {
        /* deny-scripts-reconfig <yes|no> */
        if ((sentinel.deny_scripts_reconfig = yesnotoi(argv[1])) == -1) {
            return "Please specify yes or no for the "
                   "deny-scripts-reconfig options.";
        }
    } else if (!strcasecmp(argv[0],"sentinel-user") && argc == 2) {
        /* sentinel-user <user-name> */
        if (strlen(argv[1]))
            sentinel.sentinel_auth_user = sdsnew(argv[1]);
    } else if (!strcasecmp(argv[0],"sentinel-pass") && argc == 2) {
        /* sentinel-pass <password> */
        if (strlen(argv[1]))
            sentinel.sentinel_auth_pass = sdsnew(argv[1]);
    } else if (!strcasecmp(argv[0],"resolve-hostnames") && argc == 2) {
        /* resolve-hostnames <yes|no> */
        if ((sentinel.resolve_hostnames = yesnotoi(argv[1])) == -1) {
            return "Please specify yes or not for the resolve-hostnames option.";
        }
    } else if (!strcasecmp(argv[0],"announce-hostnames") && argc == 2) {
        /* announce-hostnames <yes|no> */
        if ((sentinel.announce_hostnames = yesnotoi(argv[1])) == -1) {
            return "Please specify yes or not for the announce-hostnames option.";
        }
    } else {
        return "Unrecognized sentinel configuration statement.";
    }
    return NULL;
}

/* Implements CONFIG REWRITE for "sentinel" option.
 * This is used not just to rewrite the configuration given by the user
 * (the configured masters) but also in order to retain the state of
 * Sentinel across restarts: config epoch of masters, associated slaves
 * and sentinel instances, and so forth. */
void rewriteConfigSentinelOption(struct rewriteConfigState *state) {
    dictIterator *di, *di2;
    dictEntry *de;
    sds line;

    /* sentinel unique ID. */
    line = sdscatprintf(sdsempty(), "sentinel myid %s", sentinel.myid);
    rewriteConfigRewriteLine(state,"sentinel myid",line,1);

    /* sentinel deny-scripts-reconfig. */
    line = sdscatprintf(sdsempty(), "sentinel deny-scripts-reconfig %s",
        sentinel.deny_scripts_reconfig ? "yes" : "no");
    rewriteConfigRewriteLine(state,"sentinel deny-scripts-reconfig",line,
        sentinel.deny_scripts_reconfig != SENTINEL_DEFAULT_DENY_SCRIPTS_RECONFIG);

    /* sentinel resolve-hostnames.
     * This must be included early in the file so it is already in effect
     * when reading the file.
     */
    line = sdscatprintf(sdsempty(), "sentinel resolve-hostnames %s",
                        sentinel.resolve_hostnames ? "yes" : "no");
    rewriteConfigRewriteLine(state,"sentinel resolve-hostnames",line,
                             sentinel.resolve_hostnames != SENTINEL_DEFAULT_RESOLVE_HOSTNAMES);

    /* sentinel announce-hostnames. */
    line = sdscatprintf(sdsempty(), "sentinel announce-hostnames %s",
                        sentinel.announce_hostnames ? "yes" : "no");
    rewriteConfigRewriteLine(state,"sentinel announce-hostnames",line,
                             sentinel.announce_hostnames != SENTINEL_DEFAULT_ANNOUNCE_HOSTNAMES);

    /* For every master emit a "sentinel monitor" config entry. */
    di = dictGetIterator(sentinel.masters);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *master, *ri;
        sentinelAddr *master_addr;

        /* sentinel monitor */
        master = dictGetVal(de);
        master_addr = sentinelGetCurrentMasterAddress(master);
        line = sdscatprintf(sdsempty(),"sentinel monitor %s %s %d %d",
            master->name, announceSentinelAddr(master_addr), master_addr->port,
            master->quorum);
        rewriteConfigRewriteLine(state,"sentinel monitor",line,1);
        /* rewriteConfigMarkAsProcessed is handled after the loop */

        /* sentinel down-after-milliseconds */
        if (master->down_after_period != SENTINEL_DEFAULT_DOWN_AFTER) {
            line = sdscatprintf(sdsempty(),
                "sentinel down-after-milliseconds %s %ld",
                master->name, (long) master->down_after_period);
            rewriteConfigRewriteLine(state,"sentinel down-after-milliseconds",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }

        /* sentinel failover-timeout */
        if (master->failover_timeout != SENTINEL_DEFAULT_FAILOVER_TIMEOUT) {
            line = sdscatprintf(sdsempty(),
                "sentinel failover-timeout %s %ld",
                master->name, (long) master->failover_timeout);
            rewriteConfigRewriteLine(state,"sentinel failover-timeout",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */

        }

        /* sentinel parallel-syncs */
        if (master->parallel_syncs != SENTINEL_DEFAULT_PARALLEL_SYNCS) {
            line = sdscatprintf(sdsempty(),
                "sentinel parallel-syncs %s %d",
                master->name, master->parallel_syncs);
            rewriteConfigRewriteLine(state,"sentinel parallel-syncs",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }

        /* sentinel notification-script */
        if (master->notification_script) {
            line = sdscatprintf(sdsempty(),
                "sentinel notification-script %s %s",
                master->name, master->notification_script);
            rewriteConfigRewriteLine(state,"sentinel notification-script",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }

        /* sentinel client-reconfig-script */
        if (master->client_reconfig_script) {
            line = sdscatprintf(sdsempty(),
                "sentinel client-reconfig-script %s %s",
                master->name, master->client_reconfig_script);
            rewriteConfigRewriteLine(state,"sentinel client-reconfig-script",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }

        /* sentinel auth-pass & auth-user */
        if (master->auth_pass) {
            line = sdscatprintf(sdsempty(),
                "sentinel auth-pass %s %s",
                master->name, master->auth_pass);
            rewriteConfigRewriteLine(state,"sentinel auth-pass",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }

        if (master->auth_user) {
            line = sdscatprintf(sdsempty(),
                "sentinel auth-user %s %s",
                master->name, master->auth_user);
            rewriteConfigRewriteLine(state,"sentinel auth-user",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }

        /* sentinel config-epoch */
        line = sdscatprintf(sdsempty(),
            "sentinel config-epoch %s %llu",
            master->name, (unsigned long long) master->config_epoch);
        rewriteConfigRewriteLine(state,"sentinel config-epoch",line,1);
        /* rewriteConfigMarkAsProcessed is handled after the loop */


        /* sentinel leader-epoch */
        line = sdscatprintf(sdsempty(),
            "sentinel leader-epoch %s %llu",
            master->name, (unsigned long long) master->leader_epoch);
        rewriteConfigRewriteLine(state,"sentinel leader-epoch",line,1);
        /* rewriteConfigMarkAsProcessed is handled after the loop */

        /* sentinel known-slave */
        di2 = dictGetIterator(master->slaves);
        while((de = dictNext(di2)) != NULL) {
            sentinelAddr *slave_addr;

            ri = dictGetVal(de);
            slave_addr = ri->addr;

            /* If master_addr (obtained using sentinelGetCurrentMasterAddress()
             * so it may be the address of the promoted slave) is equal to this
             * slave's address, a failover is in progress and the slave was
             * already successfully promoted. So as the address of this slave
             * we use the old master address instead. */
            if (sentinelAddrIsEqual(slave_addr,master_addr))
                slave_addr = master->addr;
            line = sdscatprintf(sdsempty(),
                "sentinel known-replica %s %s %d",
                master->name, announceSentinelAddr(slave_addr), slave_addr->port);
            rewriteConfigRewriteLine(state,"sentinel known-replica",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }
        dictReleaseIterator(di2);

        /* sentinel known-sentinel */
        di2 = dictGetIterator(master->sentinels);
        while((de = dictNext(di2)) != NULL) {
            ri = dictGetVal(de);
            if (ri->runid == NULL) continue;
            line = sdscatprintf(sdsempty(),
                "sentinel known-sentinel %s %s %d %s",
                master->name, announceSentinelAddr(ri->addr), ri->addr->port, ri->runid);
            rewriteConfigRewriteLine(state,"sentinel known-sentinel",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }
        dictReleaseIterator(di2);

        /* sentinel rename-command */
        di2 = dictGetIterator(master->renamed_commands);
        while((de = dictNext(di2)) != NULL) {
            sds oldname = dictGetKey(de);
            sds newname = dictGetVal(de);
            line = sdscatprintf(sdsempty(),
                "sentinel rename-command %s %s %s",
                master->name, oldname, newname);
            rewriteConfigRewriteLine(state,"sentinel rename-command",line,1);
            /* rewriteConfigMarkAsProcessed is handled after the loop */
        }
        dictReleaseIterator(di2);
    }

    /* sentinel current-epoch is a global state valid for all the masters. */
    line = sdscatprintf(sdsempty(),
        "sentinel current-epoch %llu", (unsigned long long) sentinel.current_epoch);
    rewriteConfigRewriteLine(state,"sentinel current-epoch",line,1);

    /* sentinel announce-ip. */
    if (sentinel.announce_ip) {
        line = sdsnew("sentinel announce-ip ");
        line = sdscatrepr(line, sentinel.announce_ip, sdslen(sentinel.announce_ip));
        rewriteConfigRewriteLine(state,"sentinel announce-ip",line,1);
    } else {
        rewriteConfigMarkAsProcessed(state,"sentinel announce-ip");
    }

    /* sentinel announce-port. */
    if (sentinel.announce_port) {
        line = sdscatprintf(sdsempty(),"sentinel announce-port %d",
                            sentinel.announce_port);
        rewriteConfigRewriteLine(state,"sentinel announce-port",line,1);
    } else {
        rewriteConfigMarkAsProcessed(state,"sentinel announce-port");
    }

    /* sentinel sentinel-user. */
    if (sentinel.sentinel_auth_user) {
        line = sdscatprintf(sdsempty(), "sentinel sentinel-user %s", sentinel.sentinel_auth_user);
        rewriteConfigRewriteLine(state,"sentinel sentinel-user",line,1);
    } else {
        rewriteConfigMarkAsProcessed(state,"sentinel sentinel-user");
    }

    /* sentinel sentinel-pass. */
    if (sentinel.sentinel_auth_pass) {
        line = sdscatprintf(sdsempty(), "sentinel sentinel-pass %s", sentinel.sentinel_auth_pass);
        rewriteConfigRewriteLine(state,"sentinel sentinel-pass",line,1);
    } else {
        rewriteConfigMarkAsProcessed(state,"sentinel sentinel-pass");  
    }

    dictReleaseIterator(di);

    /* NOTE: the purpose here is in case due to the state change, the config rewrite 
     does not handle the configs, however, previously the config was set in the config file, 
     rewriteConfigMarkAsProcessed should be put here to mark it as processed in order to 
     delete the old config entry.
    */
    rewriteConfigMarkAsProcessed(state,"sentinel monitor");
    rewriteConfigMarkAsProcessed(state,"sentinel down-after-milliseconds");
    rewriteConfigMarkAsProcessed(state,"sentinel failover-timeout");
    rewriteConfigMarkAsProcessed(state,"sentinel parallel-syncs");
    rewriteConfigMarkAsProcessed(state,"sentinel notification-script");
    rewriteConfigMarkAsProcessed(state,"sentinel client-reconfig-script");
    rewriteConfigMarkAsProcessed(state,"sentinel auth-pass");
    rewriteConfigMarkAsProcessed(state,"sentinel auth-user");
    rewriteConfigMarkAsProcessed(state,"sentinel config-epoch");
    rewriteConfigMarkAsProcessed(state,"sentinel leader-epoch");
    rewriteConfigMarkAsProcessed(state,"sentinel known-replica");
    rewriteConfigMarkAsProcessed(state,"sentinel known-sentinel");
    rewriteConfigMarkAsProcessed(state,"sentinel rename-command");
}

/* This function uses the config rewriting Redis engine in order to persist
 * the state of the Sentinel in the current configuration file.
 * 
 * 此函数使用配置重写 Redis 引擎将 Sentinel 的状态持久化到当前配置文件中
 * 
 * Before returning the function calls fsync() against the generated
 * configuration file to make sure changes are committed to disk.
 * 
 * 返回之前，函数调用 fsync() 将生成的配置文件提交到磁盘
 * 
 * On failure the function logs a warning on the Redis log. 
 * 
 * 失败时，函数会在 Redis 日志中记录警告
 */
void sentinelFlushConfig(void) {
    int fd = -1;
    int saved_hz = server.hz;
    int rewrite_status;

    server.hz = CONFIG_DEFAULT_HZ;
    rewrite_status = rewriteConfig(server.configfile, 0);
    server.hz = saved_hz;

    if (rewrite_status == -1) goto werr;
    if ((fd = open(server.configfile,O_RDONLY)) == -1) goto werr;
    if (fsync(fd) == -1) goto werr;
    if (close(fd) == EOF) goto werr;
    return;

werr:
    if (fd != -1) close(fd);
    serverLog(LL_WARNING,"WARNING: Sentinel was not able to save the new configuration on disk!!!: %s", strerror(errno));
}

/* ====================== hiredis connection handling ======================= */

/* Send the AUTH command with the specified master password if needed.
 * Note that for slaves the password set for the master is used.
 *
 * In case this Sentinel requires a password as well, via the "requirepass"
 * configuration directive, we assume we should use the local password in
 * order to authenticate when connecting with the other Sentinels as well.
 * So basically all the Sentinels share the same password and use it to
 * authenticate reciprocally.
 *
 * We don't check at all if the command was successfully transmitted
 * to the instance as if it fails Sentinel will detect the instance down,
 * will disconnect and reconnect the link and so forth. */
void sentinelSendAuthIfNeeded(sentinelRedisInstance *ri, redisAsyncContext *c) {
    char *auth_pass = NULL;
    char *auth_user = NULL;

    if (ri->flags & SRI_MASTER) {
        auth_pass = ri->auth_pass;
        auth_user = ri->auth_user;
    } else if (ri->flags & SRI_SLAVE) {
        auth_pass = ri->master->auth_pass;
        auth_user = ri->master->auth_user;
    } else if (ri->flags & SRI_SENTINEL) {
        /* If sentinel_auth_user is NULL, AUTH will use default user
           with sentinel_auth_pass to authenticate */
        if (sentinel.sentinel_auth_pass) {
            auth_pass = sentinel.sentinel_auth_pass;
            auth_user = sentinel.sentinel_auth_user;
        } else {
            /* Compatibility with old configs. requirepass is used
             * for both incoming and outgoing authentication. */
            auth_pass = server.requirepass;
            auth_user = NULL;
        }
    }

    if (auth_pass && auth_user == NULL) {
        if (redisAsyncCommand(c, sentinelDiscardReplyCallback, ri, "%s %s",
            sentinelInstanceMapCommand(ri,"AUTH"),
            auth_pass) == C_OK) ri->link->pending_commands++;
    } else if (auth_pass && auth_user) {
        /* If we also have an username, use the ACL-style AUTH command
         * with two arguments, username and password. */
        if (redisAsyncCommand(c, sentinelDiscardReplyCallback, ri, "%s %s %s",
            sentinelInstanceMapCommand(ri,"AUTH"),
            auth_user, auth_pass) == C_OK) ri->link->pending_commands++;
    }
}

/* Use CLIENT SETNAME to name the connection in the Redis instance as
 * sentinel-<first_8_chars_of_runid>-<connection_type>
 * The connection type is "cmd" or "pubsub" as specified by 'type'.
 *
 * This makes it possible to list all the sentinel instances connected
 * to a Redis server with CLIENT LIST, grepping for a specific name format. */
void sentinelSetClientName(sentinelRedisInstance *ri, redisAsyncContext *c, char *type) {
    char name[64];

    snprintf(name,sizeof(name),"sentinel-%.8s-%s",sentinel.myid,type);
    if (redisAsyncCommand(c, sentinelDiscardReplyCallback, ri,
        "%s SETNAME %s",
        sentinelInstanceMapCommand(ri,"CLIENT"),
        name) == C_OK)
    {
        ri->link->pending_commands++;
    }
}

static int instanceLinkNegotiateTLS(redisAsyncContext *context) {
#ifndef USE_OPENSSL
    (void) context;
#else
    if (!redis_tls_ctx) return C_ERR;
    SSL *ssl = SSL_new(redis_tls_client_ctx ? redis_tls_client_ctx : redis_tls_ctx);
    if (!ssl) return C_ERR;

    if (redisInitiateSSL(&context->c, ssl) == REDIS_ERR) return C_ERR;
#endif
    return C_OK;
}

/* Create the async connections for the instance link if the link
 * is disconnected. Note that link->disconnected is true even if just
 * one of the two links (commands and pub/sub) is missing. 
 * 
 * 如果 sentinel 与实例处于断线状态，那么创建连向实例的异步连接。
 * 注意:即使两个连接(命令连接和订阅连接)中的一个处于断线状态，那么 link->disconnected 为 true，
 * 即认为 sentinel 与实例处于断线状态
 */
void sentinelReconnectInstance(sentinelRedisInstance *ri) {
    // 没有断线，直接返回
    if (ri->link->disconnected == 0) return;
    // 端口号为 0，无效地址，直接返回
    if (ri->addr->port == 0) return; /* port == 0 means invalid address. */
    instanceLink *link = ri->link;
    mstime_t now = mstime();
    // 如果当前时间与上次建立连接的时间差小于 SENTINEL_PING_PERIOD=1 秒，则直接返回
    if (now - ri->link->last_reconn_time < SENTINEL_PING_PERIOD) return;
    // 记录 sentinel 与实例建立连接的时间 
    ri->link->last_reconn_time = now;

    /* Commands connection. 
     * 创建 sentinel 与实例之间的命令连接，
     * 用于发送 redis 命令
     */
    if (link->cc == NULL) {
        // 连接实例
        link->cc = redisAsyncConnectBind(ri->addr->ip,ri->addr->port,NET_FIRST_BIND_ADDR);
        if (!link->cc->err) anetCloexec(link->cc->c.fd);
        if (!link->cc->err && server.tls_replication &&
                (instanceLinkNegotiateTLS(link->cc) == C_ERR)) {
            sentinelEvent(LL_DEBUG,"-cmd-link-reconnection",ri,"%@ #Failed to initialize TLS");
            instanceLinkCloseConnection(link,link->cc);
        } else if (link->cc->err) {
            sentinelEvent(LL_DEBUG,"-cmd-link-reconnection",ri,"%@ #%s",
                link->cc->errstr);
            instanceLinkCloseConnection(link,link->cc);
        } else {
            // 设置连接属性
            link->pending_commands = 0;
            link->cc_conn_time = mstime();
            link->cc->data = link;
            redisAeAttach(server.el,link->cc);
            // 设置连接回调
            redisAsyncSetConnectCallback(link->cc,
                    sentinelLinkEstablishedCallback);
            // 设置断线回掉
            redisAsyncSetDisconnectCallback(link->cc,
                    sentinelDisconnectCallback);
            // 发送 AUTH 命令，验证身份
            sentinelSendAuthIfNeeded(ri,link->cc);
            sentinelSetClientName(ri,link->cc,"cmd");

            /* Send a PING ASAP when reconnecting. 
             * 重连后立即发送 PING 命令
             */
            sentinelSendPing(ri);
        }
    }
    /* Pub / Sub */
    // 对于 master 和 slave，创建一个订阅/发布连接
    if ((ri->flags & (SRI_MASTER|SRI_SLAVE)) && link->pc == NULL) {
        // 连接实例
        link->pc = redisAsyncConnectBind(ri->addr->ip,ri->addr->port,NET_FIRST_BIND_ADDR);
        if (!link->pc->err) anetCloexec(link->pc->c.fd);
        if (!link->pc->err && server.tls_replication &&
                (instanceLinkNegotiateTLS(link->pc) == C_ERR)) {
            sentinelEvent(LL_DEBUG,"-pubsub-link-reconnection",ri,"%@ #Failed to initialize TLS");
        } else if (link->pc->err) {
            sentinelEvent(LL_DEBUG,"-pubsub-link-reconnection",ri,"%@ #%s",
                link->pc->errstr);
            instanceLinkCloseConnection(link,link->pc);
        } else {
            // 设置连接属性
            int retval;
            link->pc_conn_time = mstime();
            link->pc->data = link;
            redisAeAttach(server.el,link->pc);
            // 设置连接回掉
            redisAsyncSetConnectCallback(link->pc,
                    sentinelLinkEstablishedCallback);
            // 设置断线回掉
            redisAsyncSetDisconnectCallback(link->pc,
                    sentinelDisconnectCallback);
            // 发送 AUTH 命令，验证身份
            sentinelSendAuthIfNeeded(ri,link->pc);
            sentinelSetClientName(ri,link->pc,"pubsub");
            /* Now we subscribe to the Sentinels "Hello" channel. 
             * 发送 SUBSCRIBE __sentinel__:hello 命令，订阅频道
             */
            retval = redisAsyncCommand(link->pc,
                sentinelReceiveHelloMessages, ri, "%s %s",
                sentinelInstanceMapCommand(ri,"SUBSCRIBE"),
                SENTINEL_HELLO_CHANNEL);
            // 订阅出错，断开连接
            if (retval != C_OK) {
                /* If we can't subscribe, the Pub/Sub connection is useless
                 * and we can simply disconnect it and try again. */
                instanceLinkCloseConnection(link,link->pc);
                return;
            }
        }
    }
    /* Clear the disconnected status only if we have both the connections
     * (or just the commands connection if this is a sentinel instance).
     * 当实例是 master 或 slave 时，当命令连接和订阅连接都创建成功时，将连接状态标记为连接
     * 当实例是 sentinel时，当订阅连接都创建成功时，将连接状态标记为连接
     */
    if (link->cc && (ri->flags & SRI_SENTINEL || link->pc))
        link->disconnected = 0;
}

/* ======================== Redis instances pinging  ======================== */

/* Return true if master looks "sane", that is:
 * 1) It is actually a master in the current configuration.
 * 2) It reports itself as a master.
 * 3) It is not SDOWN or ODOWN.
 * 4) We obtained last INFO no more than two times the INFO period time ago. */
int sentinelMasterLooksSane(sentinelRedisInstance *master) {
    return
        master->flags & SRI_MASTER &&
        master->role_reported == SRI_MASTER &&
        (master->flags & (SRI_S_DOWN|SRI_O_DOWN)) == 0 &&
        (mstime() - master->info_refresh) < SENTINEL_INFO_PERIOD*2;
}

/* Process the INFO output from masters. 
 * 处理 master 或 slave 返回的 INFO 命令回复信息
 */
void sentinelRefreshInstanceInfo(sentinelRedisInstance *ri, const char *info) {
    sds *lines;
    int numlines, j;
    int role = 0;

    /* cache full INFO output for instance */
    sdsfree(ri->info);
    ri->info = sdsnew(info);

    /* The following fields must be reset to a given value in the case they
     * are not found at all in the INFO output. */
    ri->master_link_down_time = 0;

    /* Process line by line. */
    lines = sdssplitlen(info,strlen(info),"\r\n",2,&numlines);
    for (j = 0; j < numlines; j++) {
        sentinelRedisInstance *slave;
        sds l = lines[j];

        /* run_id:<40 hex chars>*/
        if (sdslen(l) >= 47 && !memcmp(l,"run_id:",7)) {
            if (ri->runid == NULL) {
                ri->runid = sdsnewlen(l+7,40);
            } else {
                if (strncmp(ri->runid,l+7,40) != 0) {
                    sentinelEvent(LL_NOTICE,"+reboot",ri,"%@");
                    sdsfree(ri->runid);
                    ri->runid = sdsnewlen(l+7,40);
                }
            }
        }

        /* old versions: slave0:<ip>,<port>,<state>
         * new versions: slave0:ip=127.0.0.1,port=9999,... */
        if ((ri->flags & SRI_MASTER) &&
            sdslen(l) >= 7 &&
            !memcmp(l,"slave",5) && isdigit(l[5]))
        {
            char *ip, *port, *end;

            if (strstr(l,"ip=") == NULL) {
                /* Old format. */
                ip = strchr(l,':'); if (!ip) continue;
                ip++; /* Now ip points to start of ip address. */
                port = strchr(ip,','); if (!port) continue;
                *port = '\0'; /* nul term for easy access. */
                port++; /* Now port points to start of port number. */
                end = strchr(port,','); if (!end) continue;
                *end = '\0'; /* nul term for easy access. */
            } else {
                /* New format. */
                ip = strstr(l,"ip="); if (!ip) continue;
                ip += 3; /* Now ip points to start of ip address. */
                port = strstr(l,"port="); if (!port) continue;
                port += 5; /* Now port points to start of port number. */
                /* Nul term both fields for easy access. */
                end = strchr(ip,','); if (end) *end = '\0';
                end = strchr(port,','); if (end) *end = '\0';
            }

            /* Check if we already have this slave into our table,
             * otherwise add it. */
            if (sentinelRedisInstanceLookupSlave(ri,ip,atoi(port)) == NULL) {
                if ((slave = createSentinelRedisInstance(NULL,SRI_SLAVE,ip,
                            atoi(port), ri->quorum, ri)) != NULL)
                {
                    sentinelEvent(LL_NOTICE,"+slave",slave,"%@");
                    sentinelFlushConfig();
                }
            }
        }

        /* master_link_down_since_seconds:<seconds> */
        if (sdslen(l) >= 32 &&
            !memcmp(l,"master_link_down_since_seconds",30))
        {
            ri->master_link_down_time = strtoll(l+31,NULL,10)*1000;
        }

        /* role:<role> */
        if (sdslen(l) >= 11 && !memcmp(l,"role:master",11)) role = SRI_MASTER;
        else if (sdslen(l) >= 10 && !memcmp(l,"role:slave",10)) role = SRI_SLAVE;

        if (role == SRI_SLAVE) {
            /* master_host:<host> */
            if (sdslen(l) >= 12 && !memcmp(l,"master_host:",12)) {
                if (ri->slave_master_host == NULL ||
                    strcasecmp(l+12,ri->slave_master_host))
                {
                    sdsfree(ri->slave_master_host);
                    ri->slave_master_host = sdsnew(l+12);
                    ri->slave_conf_change_time = mstime();
                }
            }

            /* master_port:<port> */
            if (sdslen(l) >= 12 && !memcmp(l,"master_port:",12)) {
                int slave_master_port = atoi(l+12);

                if (ri->slave_master_port != slave_master_port) {
                    ri->slave_master_port = slave_master_port;
                    ri->slave_conf_change_time = mstime();
                }
            }

            /* master_link_status:<status> */
            if (sdslen(l) >= 19 && !memcmp(l,"master_link_status:",19)) {
                ri->slave_master_link_status =
                    (strcasecmp(l+19,"up") == 0) ?
                    SENTINEL_MASTER_LINK_STATUS_UP :
                    SENTINEL_MASTER_LINK_STATUS_DOWN;
            }

            /* slave_priority:<priority> */
            if (sdslen(l) >= 15 && !memcmp(l,"slave_priority:",15))
                ri->slave_priority = atoi(l+15);

            /* slave_repl_offset:<offset> */
            if (sdslen(l) >= 18 && !memcmp(l,"slave_repl_offset:",18))
                ri->slave_repl_offset = strtoull(l+18,NULL,10);
        }
    }
    ri->info_refresh = mstime();
    sdsfreesplitres(lines,numlines);

    /* ---------------------------- Acting half -----------------------------
     * Some things will not happen if sentinel.tilt is true, but some will
     * still be processed. */

    /* Remember when the role changed. */
    if (role != ri->role_reported) {
        ri->role_reported_time = mstime();
        ri->role_reported = role;
        if (role == SRI_SLAVE) ri->slave_conf_change_time = mstime();
        /* Log the event with +role-change if the new role is coherent or
         * with -role-change if there is a mismatch with the current config. */
        sentinelEvent(LL_VERBOSE,
            ((ri->flags & (SRI_MASTER|SRI_SLAVE)) == role) ?
            "+role-change" : "-role-change",
            ri, "%@ new reported role is %s",
            role == SRI_MASTER ? "master" : "slave",
            ri->flags & SRI_MASTER ? "master" : "slave");
    }

    /* None of the following conditions are processed when in tilt mode, so
     * return asap. */
    if (sentinel.tilt) return;

    /* Handle master -> slave role switch. */
    if ((ri->flags & SRI_MASTER) && role == SRI_SLAVE) {
        /* Nothing to do, but masters claiming to be slaves are
         * considered to be unreachable by Sentinel, so eventually
         * a failover will be triggered. */
    }

    /* Handle slave -> master role switch. */
    if ((ri->flags & SRI_SLAVE) && role == SRI_MASTER) {
        /* If this is a promoted slave we can change state to the
         * failover state machine. */
        if ((ri->flags & SRI_PROMOTED) &&
            (ri->master->flags & SRI_FAILOVER_IN_PROGRESS) &&
            (ri->master->failover_state ==
                SENTINEL_FAILOVER_STATE_WAIT_PROMOTION))
        {
            /* Now that we are sure the slave was reconfigured as a master
             * set the master configuration epoch to the epoch we won the
             * election to perform this failover. This will force the other
             * Sentinels to update their config (assuming there is not
             * a newer one already available). */
            ri->master->config_epoch = ri->master->failover_epoch;
            ri->master->failover_state = SENTINEL_FAILOVER_STATE_RECONF_SLAVES;
            ri->master->failover_state_change_time = mstime();
            sentinelFlushConfig();
            sentinelEvent(LL_WARNING,"+promoted-slave",ri,"%@");
            if (sentinel.simfailure_flags &
                SENTINEL_SIMFAILURE_CRASH_AFTER_PROMOTION)
                sentinelSimFailureCrash();
            sentinelEvent(LL_WARNING,"+failover-state-reconf-slaves",
                ri->master,"%@");
            sentinelCallClientReconfScript(ri->master,SENTINEL_LEADER,
                "start",ri->master->addr,ri->addr);
            sentinelForceHelloUpdateForMaster(ri->master);
        } else {
            /* A slave turned into a master. We want to force our view and
             * reconfigure as slave. Wait some time after the change before
             * going forward, to receive new configs if any. */
            mstime_t wait_time = SENTINEL_PUBLISH_PERIOD*4;

            if (!(ri->flags & SRI_PROMOTED) &&
                 sentinelMasterLooksSane(ri->master) &&
                 sentinelRedisInstanceNoDownFor(ri,wait_time) &&
                 mstime() - ri->role_reported_time > wait_time)
            {
                int retval = sentinelSendSlaveOf(ri,ri->master->addr);
                if (retval == C_OK)
                    sentinelEvent(LL_NOTICE,"+convert-to-slave",ri,"%@");
            }
        }
    }

    /* Handle slaves replicating to a different master address. */
    if ((ri->flags & SRI_SLAVE) &&
        role == SRI_SLAVE &&
        (ri->slave_master_port != ri->master->addr->port ||
         !sentinelAddrEqualsHostname(ri->master->addr, ri->slave_master_host)))
    {
        mstime_t wait_time = ri->master->failover_timeout;

        /* Make sure the master is sane before reconfiguring this instance
         * into a slave. */
        if (sentinelMasterLooksSane(ri->master) &&
            sentinelRedisInstanceNoDownFor(ri,wait_time) &&
            mstime() - ri->slave_conf_change_time > wait_time)
        {
            int retval = sentinelSendSlaveOf(ri,ri->master->addr);
            if (retval == C_OK)
                sentinelEvent(LL_NOTICE,"+fix-slave-config",ri,"%@");
        }
    }

    /* Detect if the slave that is in the process of being reconfigured
     * changed state. */
    if ((ri->flags & SRI_SLAVE) && role == SRI_SLAVE &&
        (ri->flags & (SRI_RECONF_SENT|SRI_RECONF_INPROG)))
    {
        /* SRI_RECONF_SENT -> SRI_RECONF_INPROG. */
        if ((ri->flags & SRI_RECONF_SENT) &&
            ri->slave_master_host &&
            sentinelAddrEqualsHostname(ri->master->promoted_slave->addr,
                ri->slave_master_host) &&
            ri->slave_master_port == ri->master->promoted_slave->addr->port)
        {
            ri->flags &= ~SRI_RECONF_SENT;
            ri->flags |= SRI_RECONF_INPROG;
            sentinelEvent(LL_NOTICE,"+slave-reconf-inprog",ri,"%@");
        }

        /* SRI_RECONF_INPROG -> SRI_RECONF_DONE */
        if ((ri->flags & SRI_RECONF_INPROG) &&
            ri->slave_master_link_status == SENTINEL_MASTER_LINK_STATUS_UP)
        {
            ri->flags &= ~SRI_RECONF_INPROG;
            ri->flags |= SRI_RECONF_DONE;
            sentinelEvent(LL_NOTICE,"+slave-reconf-done",ri,"%@");
        }
    }
}

void sentinelInfoReplyCallback(redisAsyncContext *c, void *reply, void *privdata) {
    sentinelRedisInstance *ri = privdata;
    instanceLink *link = c->data;
    redisReply *r;

    if (!reply || !link) return;
    link->pending_commands--;
    r = reply;

    if (r->type == REDIS_REPLY_STRING)
        sentinelRefreshInstanceInfo(ri,r->str);
}

/* Just discard the reply. We use this when we are not monitoring the return
 * value of the command but its effects directly. */
void sentinelDiscardReplyCallback(redisAsyncContext *c, void *reply, void *privdata) {
    instanceLink *link = c->data;
    UNUSED(reply);
    UNUSED(privdata);

    if (link) link->pending_commands--;
}

void sentinelPingReplyCallback(redisAsyncContext *c, void *reply, void *privdata) {
    sentinelRedisInstance *ri = privdata;
    instanceLink *link = c->data;
    redisReply *r;

    if (!reply || !link) return;
    link->pending_commands--;
    r = reply;

    if (r->type == REDIS_REPLY_STATUS ||
        r->type == REDIS_REPLY_ERROR) {
        /* Update the "instance available" field only if this is an
         * acceptable reply. */
        if (strncmp(r->str,"PONG",4) == 0 ||
            strncmp(r->str,"LOADING",7) == 0 ||
            strncmp(r->str,"MASTERDOWN",10) == 0)
        {
            link->last_avail_time = mstime();
            link->act_ping_time = 0; /* Flag the pong as received. */
        } else {
            /* Send a SCRIPT KILL command if the instance appears to be
             * down because of a busy script. */
            if (strncmp(r->str,"BUSY",4) == 0 &&
                (ri->flags & SRI_S_DOWN) &&
                !(ri->flags & SRI_SCRIPT_KILL_SENT))
            {
                if (redisAsyncCommand(ri->link->cc,
                        sentinelDiscardReplyCallback, ri,
                        "%s KILL",
                        sentinelInstanceMapCommand(ri,"SCRIPT")) == C_OK)
                {
                    ri->link->pending_commands++;
                }
                ri->flags |= SRI_SCRIPT_KILL_SENT;
            }
        }
    }
    link->last_pong_time = mstime();
}

/* This is called when we get the reply about the PUBLISH command we send
 * to the master to advertise this sentinel. */
void sentinelPublishReplyCallback(redisAsyncContext *c, void *reply, void *privdata) {
    sentinelRedisInstance *ri = privdata;
    instanceLink *link = c->data;
    redisReply *r;

    if (!reply || !link) return;
    link->pending_commands--;
    r = reply;

    /* Only update pub_time if we actually published our message. Otherwise
     * we'll retry again in 100 milliseconds. */
    if (r->type != REDIS_REPLY_ERROR)
        ri->last_pub_time = mstime();
}

/* Process a hello message received via Pub/Sub in master or slave instance,
 * or sent directly to this sentinel via the (fake) PUBLISH command of Sentinel.
 *
 * If the master name specified in the message is not known, the message is
 * discarded. */
void sentinelProcessHelloMessage(char *hello, int hello_len) {
    /* Format is composed of 8 tokens:
     * 0=ip,1=port,2=runid,3=current_epoch,4=master_name,
     * 5=master_ip,6=master_port,7=master_config_epoch. */
    int numtokens, port, removed, master_port;
    uint64_t current_epoch, master_config_epoch;
    char **token = sdssplitlen(hello, hello_len, ",", 1, &numtokens);
    sentinelRedisInstance *si, *master;

    if (numtokens == 8) {
        /* Obtain a reference to the master this hello message is about */
        master = sentinelGetMasterByName(token[4]);
        if (!master) goto cleanup; /* Unknown master, skip the message. */

        /* First, try to see if we already have this sentinel. */
        port = atoi(token[1]);
        master_port = atoi(token[6]);
        si = getSentinelRedisInstanceByAddrAndRunID(
                        master->sentinels,token[0],port,token[2]);
        current_epoch = strtoull(token[3],NULL,10);
        master_config_epoch = strtoull(token[7],NULL,10);

        if (!si) {
            /* If not, remove all the sentinels that have the same runid
             * because there was an address change, and add the same Sentinel
             * with the new address back. */
            removed = removeMatchingSentinelFromMaster(master,token[2]);
            if (removed) {
                sentinelEvent(LL_NOTICE,"+sentinel-address-switch",master,
                    "%@ ip %s port %d for %s", token[0],port,token[2]);
            } else {
                /* Check if there is another Sentinel with the same address this
                 * new one is reporting. What we do if this happens is to set its
                 * port to 0, to signal the address is invalid. We'll update it
                 * later if we get an HELLO message. */
                sentinelRedisInstance *other =
                    getSentinelRedisInstanceByAddrAndRunID(
                        master->sentinels, token[0],port,NULL);
                if (other) {
                    sentinelEvent(LL_NOTICE,"+sentinel-invalid-addr",other,"%@");
                    other->addr->port = 0; /* It means: invalid address. */
                    sentinelUpdateSentinelAddressInAllMasters(other);
                }
            }

            /* Add the new sentinel. */
            si = createSentinelRedisInstance(token[2],SRI_SENTINEL,
                            token[0],port,master->quorum,master);

            if (si) {
                if (!removed) sentinelEvent(LL_NOTICE,"+sentinel",si,"%@");
                /* The runid is NULL after a new instance creation and
                 * for Sentinels we don't have a later chance to fill it,
                 * so do it now. */
                si->runid = sdsnew(token[2]);
                sentinelTryConnectionSharing(si);
                if (removed) sentinelUpdateSentinelAddressInAllMasters(si);
                sentinelFlushConfig();
            }
        }

        /* Update local current_epoch if received current_epoch is greater.*/
        if (current_epoch > sentinel.current_epoch) {
            sentinel.current_epoch = current_epoch;
            sentinelFlushConfig();
            sentinelEvent(LL_WARNING,"+new-epoch",master,"%llu",
                (unsigned long long) sentinel.current_epoch);
        }

        /* Update master info if received configuration is newer. */
        if (si && master->config_epoch < master_config_epoch) {
            master->config_epoch = master_config_epoch;
            if (master_port != master->addr->port ||
                !sentinelAddrEqualsHostname(master->addr, token[5]))
            {
                sentinelAddr *old_addr;

                sentinelEvent(LL_WARNING,"+config-update-from",si,"%@");
                sentinelEvent(LL_WARNING,"+switch-master",
                    master,"%s %s %d %s %d",
                    master->name,
                    announceSentinelAddr(master->addr), master->addr->port,
                    token[5], master_port);

                old_addr = dupSentinelAddr(master->addr);
                sentinelResetMasterAndChangeAddress(master, token[5], master_port);
                sentinelCallClientReconfScript(master,
                    SENTINEL_OBSERVER,"start",
                    old_addr,master->addr);
                releaseSentinelAddr(old_addr);
            }
        }

        /* Update the state of the Sentinel. */
        if (si) si->last_hello_time = mstime();
    }

cleanup:
    sdsfreesplitres(token,numtokens);
}


/* This is our Pub/Sub callback for the Hello channel. It's useful in order
 * to discover other sentinels attached at the same master. */
void sentinelReceiveHelloMessages(redisAsyncContext *c, void *reply, void *privdata) {
    sentinelRedisInstance *ri = privdata;
    redisReply *r;
    UNUSED(c);

    if (!reply || !ri) return;
    r = reply;

    /* Update the last activity in the pubsub channel. Note that since we
     * receive our messages as well this timestamp can be used to detect
     * if the link is probably disconnected even if it seems otherwise. */
    ri->link->pc_last_activity = mstime();

    /* Sanity check in the reply we expect, so that the code that follows
     * can avoid to check for details. */
    if (r->type != REDIS_REPLY_ARRAY ||
        r->elements != 3 ||
        r->element[0]->type != REDIS_REPLY_STRING ||
        r->element[1]->type != REDIS_REPLY_STRING ||
        r->element[2]->type != REDIS_REPLY_STRING ||
        strcmp(r->element[0]->str,"message") != 0) return;

    /* We are not interested in meeting ourselves */
    if (strstr(r->element[2]->str,sentinel.myid) != NULL) return;

    sentinelProcessHelloMessage(r->element[2]->str, r->element[2]->len);
}

/* Send a "Hello" message via Pub/Sub to the specified 'ri' Redis
 * instance in order to broadcast the current configuration for this
 * master, and to advertise the existence of this Sentinel at the same time.
 *
 * 向指定的实例的指定频道发送消息，以此广播当前 master 的配置，
 * 同时告知其它 Sentinel 本 Sentinel 的存在
 * 
 * The message has the following format:
 * 
 * 发送的消息的格式如下:
 *
 * sentinel_ip,sentinel_port,sentinel_runid,current_epoch,
 * master_name,master_ip,master_port,master_config_epoch.
 *
 * Sentinel 的 ip,Sentinel 的端口号, Sentinel 的运行 ID,Sentinel 当前的纪元,
 * Master 的名字,Master 的 ip,Master 的端口号,Master 的配置纪元
 * 
 * Returns C_OK if the PUBLISH was queued correctly, otherwise
 * C_ERR is returned. 
 * 如果 PUBLISH 命令成功入队，则返回 C_OK
 * 否则返回 C_ERR
 */
int sentinelSendHello(sentinelRedisInstance *ri) {
    char ip[NET_IP_STR_LEN];
    char payload[NET_IP_STR_LEN+1024];
    int retval;
    char *announce_ip;
    int announce_port;
    /*
     * 如果此实例是 Master,则直接使用此实例
     * 如果此实例是 Slave 或 Sentinel，则使用这个实例的 Master
     */
    sentinelRedisInstance *master = (ri->flags & SRI_MASTER) ? ri : ri->master;

    // 获取 Master 的地址
    sentinelAddr *master_addr = sentinelGetCurrentMasterAddress(master);

    if (ri->link->disconnected) return C_ERR;

    /* Use the specified announce address if specified, otherwise try to
     * obtain our own IP address. 
     * 使用指定的公告 ip
     */
    if (sentinel.announce_ip) {
        announce_ip = sentinel.announce_ip;
    } else {
        /*
         * 获取实例自身 ip
         */
        if (anetFdToString(ri->link->cc->c.fd,ip,sizeof(ip),NULL,FD_TO_SOCK_NAME) == -1)
            return C_ERR;
        announce_ip = ip;
    }
    /*
     * 使用公告的端口
     */
    if (sentinel.announce_port) announce_port = sentinel.announce_port;
    else if (server.tls_replication && server.tls_port) announce_port = server.tls_port;
    else announce_port = server.port;

    /* Format and send the Hello message. 
     * 格式化要发送的 Hello 消息
     */
    snprintf(payload,sizeof(payload),
        "%s,%d,%s,%llu," /* Info about this sentinel. */
        "%s,%s,%d,%llu", /* Info about current master. */
        announce_ip, announce_port, sentinel.myid,
        (unsigned long long) sentinel.current_epoch,
        /* --- */
        master->name,announceSentinelAddr(master_addr),master_addr->port,
        (unsigned long long) master->config_epoch);
    retval = redisAsyncCommand(ri->link->cc,
        sentinelPublishReplyCallback, ri, "%s %s %s",
        sentinelInstanceMapCommand(ri,"PUBLISH"),
        SENTINEL_HELLO_CHANNEL,payload);
    if (retval != C_OK) return C_ERR;
    ri->link->pending_commands++;
    return C_OK;
}

/* Reset last_pub_time in all the instances in the specified dictionary
 * in order to force the delivery of a Hello update ASAP. */
void sentinelForceHelloUpdateDictOfRedisInstances(dict *instances) {
    dictIterator *di;
    dictEntry *de;

    di = dictGetSafeIterator(instances);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        if (ri->last_pub_time >= (SENTINEL_PUBLISH_PERIOD+1))
            ri->last_pub_time -= (SENTINEL_PUBLISH_PERIOD+1);
    }
    dictReleaseIterator(di);
}

/* This function forces the delivery of a "Hello" message (see
 * sentinelSendHello() top comment for further information) to all the Redis
 * and Sentinel instances related to the specified 'master'.
 *
 * It is technically not needed since we send an update to every instance
 * with a period of SENTINEL_PUBLISH_PERIOD milliseconds, however when a
 * Sentinel upgrades a configuration it is a good idea to deliver an update
 * to the other Sentinels ASAP. */
int sentinelForceHelloUpdateForMaster(sentinelRedisInstance *master) {
    if (!(master->flags & SRI_MASTER)) return C_ERR;
    if (master->last_pub_time >= (SENTINEL_PUBLISH_PERIOD+1))
        master->last_pub_time -= (SENTINEL_PUBLISH_PERIOD+1);
    sentinelForceHelloUpdateDictOfRedisInstances(master->sentinels);
    sentinelForceHelloUpdateDictOfRedisInstances(master->slaves);
    return C_OK;
}

/* Send a PING to the specified instance and refresh the act_ping_time
 * if it is zero (that is, if we received a pong for the previous ping).
 *
 * 发送 PING 命令到指定的实例，如果 act_ping_time 是的值是 0，则刷新它的值
 * 
 * On error zero is returned, and we can't consider the PING command
 * queued in the connection. */
int sentinelSendPing(sentinelRedisInstance *ri) {
    int retval = redisAsyncCommand(ri->link->cc,
        sentinelPingReplyCallback, ri, "%s",
        sentinelInstanceMapCommand(ri,"PING"));
    if (retval == C_OK) {
        ri->link->pending_commands++;
        ri->link->last_ping_time = mstime();
        /* We update the active ping time only if we received the pong for
         * the previous ping, otherwise we are technically waiting since the
         * first ping that did not receive a reply. */
        if (ri->link->act_ping_time == 0)
            ri->link->act_ping_time = ri->link->last_ping_time;
        return 1;
    } else {
        return 0;
    }
}

/* Send periodic PING, INFO, and PUBLISH to the Hello channel to
 * the specified master or slave instance. 
 * 定期向指定的 master 或 slave 实例发送 PING、INFO 命令和向 Hello 通道
 * 发送 PUBLISH 命令。
 */
void sentinelSendPeriodicCommands(sentinelRedisInstance *ri) {
    mstime_t now = mstime();
    mstime_t info_period, ping_period;
    int retval;

    /* Return ASAP if we have already a PING or INFO already pending, or
     * in the case the instance is not properly connected. 
     * 如果连接状态为断开状态，则立即返回
     */
    if (ri->link->disconnected) return;

    /* For INFO, PING, PUBLISH that are not critical commands to send we
     * also have a limit of SENTINEL_MAX_PENDING_COMMANDS. We don't
     * want to use a lot of memory just because a link is not working
     * properly (note that anyway there is a redundant protection about this,
     * that is, the link will be disconnected and reconnected if a long
     * timeout condition is detected.
     * 
     * 为了避免 sentinel 在实例处于不正常状态时，发送过多命令，
     * sentinel 只在等待回复的命令数量未超过 SENTINEL_MAX_PENDING_COMMANDS * 监视的实例数量
     * 常量时，才进行命令发送
     */
    if (ri->link->pending_commands >=
        SENTINEL_MAX_PENDING_COMMANDS * ri->link->refcount) return;

    /* If this is a slave of a master in O_DOWN condition we start sending
     * it INFO every second, instead of the usual SENTINEL_INFO_PERIOD
     * period. In this state we want to closely monitor slaves in case they
     * are turned into masters by another Sentinel, or by the sysadmin.
     *
     * Similarly we monitor the INFO output more often if the slave reports
     * to be disconnected from the master, so that we can have a fresh
     * disconnection time figure. 
     * 默认每 SENTINEL_INFO_PERIOD=10 秒向 master 和 slave 发送一次 INFO 命令，
     * 但是当 slave 的 master 处于 SRI_O_DOWN 状态或正在执行故障转移时，为了
     * 更快捕获 slave 的变动，sentinel 会将发送 INFO 命令的频率调整为每秒一次
     */
    if ((ri->flags & SRI_SLAVE) &&
        ((ri->master->flags & (SRI_O_DOWN|SRI_FAILOVER_IN_PROGRESS)) ||
         (ri->master_link_down_time != 0)))
    {
        info_period = 1000;
    } else {
        info_period = SENTINEL_INFO_PERIOD;
    }

    /* We ping instances every time the last received pong is older than
     * the configured 'down-after-milliseconds' time, but every second
     * anyway if 'down-after-milliseconds' is greater than 1 second. 
     * 如果配置的 down-after-milliseconds 毫秒 比 SENTINEL_PING_PERIOD=1 秒大，
     * 则将 ping 周期设置为 SENTINEL_PING_PERIOD=1 秒，否则将 ping 周期设置
     * 为 down-after-milliseconds 毫秒
     */
    ping_period = ri->down_after_period;
    if (ping_period > SENTINEL_PING_PERIOD) ping_period = SENTINEL_PING_PERIOD;

    /* Send INFO to masters and slaves, not sentinels. 
     * 满足以下其中一个条件向 master 和 slave 发送 INFO 命令
     * 1.sentinel 未收到过这个实例的 INFO 命令回复
     * 2.距离 sentinel 上次收到实例回复 INFO 命令的时间已经超过 info_period
     */
    if ((ri->flags & SRI_SENTINEL) == 0 &&
        (ri->info_refresh == 0 ||
        (now - ri->info_refresh) > info_period))
    {
        retval = redisAsyncCommand(ri->link->cc,
            sentinelInfoReplyCallback, ri, "%s",
            sentinelInstanceMapCommand(ri,"INFO"));
        if (retval == C_OK) ri->link->pending_commands++;
    }

    /* Send PING to all the three kinds of instances. 
     * 满足以下条件向所有实例发送 PING 命令
     * 1.距离 sentinel 上次收到实例回复 PING 命令的时间已经超过 ping_period
     * 2.距离 sentinel 上次发送 PING 命令的时间已经超过 ping_period/2
     */
    if ((now - ri->link->last_pong_time) > ping_period &&
               (now - ri->link->last_ping_time) > ping_period/2) {
        sentinelSendPing(ri);
    }

    /* PUBLISH hello messages to all the three kinds of instances. 
     * 满足以下条件向所有实例发送 PUBLISH 命令
     * 1. 距离 sentinel 上次发送 PUBLISH 命令的时间已经超过 SENTINEL_PUBLISH_PERIOD=2 秒
     */
    if ((now - ri->last_pub_time) > SENTINEL_PUBLISH_PERIOD) {
        sentinelSendHello(ri);
    }
}

/* =========================== SENTINEL command ============================= */

/* SENTINEL CONFIG SET <option> */
void sentinelConfigSetCommand(client *c) {
    robj *o = c->argv[3];
    robj *val = c->argv[4];
    long long numval;
    int drop_conns = 0;

    if (!strcasecmp(o->ptr, "resolve-hostnames")) {
        if ((numval = yesnotoi(val->ptr)) == -1) goto badfmt;
        sentinel.resolve_hostnames = numval;
    } else if (!strcasecmp(o->ptr, "announce-hostnames")) {
        if ((numval = yesnotoi(val->ptr)) == -1) goto badfmt;
        sentinel.announce_hostnames = numval;
    } else if (!strcasecmp(o->ptr, "announce-ip")) {
        if (sentinel.announce_ip) sdsfree(sentinel.announce_ip);
        sentinel.announce_ip = sdsnew(val->ptr);
    } else if (!strcasecmp(o->ptr, "announce-port")) {
        if (getLongLongFromObject(val, &numval) == C_ERR ||
            numval < 0 || numval > 65535)
            goto badfmt;
        sentinel.announce_port = numval;
    } else if (!strcasecmp(o->ptr, "sentinel-user")) {
        sdsfree(sentinel.sentinel_auth_user);
        sentinel.sentinel_auth_user = sdsnew(val->ptr);
        drop_conns = 1;
    } else if (!strcasecmp(o->ptr, "sentinel-pass")) {
        sdsfree(sentinel.sentinel_auth_pass);
        sentinel.sentinel_auth_pass = sdsnew(val->ptr);
        drop_conns = 1;
    } else {
        addReplyErrorFormat(c, "Invalid argument '%s' to SENTINEL CONFIG SET",
                            (char *) o->ptr);
        return;
    }

    sentinelFlushConfig();
    addReply(c, shared.ok);

    /* Drop Sentinel connections to initiate a reconnect if needed. */
    if (drop_conns)
        sentinelDropConnections();

    return;

badfmt:
    addReplyErrorFormat(c, "Invalid value '%s' to SENTINEL CONFIG SET '%s'",
                        (char *) val->ptr, (char *) o->ptr);
}

/* SENTINEL CONFIG GET <option> */
void sentinelConfigGetCommand(client *c) {
    robj *o = c->argv[3];
    const char *pattern = o->ptr;
    void *replylen = addReplyDeferredLen(c);
    int matches = 0;

    if (stringmatch(pattern,"resolve-hostnames",1)) {
        addReplyBulkCString(c,"resolve-hostnames");
        addReplyBulkCString(c,sentinel.resolve_hostnames ? "yes" : "no");
        matches++;
    }

    if (stringmatch(pattern, "announce-hostnames", 1)) {
        addReplyBulkCString(c,"announce-hostnames");
        addReplyBulkCString(c,sentinel.announce_hostnames ? "yes" : "no");
        matches++;
    }

    if (stringmatch(pattern, "announce-ip", 1)) {
        addReplyBulkCString(c,"announce-ip");
        addReplyBulkCString(c,sentinel.announce_ip ? sentinel.announce_ip : "");
        matches++;
    }

    if (stringmatch(pattern, "announce-port", 1)) {
        addReplyBulkCString(c, "announce-port");
        addReplyBulkLongLong(c, sentinel.announce_port);
        matches++;
    }

    if (stringmatch(pattern, "sentinel-user", 1)) {
        addReplyBulkCString(c, "sentinel-user");
        addReplyBulkCString(c, sentinel.sentinel_auth_user ? sentinel.sentinel_auth_user : "");
        matches++;
    }

    if (stringmatch(pattern, "sentinel-pass", 1)) {
        addReplyBulkCString(c, "sentinel-pass");
        addReplyBulkCString(c, sentinel.sentinel_auth_pass ? sentinel.sentinel_auth_pass : "");
        matches++;
    }

    setDeferredMapLen(c, replylen, matches);
}

const char *sentinelFailoverStateStr(int state) {
    switch(state) {
    case SENTINEL_FAILOVER_STATE_NONE: return "none";
    case SENTINEL_FAILOVER_STATE_WAIT_START: return "wait_start";
    case SENTINEL_FAILOVER_STATE_SELECT_SLAVE: return "select_slave";
    case SENTINEL_FAILOVER_STATE_SEND_SLAVEOF_NOONE: return "send_slaveof_noone";
    case SENTINEL_FAILOVER_STATE_WAIT_PROMOTION: return "wait_promotion";
    case SENTINEL_FAILOVER_STATE_RECONF_SLAVES: return "reconf_slaves";
    case SENTINEL_FAILOVER_STATE_UPDATE_CONFIG: return "update_config";
    default: return "unknown";
    }
}

/* Redis instance to Redis protocol representation. */
void addReplySentinelRedisInstance(client *c, sentinelRedisInstance *ri) {
    char *flags = sdsempty();
    void *mbl;
    int fields = 0;

    mbl = addReplyDeferredLen(c);

    addReplyBulkCString(c,"name");
    addReplyBulkCString(c,ri->name);
    fields++;

    addReplyBulkCString(c,"ip");
    addReplyBulkCString(c,announceSentinelAddr(ri->addr));
    fields++;

    addReplyBulkCString(c,"port");
    addReplyBulkLongLong(c,ri->addr->port);
    fields++;

    addReplyBulkCString(c,"runid");
    addReplyBulkCString(c,ri->runid ? ri->runid : "");
    fields++;

    addReplyBulkCString(c,"flags");
    if (ri->flags & SRI_S_DOWN) flags = sdscat(flags,"s_down,");
    if (ri->flags & SRI_O_DOWN) flags = sdscat(flags,"o_down,");
    if (ri->flags & SRI_MASTER) flags = sdscat(flags,"master,");
    if (ri->flags & SRI_SLAVE) flags = sdscat(flags,"slave,");
    if (ri->flags & SRI_SENTINEL) flags = sdscat(flags,"sentinel,");
    if (ri->link->disconnected) flags = sdscat(flags,"disconnected,");
    if (ri->flags & SRI_MASTER_DOWN) flags = sdscat(flags,"master_down,");
    if (ri->flags & SRI_FAILOVER_IN_PROGRESS)
        flags = sdscat(flags,"failover_in_progress,");
    if (ri->flags & SRI_PROMOTED) flags = sdscat(flags,"promoted,");
    if (ri->flags & SRI_RECONF_SENT) flags = sdscat(flags,"reconf_sent,");
    if (ri->flags & SRI_RECONF_INPROG) flags = sdscat(flags,"reconf_inprog,");
    if (ri->flags & SRI_RECONF_DONE) flags = sdscat(flags,"reconf_done,");

    if (sdslen(flags) != 0) sdsrange(flags,0,-2); /* remove last "," */
    addReplyBulkCString(c,flags);
    sdsfree(flags);
    fields++;

    addReplyBulkCString(c,"link-pending-commands");
    addReplyBulkLongLong(c,ri->link->pending_commands);
    fields++;

    addReplyBulkCString(c,"link-refcount");
    addReplyBulkLongLong(c,ri->link->refcount);
    fields++;

    if (ri->flags & SRI_FAILOVER_IN_PROGRESS) {
        addReplyBulkCString(c,"failover-state");
        addReplyBulkCString(c,(char*)sentinelFailoverStateStr(ri->failover_state));
        fields++;
    }

    addReplyBulkCString(c,"last-ping-sent");
    addReplyBulkLongLong(c,
        ri->link->act_ping_time ? (mstime() - ri->link->act_ping_time) : 0);
    fields++;

    addReplyBulkCString(c,"last-ok-ping-reply");
    addReplyBulkLongLong(c,mstime() - ri->link->last_avail_time);
    fields++;

    addReplyBulkCString(c,"last-ping-reply");
    addReplyBulkLongLong(c,mstime() - ri->link->last_pong_time);
    fields++;

    if (ri->flags & SRI_S_DOWN) {
        addReplyBulkCString(c,"s-down-time");
        addReplyBulkLongLong(c,mstime()-ri->s_down_since_time);
        fields++;
    }

    if (ri->flags & SRI_O_DOWN) {
        addReplyBulkCString(c,"o-down-time");
        addReplyBulkLongLong(c,mstime()-ri->o_down_since_time);
        fields++;
    }

    addReplyBulkCString(c,"down-after-milliseconds");
    addReplyBulkLongLong(c,ri->down_after_period);
    fields++;

    /* Masters and Slaves */
    if (ri->flags & (SRI_MASTER|SRI_SLAVE)) {
        addReplyBulkCString(c,"info-refresh");
        addReplyBulkLongLong(c,mstime() - ri->info_refresh);
        fields++;

        addReplyBulkCString(c,"role-reported");
        addReplyBulkCString(c, (ri->role_reported == SRI_MASTER) ? "master" :
                                                                   "slave");
        fields++;

        addReplyBulkCString(c,"role-reported-time");
        addReplyBulkLongLong(c,mstime() - ri->role_reported_time);
        fields++;
    }

    /* Only masters */
    if (ri->flags & SRI_MASTER) {
        addReplyBulkCString(c,"config-epoch");
        addReplyBulkLongLong(c,ri->config_epoch);
        fields++;

        addReplyBulkCString(c,"num-slaves");
        addReplyBulkLongLong(c,dictSize(ri->slaves));
        fields++;

        addReplyBulkCString(c,"num-other-sentinels");
        addReplyBulkLongLong(c,dictSize(ri->sentinels));
        fields++;

        addReplyBulkCString(c,"quorum");
        addReplyBulkLongLong(c,ri->quorum);
        fields++;

        addReplyBulkCString(c,"failover-timeout");
        addReplyBulkLongLong(c,ri->failover_timeout);
        fields++;

        addReplyBulkCString(c,"parallel-syncs");
        addReplyBulkLongLong(c,ri->parallel_syncs);
        fields++;

        if (ri->notification_script) {
            addReplyBulkCString(c,"notification-script");
            addReplyBulkCString(c,ri->notification_script);
            fields++;
        }

        if (ri->client_reconfig_script) {
            addReplyBulkCString(c,"client-reconfig-script");
            addReplyBulkCString(c,ri->client_reconfig_script);
            fields++;
        }
    }

    /* Only slaves */
    if (ri->flags & SRI_SLAVE) {
        addReplyBulkCString(c,"master-link-down-time");
        addReplyBulkLongLong(c,ri->master_link_down_time);
        fields++;

        addReplyBulkCString(c,"master-link-status");
        addReplyBulkCString(c,
            (ri->slave_master_link_status == SENTINEL_MASTER_LINK_STATUS_UP) ?
            "ok" : "err");
        fields++;

        addReplyBulkCString(c,"master-host");
        addReplyBulkCString(c,
            ri->slave_master_host ? ri->slave_master_host : "?");
        fields++;

        addReplyBulkCString(c,"master-port");
        addReplyBulkLongLong(c,ri->slave_master_port);
        fields++;

        addReplyBulkCString(c,"slave-priority");
        addReplyBulkLongLong(c,ri->slave_priority);
        fields++;

        addReplyBulkCString(c,"slave-repl-offset");
        addReplyBulkLongLong(c,ri->slave_repl_offset);
        fields++;
    }

    /* Only sentinels */
    if (ri->flags & SRI_SENTINEL) {
        addReplyBulkCString(c,"last-hello-message");
        addReplyBulkLongLong(c,mstime() - ri->last_hello_time);
        fields++;

        addReplyBulkCString(c,"voted-leader");
        addReplyBulkCString(c,ri->leader ? ri->leader : "?");
        fields++;

        addReplyBulkCString(c,"voted-leader-epoch");
        addReplyBulkLongLong(c,ri->leader_epoch);
        fields++;
    }

    setDeferredMapLen(c,mbl,fields);
}

/* Output a number of instances contained inside a dictionary as
 * Redis protocol. */
void addReplyDictOfRedisInstances(client *c, dict *instances) {
    dictIterator *di;
    dictEntry *de;

    di = dictGetIterator(instances);
    addReplyArrayLen(c,dictSize(instances));
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        addReplySentinelRedisInstance(c,ri);
    }
    dictReleaseIterator(di);
}

/* Lookup the named master into sentinel.masters.
 * If the master is not found reply to the client with an error and returns
 * NULL. */
sentinelRedisInstance *sentinelGetMasterByNameOrReplyError(client *c,
                        robj *name)
{
    sentinelRedisInstance *ri;

    ri = dictFetchValue(sentinel.masters,name->ptr);
    if (!ri) {
        addReplyError(c,"No such master with that name");
        return NULL;
    }
    return ri;
}

#define SENTINEL_ISQR_OK 0
#define SENTINEL_ISQR_NOQUORUM (1<<0)
#define SENTINEL_ISQR_NOAUTH (1<<1)
int sentinelIsQuorumReachable(sentinelRedisInstance *master, int *usableptr) {
    dictIterator *di;
    dictEntry *de;
    int usable = 1; /* Number of usable Sentinels. Init to 1 to count myself. */
    int result = SENTINEL_ISQR_OK;
    int voters = dictSize(master->sentinels)+1; /* Known Sentinels + myself. */

    di = dictGetIterator(master->sentinels);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        if (ri->flags & (SRI_S_DOWN|SRI_O_DOWN)) continue;
        usable++;
    }
    dictReleaseIterator(di);

    if (usable < (int)master->quorum) result |= SENTINEL_ISQR_NOQUORUM;
    if (usable < voters/2+1) result |= SENTINEL_ISQR_NOAUTH;
    if (usableptr) *usableptr = usable;
    return result;
}

void sentinelCommand(client *c) {
    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"CKQUORUM <master-name>",
"    Check if the current Sentinel configuration is able to reach the quorum",
"    needed to failover a master and the majority needed to authorize the",
"    failover.",
"CONFIG SET <param> <value>",
"    Set a global Sentinel configuration parameter.",
"CONFIG GET <param>",
"    Get global Sentinel configuration parameter.",
"GET-MASTER-ADDR-BY-NAME <master-name>",
"    Return the ip and port number of the master with that name.",
"FAILOVER <master-name>",
"    Manually failover a master node without asking for agreement from other",
"    Sentinels",
"FLUSHCONFIG",
"    Force Sentinel to rewrite its configuration on disk, including the current",
"    Sentinel state.",
"INFO-CACHE <master-name>",
"    Return last cached INFO output from masters and all its replicas.",
"IS-MASTER-DOWN-BY-ADDR <ip> <port> <current-epoch> <runid>",
"    Check if the master specified by ip:port is down from current Sentinel's",
"    point of view.",
"MASTER <master-name>",
"    Show the state and info of the specified master.",
"MASTERS",
"    Show a list of monitored masters and their state.",
"MONITOR <name> <ip> <port> <quorum>",
"    Start monitoring a new master with the specified name, ip, port and quorum.",
"MYID",
"    Return the ID of the Sentinel instance.",
"PENDING-SCRIPTS",
"    Get pending scripts information.",
"REMOVE <master-name>",
"    Remove master from Sentinel's monitor list.",
"REPLICAS <master-name>",
"    Show a list of replicas for this master and their state.",
"RESET <pattern>",
"    Reset masters for specific master name matching this pattern.",
"SENTINELS <master-name>",
"    Show a list of Sentinel instances for this master and their state.",
"SET <master-name> <option> <value>",
"    Set configuration paramters for certain masters.",
"SIMULATE-FAILURE (CRASH-AFTER-ELECTION|CRASH-AFTER-PROMOTION|HELP)",
"    Simulate a Sentinel crash.",
NULL
        };
        addReplyHelp(c, help);
    } else if (!strcasecmp(c->argv[1]->ptr,"masters")) {
        /* SENTINEL MASTERS */
        if (c->argc != 2) goto numargserr;
        addReplyDictOfRedisInstances(c,sentinel.masters);
    } else if (!strcasecmp(c->argv[1]->ptr,"master")) {
        /* SENTINEL MASTER <name> */
        sentinelRedisInstance *ri;

        if (c->argc != 3) goto numargserr;
        if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2]))
            == NULL) return;
        addReplySentinelRedisInstance(c,ri);
    } else if (!strcasecmp(c->argv[1]->ptr,"slaves") ||
               !strcasecmp(c->argv[1]->ptr,"replicas"))
    {
        /* SENTINEL REPLICAS <master-name> */
        sentinelRedisInstance *ri;

        if (c->argc != 3) goto numargserr;
        if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2])) == NULL)
            return;
        addReplyDictOfRedisInstances(c,ri->slaves);
    } else if (!strcasecmp(c->argv[1]->ptr,"sentinels")) {
        /* SENTINEL SENTINELS <master-name> */
        sentinelRedisInstance *ri;

        if (c->argc != 3) goto numargserr;
        if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2])) == NULL)
            return;
        addReplyDictOfRedisInstances(c,ri->sentinels);
    } else if (!strcasecmp(c->argv[1]->ptr,"myid") && c->argc == 2) {
        /* SENTINEL MYID */
        addReplyBulkCBuffer(c,sentinel.myid,CONFIG_RUN_ID_SIZE);
    } else if (!strcasecmp(c->argv[1]->ptr,"is-master-down-by-addr")) {
        /* SENTINEL IS-MASTER-DOWN-BY-ADDR <ip> <port> <current-epoch> <runid>
         *
         * Arguments:
         *
         * ip and port are the ip and port of the master we want to be
         * checked by Sentinel. Note that the command will not check by
         * name but just by master, in theory different Sentinels may monitor
         * different masters with the same name.
         *
         * current-epoch is needed in order to understand if we are allowed
         * to vote for a failover leader or not. Each Sentinel can vote just
         * one time per epoch.
         *
         * runid is "*" if we are not seeking for a vote from the Sentinel
         * in order to elect the failover leader. Otherwise it is set to the
         * runid we want the Sentinel to vote if it did not already voted.
         */
        sentinelRedisInstance *ri;
        long long req_epoch;
        uint64_t leader_epoch = 0;
        char *leader = NULL;
        long port;
        int isdown = 0;

        if (c->argc != 6) goto numargserr;
        if (getLongFromObjectOrReply(c,c->argv[3],&port,NULL) != C_OK ||
            getLongLongFromObjectOrReply(c,c->argv[4],&req_epoch,NULL)
                                                              != C_OK)
            return;
        ri = getSentinelRedisInstanceByAddrAndRunID(sentinel.masters,
            c->argv[2]->ptr,port,NULL);

        /* It exists? Is actually a master? Is subjectively down? It's down.
         * Note: if we are in tilt mode we always reply with "0". */
        if (!sentinel.tilt && ri && (ri->flags & SRI_S_DOWN) &&
                                    (ri->flags & SRI_MASTER))
            isdown = 1;

        /* Vote for the master (or fetch the previous vote) if the request
         * includes a runid, otherwise the sender is not seeking for a vote. 
         * 
         * 如果请求包含 runid，请为 master 投票，否则发送方不是在寻求投票
         */
        if (ri && ri->flags & SRI_MASTER && strcasecmp(c->argv[5]->ptr,"*")) {
            leader = sentinelVoteLeader(ri,(uint64_t)req_epoch,
                                            c->argv[5]->ptr,
                                            &leader_epoch);
        }

        /* Reply with a three-elements multi-bulk reply:
         * down state, leader, vote epoch. 
         * 多条回复
         * 1) <down_state>   1 代表下线， 0 代表未下线
         * 2) <leader_runid> sentinel 选举作为领头 sentinel 的运行 id
         * 3) <leader_epoch> 领头 sentinel 目前的纪元配置
         */
        addReplyArrayLen(c,3);
        addReply(c, isdown ? shared.cone : shared.czero);
        addReplyBulkCString(c, leader ? leader : "*");
        addReplyLongLong(c, (long long)leader_epoch);
        if (leader) sdsfree(leader);
    } else if (!strcasecmp(c->argv[1]->ptr,"reset")) {
        /* SENTINEL RESET <pattern> */
        if (c->argc != 3) goto numargserr;
        addReplyLongLong(c,sentinelResetMastersByPattern(c->argv[2]->ptr,SENTINEL_GENERATE_EVENT));
    } else if (!strcasecmp(c->argv[1]->ptr,"get-master-addr-by-name")) {
        /* SENTINEL GET-MASTER-ADDR-BY-NAME <master-name> */
        sentinelRedisInstance *ri;

        if (c->argc != 3) goto numargserr;
        ri = sentinelGetMasterByName(c->argv[2]->ptr);
        if (ri == NULL) {
            addReplyNullArray(c);
        } else {
            sentinelAddr *addr = sentinelGetCurrentMasterAddress(ri);

            addReplyArrayLen(c,2);
            addReplyBulkCString(c,announceSentinelAddr(addr));
            addReplyBulkLongLong(c,addr->port);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"failover")) {
        /* SENTINEL FAILOVER <master-name> */
        sentinelRedisInstance *ri;

        if (c->argc != 3) goto numargserr;
        if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2])) == NULL)
            return;
        if (ri->flags & SRI_FAILOVER_IN_PROGRESS) {
            addReplySds(c,sdsnew("-INPROG Failover already in progress\r\n"));
            return;
        }
        if (sentinelSelectSlave(ri) == NULL) {
            addReplySds(c,sdsnew("-NOGOODSLAVE No suitable replica to promote\r\n"));
            return;
        }
        serverLog(LL_WARNING,"Executing user requested FAILOVER of '%s'",
            ri->name);
        sentinelStartFailover(ri);
        ri->flags |= SRI_FORCE_FAILOVER;
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"pending-scripts")) {
        /* SENTINEL PENDING-SCRIPTS */

        if (c->argc != 2) goto numargserr;
        sentinelPendingScriptsCommand(c);
    } else if (!strcasecmp(c->argv[1]->ptr,"monitor")) {
        /* SENTINEL MONITOR <name> <ip> <port> <quorum> */
        sentinelRedisInstance *ri;
        long quorum, port;
        char ip[NET_IP_STR_LEN];

        if (c->argc != 6) goto numargserr;
        if (getLongFromObjectOrReply(c,c->argv[5],&quorum,"Invalid quorum")
            != C_OK) return;
        if (getLongFromObjectOrReply(c,c->argv[4],&port,"Invalid port")
            != C_OK) return;

        if (quorum <= 0) {
            addReplyError(c, "Quorum must be 1 or greater.");
            return;
        }

        /* If resolve-hostnames is used, actual DNS resolution may take place.
         * Otherwise just validate address.
         */
        if (anetResolve(NULL,c->argv[3]->ptr,ip,sizeof(ip),
                        sentinel.resolve_hostnames ? ANET_NONE : ANET_IP_ONLY) == ANET_ERR) {
            addReplyError(c, "Invalid IP address or hostname specified");
            return;
        }

        /* Parameters are valid. Try to create the master instance. */
        ri = createSentinelRedisInstance(c->argv[2]->ptr,SRI_MASTER,
                c->argv[3]->ptr,port,quorum,NULL);
        if (ri == NULL) {
            addReplyError(c,sentinelCheckCreateInstanceErrors(SRI_MASTER));
        } else {
            sentinelFlushConfig();
            sentinelEvent(LL_WARNING,"+monitor",ri,"%@ quorum %d",ri->quorum);
            addReply(c,shared.ok);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"flushconfig")) {
        if (c->argc != 2) goto numargserr;
        sentinelFlushConfig();
        addReply(c,shared.ok);
        return;
    } else if (!strcasecmp(c->argv[1]->ptr,"remove")) {
        /* SENTINEL REMOVE <name> */
        sentinelRedisInstance *ri;

        if (c->argc != 3) goto numargserr;
        if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2]))
            == NULL) return;
        sentinelEvent(LL_WARNING,"-monitor",ri,"%@");
        dictDelete(sentinel.masters,c->argv[2]->ptr);
        sentinelFlushConfig();
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"ckquorum")) {
        /* SENTINEL CKQUORUM <name> */
        sentinelRedisInstance *ri;
        int usable;

        if (c->argc != 3) goto numargserr;
        if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2]))
            == NULL) return;
        int result = sentinelIsQuorumReachable(ri,&usable);
        if (result == SENTINEL_ISQR_OK) {
            addReplySds(c, sdscatfmt(sdsempty(),
                "+OK %i usable Sentinels. Quorum and failover authorization "
                "can be reached\r\n",usable));
        } else {
            sds e = sdscatfmt(sdsempty(),
                "-NOQUORUM %i usable Sentinels. ",usable);
            if (result & SENTINEL_ISQR_NOQUORUM)
                e = sdscat(e,"Not enough available Sentinels to reach the"
                             " specified quorum for this master");
            if (result & SENTINEL_ISQR_NOAUTH) {
                if (result & SENTINEL_ISQR_NOQUORUM) e = sdscat(e,". ");
                e = sdscat(e, "Not enough available Sentinels to reach the"
                              " majority and authorize a failover");
            }
            e = sdscat(e,"\r\n");
            addReplySds(c,e);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"set")) {
        if (c->argc < 3) goto numargserr;
        sentinelSetCommand(c);
    } else if (!strcasecmp(c->argv[1]->ptr,"config")) {
        if (c->argc < 3) goto numargserr;
        if (!strcasecmp(c->argv[2]->ptr,"set") && c->argc == 5)
            sentinelConfigSetCommand(c);
        else if (!strcasecmp(c->argv[2]->ptr,"get") && c->argc == 4)
            sentinelConfigGetCommand(c);
        else
            addReplyError(c, "Only SENTINEL CONFIG GET <option> / SET <option> <value> are supported.");
    } else if (!strcasecmp(c->argv[1]->ptr,"info-cache")) {
        /* SENTINEL INFO-CACHE <name> */
        if (c->argc < 2) goto numargserr;
        mstime_t now = mstime();

        /* Create an ad-hoc dictionary type so that we can iterate
         * a dictionary composed of just the master groups the user
         * requested. */
        dictType copy_keeper = instancesDictType;
        copy_keeper.valDestructor = NULL;
        dict *masters_local = sentinel.masters;
        if (c->argc > 2) {
            masters_local = dictCreate(&copy_keeper, NULL);

            for (int i = 2; i < c->argc; i++) {
                sentinelRedisInstance *ri;
                ri = sentinelGetMasterByName(c->argv[i]->ptr);
                if (!ri) continue; /* ignore non-existing names */
                dictAdd(masters_local, ri->name, ri);
            }
        }

        /* Reply format:
         *   1.) master name
         *   2.) 1.) info from master
         *       2.) info from replica
         *       ...
         *   3.) other master name
         *   ...
         */
        addReplyArrayLen(c,dictSize(masters_local) * 2);

        dictIterator  *di;
        dictEntry *de;
        di = dictGetIterator(masters_local);
        while ((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *ri = dictGetVal(de);
            addReplyBulkCBuffer(c,ri->name,strlen(ri->name));
            addReplyArrayLen(c,dictSize(ri->slaves) + 1); /* +1 for self */
            addReplyArrayLen(c,2);
            addReplyLongLong(c, now - ri->info_refresh);
            if (ri->info)
                addReplyBulkCBuffer(c,ri->info,sdslen(ri->info));
            else
                addReplyNull(c);

            dictIterator *sdi;
            dictEntry *sde;
            sdi = dictGetIterator(ri->slaves);
            while ((sde = dictNext(sdi)) != NULL) {
                sentinelRedisInstance *sri = dictGetVal(sde);
                addReplyArrayLen(c,2);
                addReplyLongLong(c, now - sri->info_refresh);
                if (sri->info)
                    addReplyBulkCBuffer(c,sri->info,sdslen(sri->info));
                else
                    addReplyNull(c);
            }
            dictReleaseIterator(sdi);
        }
        dictReleaseIterator(di);
        if (masters_local != sentinel.masters) dictRelease(masters_local);
    } else if (!strcasecmp(c->argv[1]->ptr,"simulate-failure")) {
        /* SENTINEL SIMULATE-FAILURE <flag> <flag> ... <flag> */
        int j;

        sentinel.simfailure_flags = SENTINEL_SIMFAILURE_NONE;
        for (j = 2; j < c->argc; j++) {
            if (!strcasecmp(c->argv[j]->ptr,"crash-after-election")) {
                sentinel.simfailure_flags |=
                    SENTINEL_SIMFAILURE_CRASH_AFTER_ELECTION;
                serverLog(LL_WARNING,"Failure simulation: this Sentinel "
                    "will crash after being successfully elected as failover "
                    "leader");
            } else if (!strcasecmp(c->argv[j]->ptr,"crash-after-promotion")) {
                sentinel.simfailure_flags |=
                    SENTINEL_SIMFAILURE_CRASH_AFTER_PROMOTION;
                serverLog(LL_WARNING,"Failure simulation: this Sentinel "
                    "will crash after promoting the selected replica to master");
            } else if (!strcasecmp(c->argv[j]->ptr,"help")) {
                addReplyArrayLen(c,2);
                addReplyBulkCString(c,"crash-after-election");
                addReplyBulkCString(c,"crash-after-promotion");
            } else {
                addReplyError(c,"Unknown failure simulation specified");
                return;
            }
        }
        addReply(c,shared.ok);
    } else {
        addReplySubcommandSyntaxError(c);
    }
    return;

numargserr:
    addReplyErrorFormat(c,"Wrong number of arguments for 'sentinel %s'",
                          (char*)c->argv[1]->ptr);
}

#define info_section_from_redis(section_name) do { \
    if (defsections || allsections || !strcasecmp(section,section_name)) { \
        sds redissection; \
        if (sections++) info = sdscat(info,"\r\n"); \
        redissection = genRedisInfoString(section_name); \
        info = sdscatlen(info,redissection,sdslen(redissection)); \
        sdsfree(redissection); \
    } \
} while(0)

/* SENTINEL INFO [section] */
void sentinelInfoCommand(client *c) {
    if (c->argc > 2) {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    int defsections = 0, allsections = 0;
    char *section = c->argc == 2 ? c->argv[1]->ptr : NULL;
    if (section) {
        allsections = !strcasecmp(section,"all");
        defsections = !strcasecmp(section,"default");
    } else {
        defsections = 1;
    }

    int sections = 0;
    sds info = sdsempty();

    info_section_from_redis("server");
    info_section_from_redis("clients");
    info_section_from_redis("cpu");
    info_section_from_redis("stats");

    if (defsections || allsections || !strcasecmp(section,"sentinel")) {
        dictIterator *di;
        dictEntry *de;
        int master_id = 0;

        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info,
            "# Sentinel\r\n"
            "sentinel_masters:%lu\r\n"
            "sentinel_tilt:%d\r\n"
            "sentinel_running_scripts:%d\r\n"
            "sentinel_scripts_queue_length:%ld\r\n"
            "sentinel_simulate_failure_flags:%lu\r\n",
            dictSize(sentinel.masters),
            sentinel.tilt,
            sentinel.running_scripts,
            listLength(sentinel.scripts_queue),
            sentinel.simfailure_flags);

        di = dictGetIterator(sentinel.masters);
        while((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *ri = dictGetVal(de);
            char *status = "ok";

            if (ri->flags & SRI_O_DOWN) status = "odown";
            else if (ri->flags & SRI_S_DOWN) status = "sdown";
            info = sdscatprintf(info,
                "master%d:name=%s,status=%s,address=%s:%d,"
                "slaves=%lu,sentinels=%lu\r\n",
                master_id++, ri->name, status,
                announceSentinelAddr(ri->addr), ri->addr->port,
                dictSize(ri->slaves),
                dictSize(ri->sentinels)+1);
        }
        dictReleaseIterator(di);
    }

    addReplyBulkSds(c, info);
}

/* Implements Sentinel version of the ROLE command. The output is
 * "sentinel" and the list of currently monitored master names. */
void sentinelRoleCommand(client *c) {
    dictIterator *di;
    dictEntry *de;

    addReplyArrayLen(c,2);
    addReplyBulkCBuffer(c,"sentinel",8);
    addReplyArrayLen(c,dictSize(sentinel.masters));

    di = dictGetIterator(sentinel.masters);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        addReplyBulkCString(c,ri->name);
    }
    dictReleaseIterator(di);
}

/* SENTINEL SET <mastername> [<option> <value> ...] */
void sentinelSetCommand(client *c) {
    sentinelRedisInstance *ri;
    int j, changes = 0;
    int badarg = 0; /* Bad argument position for error reporting. */
    char *option;

    if ((ri = sentinelGetMasterByNameOrReplyError(c,c->argv[2]))
        == NULL) return;

    /* Process option - value pairs. */
    for (j = 3; j < c->argc; j++) {
        int moreargs = (c->argc-1) - j;
        option = c->argv[j]->ptr;
        long long ll;
        int old_j = j; /* Used to know what to log as an event. */

        if (!strcasecmp(option,"down-after-milliseconds") && moreargs > 0) {
            /* down-after-millisecodns <milliseconds> */
            robj *o = c->argv[++j];
            if (getLongLongFromObject(o,&ll) == C_ERR || ll <= 0) {
                badarg = j;
                goto badfmt;
            }
            ri->down_after_period = ll;
            sentinelPropagateDownAfterPeriod(ri);
            changes++;
        } else if (!strcasecmp(option,"failover-timeout") && moreargs > 0) {
            /* failover-timeout <milliseconds> */
            robj *o = c->argv[++j];
            if (getLongLongFromObject(o,&ll) == C_ERR || ll <= 0) {
                badarg = j;
                goto badfmt;
            }
            ri->failover_timeout = ll;
            changes++;
        } else if (!strcasecmp(option,"parallel-syncs") && moreargs > 0) {
            /* parallel-syncs <milliseconds> */
            robj *o = c->argv[++j];
            if (getLongLongFromObject(o,&ll) == C_ERR || ll <= 0) {
                badarg = j;
                goto badfmt;
            }
            ri->parallel_syncs = ll;
            changes++;
        } else if (!strcasecmp(option,"notification-script") && moreargs > 0) {
            /* notification-script <path> */
            char *value = c->argv[++j]->ptr;
            if (sentinel.deny_scripts_reconfig) {
                addReplyError(c,
                    "Reconfiguration of scripts path is denied for "
                    "security reasons. Check the deny-scripts-reconfig "
                    "configuration directive in your Sentinel configuration");
                goto seterr;
            }

            if (strlen(value) && access(value,X_OK) == -1) {
                addReplyError(c,
                    "Notification script seems non existing or non executable");
                goto seterr;
            }
            sdsfree(ri->notification_script);
            ri->notification_script = strlen(value) ? sdsnew(value) : NULL;
            changes++;
        } else if (!strcasecmp(option,"client-reconfig-script") && moreargs > 0) {
            /* client-reconfig-script <path> */
            char *value = c->argv[++j]->ptr;
            if (sentinel.deny_scripts_reconfig) {
                addReplyError(c,
                    "Reconfiguration of scripts path is denied for "
                    "security reasons. Check the deny-scripts-reconfig "
                    "configuration directive in your Sentinel configuration");
                goto seterr;
            }

            if (strlen(value) && access(value,X_OK) == -1) {
                addReplyError(c,
                    "Client reconfiguration script seems non existing or "
                    "non executable");
                goto seterr;
            }
            sdsfree(ri->client_reconfig_script);
            ri->client_reconfig_script = strlen(value) ? sdsnew(value) : NULL;
            changes++;
        } else if (!strcasecmp(option,"auth-pass") && moreargs > 0) {
            /* auth-pass <password> */
            char *value = c->argv[++j]->ptr;
            sdsfree(ri->auth_pass);
            ri->auth_pass = strlen(value) ? sdsnew(value) : NULL;
            changes++;
        } else if (!strcasecmp(option,"auth-user") && moreargs > 0) {
            /* auth-user <username> */
            char *value = c->argv[++j]->ptr;
            sdsfree(ri->auth_user);
            ri->auth_user = strlen(value) ? sdsnew(value) : NULL;
            changes++;
        } else if (!strcasecmp(option,"quorum") && moreargs > 0) {
            /* quorum <count> */
            robj *o = c->argv[++j];
            if (getLongLongFromObject(o,&ll) == C_ERR || ll <= 0) {
                badarg = j;
                goto badfmt;
            }
            ri->quorum = ll;
            changes++;
        } else if (!strcasecmp(option,"rename-command") && moreargs > 1) {
            /* rename-command <oldname> <newname> */
            sds oldname = c->argv[++j]->ptr;
            sds newname = c->argv[++j]->ptr;

            if ((sdslen(oldname) == 0) || (sdslen(newname) == 0)) {
                badarg = sdslen(newname) ? j-1 : j;
                goto badfmt;
            }

            /* Remove any older renaming for this command. */
            dictDelete(ri->renamed_commands,oldname);

            /* If the target name is the same as the source name there
             * is no need to add an entry mapping to itself. */
            if (!dictSdsKeyCaseCompare(NULL,oldname,newname)) {
                oldname = sdsdup(oldname);
                newname = sdsdup(newname);
                dictAdd(ri->renamed_commands,oldname,newname);
            }
            changes++;
        } else {
            addReplyErrorFormat(c,"Unknown option or number of arguments for "
                                  "SENTINEL SET '%s'", option);
            goto seterr;
        }

        /* Log the event. */
        int numargs = j-old_j+1;
        switch(numargs) {
        case 2:
            sentinelEvent(LL_WARNING,"+set",ri,"%@ %s %s",c->argv[old_j]->ptr,
                                                          c->argv[old_j+1]->ptr);
            break;
        case 3:
            sentinelEvent(LL_WARNING,"+set",ri,"%@ %s %s %s",c->argv[old_j]->ptr,
                                                             c->argv[old_j+1]->ptr,
                                                             c->argv[old_j+2]->ptr);
            break;
        default:
            sentinelEvent(LL_WARNING,"+set",ri,"%@ %s",c->argv[old_j]->ptr);
            break;
        }
    }

    if (changes) sentinelFlushConfig();
    addReply(c,shared.ok);
    return;

badfmt: /* Bad format errors */
    addReplyErrorFormat(c,"Invalid argument '%s' for SENTINEL SET '%s'",
        (char*)c->argv[badarg]->ptr,option);
seterr:
    if (changes) sentinelFlushConfig();
    return;
}

/* Our fake PUBLISH command: it is actually useful only to receive hello messages
 * from the other sentinel instances, and publishing to a channel other than
 * SENTINEL_HELLO_CHANNEL is forbidden.
 *
 * Because we have a Sentinel PUBLISH, the code to send hello messages is the same
 * for all the three kind of instances: masters, slaves, sentinels. */
void sentinelPublishCommand(client *c) {
    if (strcmp(c->argv[1]->ptr,SENTINEL_HELLO_CHANNEL)) {
        addReplyError(c, "Only HELLO messages are accepted by Sentinel instances.");
        return;
    }
    sentinelProcessHelloMessage(c->argv[2]->ptr,sdslen(c->argv[2]->ptr));
    addReplyLongLong(c,1);
}

/* ===================== SENTINEL availability checks ======================= */

/* Is this instance down from our point of view? 
 * 判断实例是否主观下线
 */
void sentinelCheckSubjectivelyDown(sentinelRedisInstance *ri) {
    mstime_t elapsed = 0;

    if (ri->link->act_ping_time)
        elapsed = mstime() - ri->link->act_ping_time;
    else if (ri->link->disconnected)
        elapsed = mstime() - ri->link->last_avail_time;

    /* Check if we are in need for a reconnection of one of the
     * links, because we are detecting low activity.
     * 
     * 如果检测到连接的活跃度很低，那么考虑断开连接并进行重连
     *  
     * 1) Check if the command link seems connected, was connected not less
     *    than SENTINEL_MIN_LINK_RECONNECT_PERIOD, but still we have a
     *    pending ping for more than half the timeout. */
    // 考虑断开实例的命令连接
    if (ri->link->cc &&
        (mstime() - ri->link->cc_conn_time) >
        SENTINEL_MIN_LINK_RECONNECT_PERIOD &&
        ri->link->act_ping_time != 0 && /* There is a pending ping... */
        /* The pending ping is delayed, and we did not receive
         * error replies as well. */
        (mstime() - ri->link->act_ping_time) > (ri->down_after_period/2) &&
        (mstime() - ri->link->last_pong_time) > (ri->down_after_period/2))
    {
        instanceLinkCloseConnection(ri->link,ri->link->cc);
    }

    /* 2) Check if the pubsub link seems connected, was connected not less
     *    than SENTINEL_MIN_LINK_RECONNECT_PERIOD, but still we have no
     *    activity in the Pub/Sub channel for more than
     *    SENTINEL_PUBLISH_PERIOD * 3.
     */
    // 考虑断开实例的订阅连接
    if (ri->link->pc &&
        (mstime() - ri->link->pc_conn_time) >
         SENTINEL_MIN_LINK_RECONNECT_PERIOD &&
        (mstime() - ri->link->pc_last_activity) > (SENTINEL_PUBLISH_PERIOD*3))
    {
        instanceLinkCloseConnection(ri->link,ri->link->pc);
    }

    /* Update the SDOWN flag. We believe the instance is SDOWN if:
     *  
     * 更新 SDOWN 标识。如果以下条件被满足，那么认为实例下线:
     * 1) It is not replying.
     *    实例没有回复命令
     * 2) We believe it is a master, it reports to be a slave for enough time
     *    to meet the down_after_period, plus enough time to get two times
     *    INFO report from the instance. 
     *    sentinel 认为这个实例是 master，但这个实例向 sentinel 报告它将成为 slave，
     *    但在超过给定时限之后，服务器仍然没有完成这一角色转换
     */
    if (elapsed > ri->down_after_period ||
        (ri->flags & SRI_MASTER &&
         ri->role_reported == SRI_SLAVE &&
         mstime() - ri->role_reported_time >
          (ri->down_after_period+SENTINEL_INFO_PERIOD*2)))
    {
        /* Is subjectively down */
        if ((ri->flags & SRI_S_DOWN) == 0) {
            // 发送事件
            sentinelEvent(LL_WARNING,"+sdown",ri,"%@");
            // 纪录进入 SDOWN 状态的时间
            ri->s_down_since_time = mstime();
            // 标记为 SDOWN 状态
            ri->flags |= SRI_S_DOWN;
        }
    } else {
        /* Is subjectively up */
        if (ri->flags & SRI_S_DOWN) {
            sentinelEvent(LL_WARNING,"-sdown",ri,"%@");
            // 将状态标记为非 SRI_S_DOWN 和 SRI_SCRIPT_KILL_SENT 状态
            ri->flags &= ~(SRI_S_DOWN|SRI_SCRIPT_KILL_SENT);
        }
    }
}

/* Is this instance down according to the configured quorum?
 * 
 * 投票判断实例是否客观下线
 * 
 * Note that ODOWN is a weak quorum, it only means that enough Sentinels
 * reported in a given time range that the instance was not reachable.
 * 
 * 注意：ODOWN 是一个 weak quorum，它仅仅意味着在给定时间内有足够多的 Sentinels
 * 报告实例不可达
 * 
 * However messages can be delayed so there are no strong guarantees about
 * N instances agreeing at the same time about the down state. 
 * 因为 Sentinel 对实例的检查信息可能有延迟，因此无法保证 N 个 Sentinel 在同一
 * 时间判断实例进入下线状态
 */
void sentinelCheckObjectivelyDown(sentinelRedisInstance *master) {
    dictIterator *di;
    dictEntry *de;
    unsigned int quorum = 0, odown = 0;
    /*
     * 如果 Sentinel 将 master 判断为主观下线
     * 那么检查是否有其它 Sentinel 同意这一判断
     * 当同意的数量足够多时，将 master 标记为客观下线
     */
    if (master->flags & SRI_S_DOWN) {
        /* Is down for enough sentinels? */
        // 统计同意的 Sentinel 数量，初始值 1 代表本 Sentinel
        quorum = 1; /* the current sentinel. */
        /* Count all the other sentinels. */
        // 统计其它认为 master 进入下线状态的 Sentinel 数量
        di = dictGetIterator(master->sentinels);
        while((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *ri = dictGetVal(de);
            
            // 该 Sentinel 也认为 master 已下线
            if (ri->flags & SRI_MASTER_DOWN) quorum++;
        }
        dictReleaseIterator(di);
        // 如果下线投票次数大于等于判断客观下线所需的票数，则标记 master 为客观下线状态 
        if (quorum >= master->quorum) odown = 1;
    }

    /* Set the flag accordingly to the outcome. */
    if (odown) {
        if ((master->flags & SRI_O_DOWN) == 0) {
            // 发送事件
            sentinelEvent(LL_WARNING,"+odown",master,"%@ #quorum %d/%d",
                quorum, master->quorum);
            master->flags |= SRI_O_DOWN;
            // 纪录进入客观下线的时间
            master->o_down_since_time = mstime();
        }
    } else {
        // 未进入 ODOWN
        // 如果 master 曾经进入过 ODOWN 状态，则移除 ODOWN 状态
        if (master->flags & SRI_O_DOWN) {
            sentinelEvent(LL_WARNING,"-odown",master,"%@");
            master->flags &= ~SRI_O_DOWN;
        }
    }
}

/* Receive the SENTINEL is-master-down-by-addr reply, see the
 * sentinelAskMasterStateToOtherSentinels() function for more information. 
 * 接收 SENTINEL is-master-down-by-addr 命令的回复信息
 */
void sentinelReceiveIsMasterDownReply(redisAsyncContext *c, void *reply, void *privdata) {
    // sentinel
    sentinelRedisInstance *ri = privdata;
    instanceLink *link = c->data;
    redisReply *r;

    if (!reply || !link) return;
    // 等待接收命令的参数减 1
    link->pending_commands--;
    r = reply;

    /* Ignore every error or unexpected reply.
     * Note that if the command returns an error for any reason we'll
     * end clearing the SRI_MASTER_DOWN flag for timeout anyway.
     * 忽略所有错误或意料之外的回复
     */
    if (r->type == REDIS_REPLY_ARRAY && r->elements == 3 &&
        r->element[0]->type == REDIS_REPLY_INTEGER &&
        r->element[1]->type == REDIS_REPLY_STRING &&
        r->element[2]->type == REDIS_REPLY_INTEGER)
    {
        /* 更新最后一次收到 SENTINEL is-master-down-by-addr
         * 命令回复的时间
         */
        ri->last_master_down_reply_time = mstime();

        // 设置 SENTINEL 认为主服务器的状态
        if (r->element[0]->integer == 1) {
            // 已下线
            ri->flags |= SRI_MASTER_DOWN;
        } else {
            // 未下线
            ri->flags &= ~SRI_MASTER_DOWN;
        }
        
        if (strcmp(r->element[1]->str,"*")) {
            /* If the runid in the reply is not "*" the Sentinel actually
             * replied with a vote. 
             * 如果回复信息中运行 ID 不是 "*" 的话，那么这是一个带投票的回复
             */
            sdsfree(ri->leader);
            // 打印日志
            if ((long long)ri->leader_epoch != r->element[2]->integer)
                serverLog(LL_WARNING,
                    "%s voted for %s %llu", ri->name,
                    r->element[1]->str,
                    (unsigned long long) r->element[2]->integer);
            // 设置领头 sentinel
            ri->leader = sdsnew(r->element[1]->str);
            ri->leader_epoch = r->element[2]->integer;
        }
    }
}

/* If we think the master is down, we start sending
 * SENTINEL IS-MASTER-DOWN-BY-ADDR requests to other sentinels
 * in order to get the replies that allow to reach the quorum
 * needed to mark the master in ODOWN state and trigger a failover. 
 * 
 * 如果 sentinel 认为 master 客观下线，那么它会向其它 sentinel 发送
 * IS-MASTER-DOWN-BY-ADDR 命令来获取投票，如果投票数足够多，则将 master
 * 标记为 ODOWN 状态，并开始一次故障转移
 * 
 */
#define SENTINEL_ASK_FORCED (1<<0)
void sentinelAskMasterStateToOtherSentinels(sentinelRedisInstance *master, int flags) {
    dictIterator *di;
    dictEntry *de;

    // 遍历监视相同 master 的所有 sentinel
    di = dictGetIterator(master->sentinels);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        // 距离该 sentinel 最后一次回复其它 sentinel 发来的 IS-MASTER-DOWN-BY-ADDR
        // 命令已经过了多久
        mstime_t elapsed = mstime() - ri->last_master_down_reply_time;
        char port[32];
        int retval;

        /* If the master state from other sentinel is too old, we clear it. 
         * 如果太久没有收到来自其它 sentinel 关于 master 的状态，则将其标记为
         * 非 SRI_MASTER_DOWN 状态
         */
        if (elapsed > SENTINEL_ASK_PERIOD*5) {
            ri->flags &= ~SRI_MASTER_DOWN;
            sdsfree(ri->leader);
            ri->leader = NULL;
        }

        /* Only ask if master is down to other sentinels if:
         *
         * 只在以下情况下才向其它 sentinel 询问 master 是否已下线
         * 
         * 1) We believe it is down, or there is a failover in progress.
         *    本 sentinel 认为 master 已经下线或该 master 正在执行故障转移
         * 2) Sentinel is connected.
         *    目标 sentinel 和本 sentinel 建立连接
         * 3) We did not receive the info within SENTINEL_ASK_PERIOD ms.
         *    本 sentinel 在 SENTINEL_ASK_PERIOD 毫秒内没有接收到目标 sentinel 发来的信息
         * 4) 条件 1 和条件 2 满足，而条件 3 不满足，但是 flags 参数给定了 SENTINEL_ASK_FORCED
         */
        // 不满足条件 1，本 sentinel 认为 master 没有主观下线
        if ((master->flags & SRI_S_DOWN) == 0) continue;
        // 不满足条件 2，目标 sentinel 与本 sentinel 没有建立连接
        if (ri->link->disconnected) continue;
        // flags 参数没有给定为 SENTINEL_ASK_FORCED，且距离目标 sentinel 最后一次
        // 回复 is-master-down 命令没过 SENTINEL_ASK_PERIOD = 1000
        if (!(flags & SENTINEL_ASK_FORCED) &&
            mstime() - ri->last_master_down_reply_time < SENTINEL_ASK_PERIOD)
            continue;

        /* Ask */
        // 发送 SENTINEL is-master-down-by-addr 命令
        // 命令格式 SENTINEL is-master-down-by-addr <ip> <port> <current_epoch> <runid>
        ll2string(port,sizeof(port),master->addr->port);
        retval = redisAsyncCommand(ri->link->cc,
                    sentinelReceiveIsMasterDownReply, ri,
                    "%s is-master-down-by-addr %s %s %llu %s",
                    // 获取命令名字
                    sentinelInstanceMapCommand(ri,"SENTINEL"),
                    // 获取 master ip
                    announceSentinelAddr(master->addr), 
                    // master 监听的端口
                    port,
                    // 纪元
                    sentinel.current_epoch,
                    /*
                     * 如果本 Sentinel 已经检测到 master 进入 ODOWN 状态
                     * 并且要开始一次故障转移，那么向其他 Sentinel 发送自己
                     * 的运行 ID，如果对方在这个纪元内还没有投票，让对方给自己
                     * 投一票，选举本 sentinel 为领头 sentinel
                     */
                    (master->failover_state > SENTINEL_FAILOVER_STATE_NONE) ?
                    sentinel.myid : "*");
        if (retval == C_OK) ri->link->pending_commands++;
    }
    dictReleaseIterator(di);
}

/* =============================== FAILOVER ================================= */

/* Crash because of user request via SENTINEL simulate-failure command. */
void sentinelSimFailureCrash(void) {
    serverLog(LL_WARNING,
        "Sentinel CRASH because of SENTINEL simulate-failure");
    exit(99);
}

/* Vote for the sentinel with 'req_runid' or return the old vote if already
 * voted for the specified 'req_epoch' or one greater.
 * 
 * 为运行 ID 为 req_runid 的 sentinel 投票，有两种额外情况可能出现:
 * 1) 如果 sentinel 在 req_epoch 纪元已经投过票，则将返回之前的投票结果
 * 2) 如果 sentinel 已经为大于 req_epoch 的纪元投过票了，则返回更大纪元的投票 
 *
 * If a vote is not available returns NULL, otherwise return the Sentinel
 * runid and populate the leader_epoch with the epoch of the vote. 
 * 
 * 如果投票不可用，那么返回 NULL，
 * 否则返回 sentinel 的 runId，并将被投票的纪元保存到 leader_epoch 里面
 */
char *sentinelVoteLeader(sentinelRedisInstance *master, uint64_t req_epoch, char *req_runid, uint64_t *leader_epoch) {
    // 如果 req_epoch 大于本 sentinel 的当前纪元
    // 则更新本 sentinel 的当前纪元
    if (req_epoch > sentinel.current_epoch) {
        sentinel.current_epoch = req_epoch;
        sentinelFlushConfig();
        sentinelEvent(LL_WARNING,"+new-epoch",master,"%llu",
            (unsigned long long) sentinel.current_epoch);
    }

    if (master->leader_epoch < req_epoch && sentinel.current_epoch <= req_epoch)
    {
        sdsfree(master->leader);
        master->leader = sdsnew(req_runid);
        master->leader_epoch = sentinel.current_epoch;
        sentinelFlushConfig();
        sentinelEvent(LL_WARNING,"+vote-for-leader",master,"%s %llu",
            master->leader, (unsigned long long) master->leader_epoch);
        /* If we did not voted for ourselves, set the master failover start
         * time to now, in order to force a delay before we can start a
         * failover for the same master. */
        if (strcasecmp(master->leader,sentinel.myid))
            master->failover_start_time = mstime()+rand()%SENTINEL_MAX_DESYNC;
    }

    *leader_epoch = master->leader_epoch;
    return master->leader ? sdsnew(master->leader) : NULL;
}

struct sentinelLeader {
    char *runid;
    unsigned long votes;
};

/* Helper function for sentinelGetLeader, increment the counter
 * relative to the specified runid. 
 * sentinelGetLeader 函数的帮助函数，递增指定 runid 的计数器
 */
int sentinelLeaderIncr(dict *counters, char *runid) {
    dictEntry *existing, *de;
    uint64_t oldval;

    de = dictAddRaw(counters,runid,&existing);
    if (existing) {
        oldval = dictGetUnsignedIntegerVal(existing);
        dictSetUnsignedIntegerVal(existing,oldval+1);
        return oldval+1;
    } else {
        serverAssert(de != NULL);
        dictSetUnsignedIntegerVal(de,1);
        return 1;
    }
}

/* Scan all the Sentinels attached to this master to check if there
 * is a leader for the specified epoch.
 * 
 * 扫描所有连接此 master 的 sentinel，检查指定的纪元是否有领导者
 *
 * To be a leader for a given epoch, we should have the majority of
 * the Sentinels we know (ever seen since the last SENTINEL RESET) that
 * reported the same instance as leader for the same epoch. 
 * 
 * sentinel 要成为给定纪元的领导者，它必须获得其它绝大多数的 sentinel 的承认
 */
char *sentinelGetLeader(sentinelRedisInstance *master, uint64_t epoch) {
    dict *counters;
    dictIterator *di;
    dictEntry *de;
    unsigned int voters = 0, voters_quorum;
    char *myvote;
    char *winner = NULL;
    uint64_t leader_epoch;
    uint64_t max_votes = 0;

    serverAssert(master->flags & (SRI_O_DOWN|SRI_FAILOVER_IN_PROGRESS));
    // 创建一个投票字典
    counters = dictCreate(&leaderVotesDictType,NULL);
    
    // 所有与 master 连接的 sentinel (包括本 sentinel，所以加 1 )
    voters = dictSize(master->sentinels)+1; /* All the other sentinels and me.*/

    /* Count other sentinels votes 
     * 统计其它 sentinel 的投票
     */
    di = dictGetIterator(master->sentinels);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        // 为选出的目标 sentinel 增加一票
        if (ri->leader != NULL && ri->leader_epoch == sentinel.current_epoch)
            sentinelLeaderIncr(counters,ri->leader);
    }
    dictReleaseIterator(di);

    /* Check what's the winner. For the winner to win, it needs two conditions:
     * 选出领头 sentinel ，它必须满足以下两个条件：
     * 1) Absolute majority between voters (50% + 1).
     *    获得超过一半 sentinel 的投票
     * 2) And anyway at least master->quorum votes. 
     *    至少获得 master->quorum 个投票
     */
    di = dictGetIterator(counters);
    while((de = dictNext(di)) != NULL) {
        uint64_t votes = dictGetUnsignedIntegerVal(de);
        
        // 获取票数最多的 runid
        if (votes > max_votes) {
            max_votes = votes;
            winner = dictGetKey(de);
        }
    }
    dictReleaseIterator(di);

    /* Count this Sentinel vote:
     * 加上本 sentinel 的投票:
     * if this Sentinel did not voted yet, either vote for the most
     * common voted sentinel, or for itself if no vote exists at all.
     * 
     * 如果本 sentinel 还没有进行过投票，它有两种选择:
     * 1) 如果选出了票数最多的 sentinel，那么将票投给它
     * 2) 如果没有选出票数最多的 sentinel，则将票投给自己
     */
    if (winner)
        myvote = sentinelVoteLeader(master,epoch,winner,&leader_epoch);
    else
        myvote = sentinelVoteLeader(master,epoch,sentinel.myid,&leader_epoch);
    
    // 本 sentinel 已投票，并且 leader_epoch 和给定的纪元相等
    if (myvote && leader_epoch == epoch) {
        // 本 sentinel 投票后，统计被投票 sentinel 的票数
        uint64_t votes = sentinelLeaderIncr(counters,myvote);

        if (votes > max_votes) {
            max_votes = votes;
            winner = myvote;
        }
    }
    /**
     * 如果最大票数不超过半数
     * 或最大票数不到 master 配置的指定票数
     * 则此次投票无效
     */
    voters_quorum = voters/2+1;
    if (winner && (max_votes < voters_quorum || max_votes < master->quorum))
        winner = NULL;

    winner = winner ? sdsnew(winner) : NULL;
    sdsfree(myvote);
    dictRelease(counters);
    return winner;
}

/* Send SLAVEOF to the specified instance, always followed by a
 * CONFIG REWRITE command in order to store the new configuration on disk
 * when possible (that is, if the Redis instance is recent enough to support
 * config rewriting, and if the server was started with a configuration file).
 *
 * If Host is NULL the function sends "SLAVEOF NO ONE".
 *
 * The command returns C_OK if the SLAVEOF command was accepted for
 * (later) delivery otherwise C_ERR. The command replies are just
 * discarded. */
int sentinelSendSlaveOf(sentinelRedisInstance *ri, const sentinelAddr *addr) {
    char portstr[32];
    const char *host;
    int retval;

    /* If host is NULL we send SLAVEOF NO ONE that will turn the instance
    * into a master. */
    if (!addr) {
        host = "NO";
        memcpy(portstr,"ONE",4);
    } else {
        host = announceSentinelAddr(addr);
        ll2string(portstr,sizeof(portstr),addr->port);
    }

    /* In order to send SLAVEOF in a safe way, we send a transaction performing
     * the following tasks:
     * 1) Reconfigure the instance according to the specified host/port params.
     * 2) Rewrite the configuration.
     * 3) Disconnect all clients (but this one sending the command) in order
     *    to trigger the ask-master-on-reconnection protocol for connected
     *    clients.
     *
     * Note that we don't check the replies returned by commands, since we
     * will observe instead the effects in the next INFO output. */
    retval = redisAsyncCommand(ri->link->cc,
        sentinelDiscardReplyCallback, ri, "%s",
        sentinelInstanceMapCommand(ri,"MULTI"));
    if (retval == C_ERR) return retval;
    ri->link->pending_commands++;

    retval = redisAsyncCommand(ri->link->cc,
        sentinelDiscardReplyCallback, ri, "%s %s %s",
        sentinelInstanceMapCommand(ri,"SLAVEOF"),
        host, portstr);
    if (retval == C_ERR) return retval;
    ri->link->pending_commands++;

    retval = redisAsyncCommand(ri->link->cc,
        sentinelDiscardReplyCallback, ri, "%s REWRITE",
        sentinelInstanceMapCommand(ri,"CONFIG"));
    if (retval == C_ERR) return retval;
    ri->link->pending_commands++;

    /* CLIENT KILL TYPE <type> is only supported starting from Redis 2.8.12,
     * however sending it to an instance not understanding this command is not
     * an issue because CLIENT is variadic command, so Redis will not
     * recognized as a syntax error, and the transaction will not fail (but
     * only the unsupported command will fail). */
    for (int type = 0; type < 2; type++) {
        retval = redisAsyncCommand(ri->link->cc,
            sentinelDiscardReplyCallback, ri, "%s KILL TYPE %s",
            sentinelInstanceMapCommand(ri,"CLIENT"),
            type == 0 ? "normal" : "pubsub");
        if (retval == C_ERR) return retval;
        ri->link->pending_commands++;
    }

    retval = redisAsyncCommand(ri->link->cc,
        sentinelDiscardReplyCallback, ri, "%s",
        sentinelInstanceMapCommand(ri,"EXEC"));
    if (retval == C_ERR) return retval;
    ri->link->pending_commands++;

    return C_OK;
}

/* Setup the master state to start a failover. 
 * 启动 Master 故障转移
 */
void sentinelStartFailover(sentinelRedisInstance *master) {
    serverAssert(master->flags & SRI_MASTER);

    // 更新 Master 故障转移状态，等待故障转移开始
    master->failover_state = SENTINEL_FAILOVER_STATE_WAIT_START;

    // 标记 Master 为正在进行故障转移
    master->flags |= SRI_FAILOVER_IN_PROGRESS;

    // 更新纪元
    master->failover_epoch = ++sentinel.current_epoch;

    sentinelEvent(LL_WARNING,"+new-epoch",master,"%llu",
        (unsigned long long) sentinel.current_epoch);
    sentinelEvent(LL_WARNING,"+try-failover",master,"%@");
    
    // 记录故障转移开始时间
    master->failover_start_time = mstime()+rand()%SENTINEL_MAX_DESYNC;
    
    // 记录故障转移状态变更时间
    master->failover_state_change_time = mstime();
}

/* This function checks if there are the conditions to start the failover,
 * that is:
 * 此函数判断是否具备启动故障转移的条件:
 * 
 * 1) Master must be in ODOWN condition.
 *    Master 进入 ODOWN 状态
 * 2) No failover already in progress.
 *    这个 Master 没有故障转移正在进行
 * 3) No failover already attempted recently.
 *    最近时间内，这个 Master 没有尝试过执行故障转移
 *    (应该是为了防止频繁执行)
 *
 * We still don't know if we'll win the election so it is possible that we
 * start the failover but that we'll not be able to act.
 * 
 * 虽然 Sentinel 可以发起一次故障转移，但因为故障转移操作是由领头 Sentinel 执行的，
 * 所以发起故障转移的 Sentinel 不一定就是执行故障转移的 Sentinel
 * 
 * Return non-zero if a failover was started. 
 * 
 * 如果故障转移被启动，则返回非零
 */
int sentinelStartFailoverIfNeeded(sentinelRedisInstance *master) {
    /* We can't failover if the master is not in O_DOWN state.
     * Master 没有进入 ODOWN 状态，直接返回
     */
    if (!(master->flags & SRI_O_DOWN)) return 0;

    /* Failover already in progress? 
     * 故障转移正在进行中，则直接返回
     */
    if (master->flags & SRI_FAILOVER_IN_PROGRESS) return 0;

    /* Last failover attempt started too little time ago? 
     * 在最近一段时间内有尝试过故障转移
     */
    if (mstime() - master->failover_start_time <
        master->failover_timeout*2)
    {
        if (master->failover_delay_logged != master->failover_start_time) {
            time_t clock = (master->failover_start_time +
                            master->failover_timeout*2) / 1000;
            char ctimebuf[26];

            ctime_r(&clock,ctimebuf);
            ctimebuf[24] = '\0'; /* Remove newline. */
            master->failover_delay_logged = master->failover_start_time;
            serverLog(LL_WARNING,
                "Next failover delay: I will not start a failover before %s",
                ctimebuf);
        }
        return 0;
    }

    // 开始故障转移
    sentinelStartFailover(master);
    return 1;
}

/* Select a suitable slave to promote. The current algorithm only uses
 * the following parameters:
 *
 * 1) None of the following conditions: S_DOWN, O_DOWN, DISCONNECTED.
 * 2) Last time the slave replied to ping no more than 5 times the PING period.
 * 3) info_refresh not older than 3 times the INFO refresh period.
 * 4) master_link_down_time no more than:
 *     (now - master->s_down_since_time) + (master->down_after_period * 10).
 *    Basically since the master is down from our POV, the slave reports
 *    to be disconnected no more than 10 times the configured down-after-period.
 *    This is pretty much black magic but the idea is, the master was not
 *    available so the slave may be lagging, but not over a certain time.
 *    Anyway we'll select the best slave according to replication offset.
 * 5) Slave priority can't be zero, otherwise the slave is discarded.
 *
 * Among all the slaves matching the above conditions we select the slave
 * with, in order of sorting key:
 *
 * - lower slave_priority.
 * - bigger processed replication offset.
 * - lexicographically smaller runid.
 *
 * Basically if runid is the same, the slave that processed more commands
 * from the master is selected.
 *
 * The function returns the pointer to the selected slave, otherwise
 * NULL if no suitable slave was found.
 */

/* Helper for sentinelSelectSlave(). This is used by qsort() in order to
 * sort suitable slaves in a "better first" order, to take the first of
 * the list. 
 * 
 * sentinelSelectSlave() 函数的帮助函数。该函数被 qsort() 使用来排序 slave
 * 1.最先比较优先级
 * 2.如果优先级相同，则比较复制偏移量
 * 3.如果复制偏移量和优先级都相同，则比较 runid
 * 
 * 如果返回值小于 0，那么 *a 所指向元素会被排在 *b 所指向元素的左面
 * 如果返回值大于 0，那么 *a 所指向元素会被排在 *b 所指向元素的右面
 * 如果返回值等于 0，那么 *a 和 *b 所指向元素的顺序不确定
 */
int compareSlavesForPromotion(const void *a, const void *b) {
    sentinelRedisInstance **sa = (sentinelRedisInstance **)a,
                          **sb = (sentinelRedisInstance **)b;
    char *sa_runid, *sb_runid;

    // 如果优先级不同，则比较优先级
    if ((*sa)->slave_priority != (*sb)->slave_priority)
        return (*sa)->slave_priority - (*sb)->slave_priority;

    /* If priority is the same, select the slave with greater replication
     * offset (processed more data from the master). 
     * 
     * 如果优先级相同，则比较两个 slave 的复制偏移量
     */
    if ((*sa)->slave_repl_offset > (*sb)->slave_repl_offset) {
        return -1; /* a < b */
    } else if ((*sa)->slave_repl_offset < (*sb)->slave_repl_offset) {
        return 1; /* a > b */
    }

    /* If the replication offset is the same select the slave with that has
     * the lexicographically smaller runid. Note that we try to handle runid
     * == NULL as there are old Redis versions that don't publish runid in
     * INFO. A NULL runid is considered bigger than any other runid.
     *
     * 如果复制偏移量和优先级都相同，则选择按字典排序较小的 slave
     * 注意：因为有些旧的版本不分配 runid，所以此处需要判断 runid 为空的情况，
     *      其中为 NULL 的 runid 被认为比任何非空 runid 大
     * 
     */
    sa_runid = (*sa)->runid;
    sb_runid = (*sb)->runid;
    if (sa_runid == NULL && sb_runid == NULL) return 0;
    else if (sa_runid == NULL) return 1;  /* a > b */
    else if (sb_runid == NULL) return -1; /* a < b */
    return strcasecmp(sa_runid, sb_runid);
}
/**
 * 在 master 的 slave 列表中选择 slave
 */
sentinelRedisInstance *sentinelSelectSlave(sentinelRedisInstance *master) {
    sentinelRedisInstance **instance =
        zmalloc(sizeof(instance[0])*dictSize(master->slaves));
    sentinelRedisInstance *selected = NULL;
    int instances = 0;
    dictIterator *di;
    dictEntry *de;
    // 允许的从节点与主节点断链时间的最大值
    mstime_t max_master_down_time = 0;

    /*
     * 计算当前时间距离 master 主观下线过去了多久
     */
    if (master->flags & SRI_S_DOWN)
        max_master_down_time += mstime() - master->s_down_since_time;
    max_master_down_time += master->down_after_period * 10;

    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);
        mstime_t info_validity_time;
        
        // 跳过处于下线状态的 slave
        if (slave->flags & (SRI_S_DOWN|SRI_O_DOWN)) continue;

        // 跳过处于断线状态的 slave
        if (slave->link->disconnected) continue;

        // 跳过最近 SENTINEL_PING_PERIOD*5=5 秒内
        // 没有回复领导 sentinel ping 命令的 slave
        if (mstime() - slave->link->last_avail_time > SENTINEL_PING_PERIOD*5) continue;
        
        // 跳过优先级为 0 的 slave
        if (slave->slave_priority == 0) continue;

        /* If the master is in SDOWN state we get INFO for slaves every second.
         * Otherwise we get it with the usual period so we need to account for
         * a larger delay. 
         * 
         * 如果 master 处于 SDOWN 状态，那么 sentinel 每秒向 slave 发送 INFO 命令
         * 否则以平常频率向 slave 发送 INFO 命令
         * 这里要检查 INFO 命令的返回值是否合法，检查的时间会乘以一个倍数，以计算延迟
         */
        if (master->flags & SRI_S_DOWN)
            info_validity_time = SENTINEL_PING_PERIOD*5;
        else
            info_validity_time = SENTINEL_INFO_PERIOD*3;
        
        // 跳过当前时间与接收到 INFO 回复消息时间之差超过 info_validity_time 时间的slave
        if (mstime() - slave->info_refresh > info_validity_time) continue;
        
        // 跳过与 master 断线时间超过 max_master_down_time 的 slave
        if (slave->master_link_down_time > max_master_down_time) continue;
        
        // 将被选中的 slave 保存在数组中
        instance[instances++] = slave;
    }
    dictReleaseIterator(di);
    if (instances) {
        
        // 对被选中的从服务器进行排序
        qsort(instance,instances,sizeof(sentinelRedisInstance*),
            compareSlavesForPromotion);
        // 取出排在位置 0 的 slave
        selected = instance[0];
    }
    zfree(instance);
    return selected;
}

/* ---------------- Failover state machine implementation ------------------- */
/* ---------------- 故障转移状态机实现 ------------------- */
void sentinelFailoverWaitStart(sentinelRedisInstance *ri) {
    char *leader;
    int isleader;

    /* Check if we are the leader for the failover epoch. 
     * 统计投票，获取领头 sentinel
     */
    leader = sentinelGetLeader(ri, ri->failover_epoch);
    // 判断本 sentinel 是否是领头 sentinel
    isleader = leader && strcasecmp(leader,sentinel.myid) == 0;
    sdsfree(leader);

    /* If I'm not the leader, and it is not a forced failover via
     * SENTINEL FAILOVER, then I can't continue with the failover. 
     * 如果本 sentinel 不是领头 sentinel，并且这次故障转移不是一次强制性
     * 故障迁移操作，则本 sentinel 不能做故障转移
     */
    if (!isleader && !(ri->flags & SRI_FORCE_FAILOVER)) {
        // SENTINEL_ELECTION_TIMEOUT=10秒
        int election_timeout = SENTINEL_ELECTION_TIMEOUT;

        /* The election timeout is the MIN between SENTINEL_ELECTION_TIMEOUT
         * and the configured failover timeout. */
        if (election_timeout > ri->failover_timeout)
            election_timeout = ri->failover_timeout;
        /* Abort the failover if I'm not the leader after some time. 
         * 选举超时，则终止故障转移
         */
        if (mstime() - ri->failover_start_time > election_timeout) {
            sentinelEvent(LL_WARNING,"-failover-abort-not-elected",ri,"%@");
            sentinelAbortFailover(ri);
        }
        return;
    }
    // 本 sentinel 是领头 sentinel，则开始执行故障迁移操作
    sentinelEvent(LL_WARNING,"+elected-leader",ri,"%@");
    if (sentinel.simfailure_flags & SENTINEL_SIMFAILURE_CRASH_AFTER_ELECTION)
        sentinelSimFailureCrash();
    
    // 进入选择 slave 状态
    ri->failover_state = SENTINEL_FAILOVER_STATE_SELECT_SLAVE;
    ri->failover_state_change_time = mstime();
    sentinelEvent(LL_WARNING,"+failover-state-select-slave",ri,"%@");
}
/**
 * 从 master 的 slave 列表中选出最佳 slave 
 */
void sentinelFailoverSelectSlave(sentinelRedisInstance *ri) {
    // 在 master 的 slave 列表中选择 slave
    sentinelRedisInstance *slave = sentinelSelectSlave(ri);

    /* We don't handle the timeout in this state as the function aborts
     * the failover or go forward in the next state. */
    if (slave == NULL) {
        sentinelEvent(LL_WARNING,"-failover-abort-no-good-slave",ri,"%@");
        sentinelAbortFailover(ri);
    } else {
        sentinelEvent(LL_WARNING,"+selected-slave",slave,"%@");
        slave->flags |= SRI_PROMOTED;
        ri->promoted_slave = slave;
        ri->failover_state = SENTINEL_FAILOVER_STATE_SEND_SLAVEOF_NOONE;
        ri->failover_state_change_time = mstime();
        sentinelEvent(LL_NOTICE,"+failover-state-send-slaveof-noone",
            slave, "%@");
    }
}
/**
 * 把选出的 slave 设置为 master
 */
void sentinelFailoverSendSlaveOfNoOne(sentinelRedisInstance *ri) {
    int retval;

    /* We can't send the command to the promoted slave if it is now
     * disconnected. Retry again and again with this state until the timeout
     * is reached, then abort the failover. */
    if (ri->promoted_slave->link->disconnected) {
        if (mstime() - ri->failover_state_change_time > ri->failover_timeout) {
            sentinelEvent(LL_WARNING,"-failover-abort-slave-timeout",ri,"%@");
            sentinelAbortFailover(ri);
        }
        return;
    }

    /* Send SLAVEOF NO ONE command to turn the slave into a master.
     * We actually register a generic callback for this command as we don't
     * really care about the reply. We check if it worked indirectly observing
     * if INFO returns a different role (master instead of slave). */
    retval = sentinelSendSlaveOf(ri->promoted_slave,NULL);
    if (retval != C_OK) return;
    sentinelEvent(LL_NOTICE, "+failover-state-wait-promotion",
        ri->promoted_slave,"%@");
    ri->failover_state = SENTINEL_FAILOVER_STATE_WAIT_PROMOTION;
    ri->failover_state_change_time = mstime();
}

/* We actually wait for promotion indirectly checking with INFO when the
 * slave turns into a master. */
void sentinelFailoverWaitPromotion(sentinelRedisInstance *ri) {
    /* Just handle the timeout. Switching to the next state is handled
     * by the function parsing the INFO command of the promoted slave. */
    if (mstime() - ri->failover_state_change_time > ri->failover_timeout) {
        sentinelEvent(LL_WARNING,"-failover-abort-slave-timeout",ri,"%@");
        sentinelAbortFailover(ri);
    }
}

void sentinelFailoverDetectEnd(sentinelRedisInstance *master) {
    int not_reconfigured = 0, timeout = 0;
    dictIterator *di;
    dictEntry *de;
    mstime_t elapsed = mstime() - master->failover_state_change_time;

    /* We can't consider failover finished if the promoted slave is
     * not reachable. */
    if (master->promoted_slave == NULL ||
        master->promoted_slave->flags & SRI_S_DOWN) return;

    /* The failover terminates once all the reachable slaves are properly
     * configured. */
    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);

        if (slave->flags & (SRI_PROMOTED|SRI_RECONF_DONE)) continue;
        if (slave->flags & SRI_S_DOWN) continue;
        not_reconfigured++;
    }
    dictReleaseIterator(di);

    /* Force end of failover on timeout. */
    if (elapsed > master->failover_timeout) {
        not_reconfigured = 0;
        timeout = 1;
        sentinelEvent(LL_WARNING,"+failover-end-for-timeout",master,"%@");
    }

    if (not_reconfigured == 0) {
        sentinelEvent(LL_WARNING,"+failover-end",master,"%@");
        master->failover_state = SENTINEL_FAILOVER_STATE_UPDATE_CONFIG;
        master->failover_state_change_time = mstime();
    }

    /* If I'm the leader it is a good idea to send a best effort SLAVEOF
     * command to all the slaves still not reconfigured to replicate with
     * the new master. */
    if (timeout) {
        dictIterator *di;
        dictEntry *de;

        di = dictGetIterator(master->slaves);
        while((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *slave = dictGetVal(de);
            int retval;

            if (slave->flags & (SRI_PROMOTED|SRI_RECONF_DONE|SRI_RECONF_SENT)) continue;
            if (slave->link->disconnected) continue;

            retval = sentinelSendSlaveOf(slave,master->promoted_slave->addr);
            if (retval == C_OK) {
                sentinelEvent(LL_NOTICE,"+slave-reconf-sent-be",slave,"%@");
                slave->flags |= SRI_RECONF_SENT;
            }
        }
        dictReleaseIterator(di);
    }
}

/* Send SLAVE OF <new master address> to all the remaining slaves that
 * still don't appear to have the configuration updated. */
void sentinelFailoverReconfNextSlave(sentinelRedisInstance *master) {
    dictIterator *di;
    dictEntry *de;
    int in_progress = 0;

    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);

        if (slave->flags & (SRI_RECONF_SENT|SRI_RECONF_INPROG))
            in_progress++;
    }
    dictReleaseIterator(di);

    di = dictGetIterator(master->slaves);
    while(in_progress < master->parallel_syncs &&
          (de = dictNext(di)) != NULL)
    {
        sentinelRedisInstance *slave = dictGetVal(de);
        int retval;

        /* Skip the promoted slave, and already configured slaves. */
        if (slave->flags & (SRI_PROMOTED|SRI_RECONF_DONE)) continue;

        /* If too much time elapsed without the slave moving forward to
         * the next state, consider it reconfigured even if it is not.
         * Sentinels will detect the slave as misconfigured and fix its
         * configuration later. */
        if ((slave->flags & SRI_RECONF_SENT) &&
            (mstime() - slave->slave_reconf_sent_time) >
            SENTINEL_SLAVE_RECONF_TIMEOUT)
        {
            sentinelEvent(LL_NOTICE,"-slave-reconf-sent-timeout",slave,"%@");
            slave->flags &= ~SRI_RECONF_SENT;
            slave->flags |= SRI_RECONF_DONE;
        }

        /* Nothing to do for instances that are disconnected or already
         * in RECONF_SENT state. */
        if (slave->flags & (SRI_RECONF_SENT|SRI_RECONF_INPROG)) continue;
        if (slave->link->disconnected) continue;

        /* Send SLAVEOF <new master>. */
        retval = sentinelSendSlaveOf(slave,master->promoted_slave->addr);
        if (retval == C_OK) {
            slave->flags |= SRI_RECONF_SENT;
            slave->slave_reconf_sent_time = mstime();
            sentinelEvent(LL_NOTICE,"+slave-reconf-sent",slave,"%@");
            in_progress++;
        }
    }
    dictReleaseIterator(di);

    /* Check if all the slaves are reconfigured and handle timeout. */
    sentinelFailoverDetectEnd(master);
}

/* This function is called when the slave is in
 * SENTINEL_FAILOVER_STATE_UPDATE_CONFIG state. In this state we need
 * to remove it from the master table and add the promoted slave instead. 
 * 当故障转移状态机为 SENTINEL_FAILOVER_STATE_UPDATE_CONFIG 状态的时候，
 * 已经选出了新 master，并且已经告诉了其它 slave 要与新 master 进行同步，
 * 此时 sentinel 需要更新 master 的地址，并将旧 master 地址对应的实例和
 * 所有 slave 都添加到新 master 地址对应实例的 master->slaves 字典中
 */
void sentinelFailoverSwitchToPromotedSlave(sentinelRedisInstance *master) {
    // 取出新选举的 master
    sentinelRedisInstance *ref = master->promoted_slave ?
                                 master->promoted_slave : master;

    sentinelEvent(LL_WARNING,"+switch-master",master,"%s %s %d %s %d",
        master->name, announceSentinelAddr(master->addr), master->addr->port,
        announceSentinelAddr(ref->addr), ref->addr->port);
    
    // 重置 master，并将 master 的地址修改为新选举出来的 master 的地址
    // 并将 master 旧地址对应的实例和所有 slave 实例添加到 master 的 master->slaves 字典中
    sentinelResetMasterAndChangeAddress(master,ref->addr->hostname,ref->addr->port);
}
// 执行故障转移
void sentinelFailoverStateMachine(sentinelRedisInstance *ri) {
    serverAssert(ri->flags & SRI_MASTER);
    // master 未被本 Sentinel 标记为需要进行故障转移
    if (!(ri->flags & SRI_FAILOVER_IN_PROGRESS)) return;

    switch(ri->failover_state) {
        // 等待故障转移开始
        case SENTINEL_FAILOVER_STATE_WAIT_START:
            // 统计选票，查看是否成为 leader
            sentinelFailoverWaitStart(ri);
            break;
        // 选择要升级为 master 的 slave
        case SENTINEL_FAILOVER_STATE_SELECT_SLAVE:
            // 从 slave 列表中选出最佳 slave
            sentinelFailoverSelectSlave(ri);
            break;
        // 向该从节点发送 SLAVEOF NO ONE 命令
        case SENTINEL_FAILOVER_STATE_SEND_SLAVEOF_NOONE:
            // 把选出的 slave 设置为 master
            sentinelFailoverSendSlaveOfNoOne(ri);
            break;
        // 等待 slave 晋升为 master
        case SENTINEL_FAILOVER_STATE_WAIT_PROMOTION:
            sentinelFailoverWaitPromotion(ri);
            break;
        // 向其它 slave 节点发送 SLAVEOF 命令，使它们与新的主节点进行同步
        case SENTINEL_FAILOVER_STATE_RECONF_SLAVES:
            sentinelFailoverReconfNextSlave(ri);
            break;
    }
}

/* Abort a failover in progress:
 *
 * This function can only be called before the promoted slave acknowledged
 * the slave -> master switch. Otherwise the failover can't be aborted and
 * will reach its end (possibly by timeout). */
void sentinelAbortFailover(sentinelRedisInstance *ri) {
    serverAssert(ri->flags & SRI_FAILOVER_IN_PROGRESS);
    serverAssert(ri->failover_state <= SENTINEL_FAILOVER_STATE_WAIT_PROMOTION);

    ri->flags &= ~(SRI_FAILOVER_IN_PROGRESS|SRI_FORCE_FAILOVER);
    ri->failover_state = SENTINEL_FAILOVER_STATE_NONE;
    ri->failover_state_change_time = mstime();
    if (ri->promoted_slave) {
        ri->promoted_slave->flags &= ~SRI_PROMOTED;
        ri->promoted_slave = NULL;
    }
}

/* ======================== SENTINEL timer handler ==========================
 * This is the "main" our Sentinel, being sentinel completely non blocking
 * in design. The function is called every second.
 * -------------------------------------------------------------------------- */

/* Perform scheduled operations for the specified Redis instance.
 * 对指定的 redis 实例执行定期操作
 */
void sentinelHandleRedisInstance(sentinelRedisInstance *ri) {
    /* ========== MONITORING HALF ============ */
    /* ========== 监控操作 ============ */
    /* Every kind of instance 
     * 对所有类型的实例进行处理
     */
    // 判断 Sentinel 与实例直接的连接，如果连接处于断开状态，创建与实例之间的连接
    sentinelReconnectInstance(ri);
    // 定期向 master、slave、sentinel 实例发送 PING 和 PUBLISH 命令，
    // 定期向 master、slave 实例发送 INFO 命令
    sentinelSendPeriodicCommands(ri);

    /* ============== ACTING HALF ============= */
    /* ==============  故障检测   ============= */
    /* We don't proceed with the acting half if we are in TILT mode.
     * TILT happens when we find something odd with the time, like a
     * sudden change in the clock. 
     * 在 TILT 模式下不进行故障检测
     */
    if (sentinel.tilt) {
        // 如果当前时间距离进入 TILT 模式的时间小于 SENTINEL_TILT_PERIOD ，则直接返回，不进行故障检测
        if (mstime()-sentinel.tilt_start_time < SENTINEL_TILT_PERIOD) return;
        // 运行到此处则说明已经超过了 TILT 模式的时间限制
        // 将 tilt 设置为 0，退出 TILT 模式
        sentinel.tilt = 0;
        sentinelEvent(LL_WARNING,"-tilt",NULL,"#tilt mode exited");
    }

    /* Every kind of instance */
    // 判断实例是否主观下线
    sentinelCheckSubjectivelyDown(ri);

    /* Masters and slaves */
    if (ri->flags & (SRI_MASTER|SRI_SLAVE)) {
        /* Nothing so far. */
    }

    /* Only masters */
    if (ri->flags & SRI_MASTER) {
        // 判断实例是否客观下线
        sentinelCheckObjectivelyDown(ri);
        // 判断是否具备启动故障转移的条件
        if (sentinelStartFailoverIfNeeded(ri))
            // 强制向其他 sentinel 发送 SENTINEL IS-MASTER-DOWN-BY-ADDR 命令
            // master 处于 ODOWN 状态
            sentinelAskMasterStateToOtherSentinels(ri,SENTINEL_ASK_FORCED);
        // 执行故障转移
        sentinelFailoverStateMachine(ri);

        // 这一句是对那些没有进入 if(sentinelStartFailoverIfNeeded(ri)) { /* ... */ }
        // 语句的主服务器使用的
        // mater 处于 SDOWN 状态
        sentinelAskMasterStateToOtherSentinels(ri,SENTINEL_NO_FLAGS);
    }
}

/* Perform scheduled operations for all the instances in the dictionary.
 * Recursively call the function against dictionaries of slaves. 
 *
 * 对字典中的所有实例执行定期操作，如果被监视的 master 有 slave，或者
 * master 还被其它 sentinel 监视的，则递归的调用此函数。
 *     sentinelHandleRedisInstance
 *                 |
 *                 |
 *                 v
 *               master
 *               /  \
 *              /    \
 *             v      v
 *          slaves   sentinels
 */
void sentinelHandleDictOfRedisInstances(dict *instances) {
    dictIterator *di;
    dictEntry *de;
    sentinelRedisInstance *switch_to_promoted = NULL;

    /* There are a number of things we need to perform against every master.
     * 遍历字典中的实例，这些实例可以是多个 master、多个 slave 或者多个 sentinel
     */
    di = dictGetIterator(instances);
    while((de = dictNext(di)) != NULL) {
        // 取出字典中单个键值对的值
        sentinelRedisInstance *ri = dictGetVal(de);
        
        /*
         * 本 sentinel 对监视的 master、slave 和对
         * 监视相同 master 的 sentinel 进行定期操作
         */
        sentinelHandleRedisInstance(ri);
        /*
         * 如果被遍历的是主服务器，那么递归的遍历该主服务器的所有
         * salve 服务器和监视该 master 的其他 sentinel
         */
        if (ri->flags & SRI_MASTER) {
            sentinelHandleDictOfRedisInstances(ri->slaves);
            sentinelHandleDictOfRedisInstances(ri->sentinels);
             
            /*
             * 对已下线 master(ri) 的故障转移已经完成，
             * 并且已经将其所有 slave 节点都同步到新 master 上了
             */
            if (ri->failover_state == SENTINEL_FAILOVER_STATE_UPDATE_CONFIG) {
                // 已经选出了新的主服务器
                switch_to_promoted = ri;
            }
        }
    }
    if (switch_to_promoted)
        // 切换 master
        sentinelFailoverSwitchToPromotedSlave(switch_to_promoted);
    dictReleaseIterator(di);
}

/* This function checks if we need to enter the TITL mode.
 * 
 * 这个函数检查 sentinel 是否需要进入 TITL 模式
 * 
 * The TILT mode is entered if we detect that between two invocations of the
 * timer interrupt, a negative amount of time, or too much time has passed.
 * 
 * 如果两次执行 sentinel 的时间差为负值或者过大时，就会进入 TILT 模式
 * 
 * Note that we expect that more or less just 100 milliseconds will pass
 * if everything is fine. However we'll see a negative number or a
 * difference bigger than SENTINEL_TILT_TRIGGER milliseconds if one of the
 * following conditions happen:
 * 
 * 通常来说，两次执行 sentinel 之间的时间差会在 100 毫秒左右，
 * 但当出现以下情况时，这个差值可能就会出现异常：
 *
 * 1) The Sentinel process for some time is blocked, for every kind of
 * random reason: the load is huge, the computer was frozen for some time
 * in I/O or alike, the process was stopped by a signal. Everything.
 *    Sentinel 进程因为某些原因而被阻塞，比如载入的数据太大，计算机 I/O 任务繁重，
 *    进程被信号停止等
 * 
 * 2) The system clock was altered significantly.
 *    系统时钟产生了明显的变化
 *
 * Under both this conditions we'll see everything as timed out and failing
 * without good reasons. Instead we enter the TILT mode and wait
 * for SENTINEL_TILT_PERIOD to elapse before starting to act again.
 * 
 * 当出现以上两种情况时，Sentinel 将所有实例都判断为超时，
 * 无原因的将所有实例都判断为掉线。为了避免这种情况的发生，
 * 当出现以上两种情况时，Sentinel 进入 TILT 模式，等待 
 * SENTINEL_TILT_PERIOD 秒钟后再进行相关操作
 *
 * During TILT time we still collect information, we just do not act. 
 * 
 * Sentinel 进入 TITL 模式后，仍然会进行监控并收集实例信息，
 * 只是不执行诸如故障转移、下线判断之类的操作而已。
 */
void sentinelCheckTiltCondition(void) {
    // 当前时间
    mstime_t now = mstime();
    // 当前时间和上次执行 Sentinel 时间的差
    mstime_t delta = now - sentinel.previous_time;

    // 如果差值是负数，或者大于 SENTINEL_TILT_TRIGGER=2 秒钟，
    // 则进入 TILT 模式
    if (delta < 0 || delta > SENTINEL_TILT_TRIGGER) {
        // 标记进入了 TILT 模式
        sentinel.tilt = 1;
        // TILT 模式开始的时间
        sentinel.tilt_start_time = mstime();
        sentinelEvent(LL_WARNING,"+tilt",NULL,"#tilt mode entered");
    }
    // 截止当前时间，最后一次执行 Sentinel 的时间
    sentinel.previous_time = mstime();
}

// sentinel 模式的主函数，由 server.c/serverCron 函数调用
void sentinelTimer(void) {
    // 判断 sentinel 是否需要进入 TITL 模式，
    // 并纪录本次执行 sentinel 的时间
    sentinelCheckTiltCondition();
    /*
     * 执行定期操作
     * 定期向 master、slave 发送 INFO 命令，并分析回复的信息
     * 定期向 master 、slave 、sentinel 发送 PING 命令
     * 定期向 master 、slave 、sentinel 发送 PUBLISH 命令，
     * 广播当前 master 的配置(名字，ip，端口纪元)，同时告知其它 Sentinel
     * 本 Sentinel 的存在(ip，端口，运行id，纪元).
     */
    sentinelHandleDictOfRedisInstances(sentinel.masters);

    // 运行等待执行的脚本
    sentinelRunPendingScripts();
    // 清理已经执行完成的脚本，并重试出错的脚本
    sentinelCollectTerminatedScripts();
    // 杀死运行超时的脚本
    sentinelKillTimedoutScripts();

    /* We continuously change the frequency of the Redis "timer interrupt"
     * in order to desynchronize every Sentinel from every other.
     * This non-determinism avoids that Sentinels started at the same time
     * exactly continue to stay synchronized asking to be voted at the
     * same time again and again (resulting in nobody likely winning the
     * election because of split brain voting). 
     * 修改定时中断的频率
     */
    server.hz = CONFIG_DEFAULT_HZ + rand() % CONFIG_DEFAULT_HZ;
}
