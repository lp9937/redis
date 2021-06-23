/* Implementation of EXPIRE (keys with fixed time to live).
 *
 * ----------------------------------------------------------------------------
 *
 * Copyright (c) 2009-2016, Salvatore Sanfilippo <antirez at gmail dot com>
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

/*-----------------------------------------------------------------------------
 * Incremental collection of expired keys.
 *
 * When keys are accessed they are expired on-access. However we need a
 * mechanism in order to ensure keys are eventually removed when expired even
 * if no access is performed on them.
 *----------------------------------------------------------------------------*/

/* Helper function for the activeExpireCycle() function.
 * This function will try to expire the key that is stored in the hash table
 * entry 'de' of the 'expires' hash table of a Redis database.
 *
 * If the key is found to be expired, it is removed from the database and
 * 1 is returned. Otherwise no operation is performed and 0 is returned.
 * 
 * 如果 key 被发现过期，将 key 从数据库中移除，并返回 1
 * 否则不执行任何操作并返回 0
 * 
 * When a key is expired, server.stat_expiredkeys is incremented.
 * 
 * 当 key 被发现是过期的，server.stat_expiredkeys 自增 1。
 *
 * The parameter 'now' is the current time in milliseconds as is passed
 * to the function to avoid too many gettimeofday() syscalls. 
 * */
int activeExpireCycleTryExpire(redisDb *db, dictEntry *de, long long now) {
    long long t = dictGetSignedIntegerVal(de);
    mstime_t expire_latency;
    // 当前时间大于键过期时间
    if (now > t) {
        sds key = dictGetKey(de);
        robj *keyobj = createStringObject(key,sdslen(key));
        // 传播过期命令
        propagateExpire(db,keyobj,server.lazyfree_lazy_expire);
        latencyStartMonitor(expire_latency);
        
        if (server.lazyfree_lazy_expire)
            // 惰性删除
            dbAsyncDelete(db,keyobj);
        else
            // 直接删除
            dbSyncDelete(db,keyobj);
        latencyEndMonitor(expire_latency);
        latencyAddSampleIfNeeded("expire-del",expire_latency);
        notifyKeyspaceEvent(NOTIFY_EXPIRED,
            "expired",keyobj,db->id);
        signalModifiedKey(NULL, db, keyobj);
        decrRefCount(keyobj);
        // 统计项 stat_expiredkeys 自增 1
        server.stat_expiredkeys++;
        return 1;
    } else {
        return 0;
    }
}

/* Try to expire a few timed out keys. The algorithm used is adaptive and
 * will use few CPU cycles if there are few expiring keys, otherwise
 * it will get more aggressive to avoid that too much memory is used by
 * keys that can be removed from the keyspace.
 *
 * 尝试删除数据库中已经过期的键
 * 算法具有自适应性，如果过期键很少，将占用很少的 CPU 时间，
 * 否则将使用更多的 CPU 时间来删除过期键，释放其占用的内存空间
 * 
 * 
 * Every expire cycle tests multiple databases: the next call will start
 * again from the next db. No more than CRON_DBS_PER_CALL databases are
 * tested at every iteration.
 * 
 * 每个周期内检测的数据库数目不会超过 CRON_DBS_PER_CALL 个
 *
 * The function can perform more or less work, depending on the "type"
 * argument. It can execute a "fast cycle" or a "slow cycle". The slow
 * cycle is the main way we collect expired cycles: this happens with
 * the "server.hz" frequency (usually 10 hertz).
 * 
 * 根据 type 参数不同，分为“快速循环”和“慢循环”两种模式
 * “慢循环”是收集过期键的主要方式，"慢循环"的发生频率由 "server.hz" 参数控制，通常是10
 * 
 *
 * However the slow cycle can exit for timeout, since it used too much time.
 * For this reason the function is also invoked to perform a fast cycle
 * at every event loop cycle, in the beforeSleep() function. The fast cycle
 * will try to perform less work, but will do it much more often.
 * 
 * 因为慢循环可以超时退出，所以会花费很多时间
 * 为此，在beforeSleep()函数中，在每个事件循环周期内 “快速循环” 也被调用。
 * 
 *
 * The following are the details of the two expire cycles and their stop
 * conditions:
 * 
 * 以下是两个“循环”及其停止条件的详细信息：
 *
 * If type is ACTIVE_EXPIRE_CYCLE_FAST the function will try to run a
 * "fast" expire cycle that takes no longer than ACTIVE_EXPIRE_CYCLE_FAST_DURATION
 * microseconds, and is not repeated again before the same amount of time.
 * The cycle will also refuse to run at all if the latest slow cycle did not
 * terminate because of a time limit condition.
 * 
 * 如果 type 是 ACTIVE_EXPIRE_CYCLE_FAST，执行“快速循环”模式
 * 执行时间不会超过 ACTIVE_EXPIRE_CYCLE_FAST_DURATION 毫秒
 * 并且在 EXPIRE_FAST_CYCLE_DURATION 毫秒之内不会再重新执行
 * 如果最近的慢循环不是因为超时而结束，循环也将完全拒绝运行
 *
 * If type is ACTIVE_EXPIRE_CYCLE_SLOW, that normal expire cycle is
 * executed, where the time limit is a percentage of the REDIS_HZ period
 * as specified by the ACTIVE_EXPIRE_CYCLE_SLOW_TIME_PERC define. In the
 * fast cycle, the check of every database is interrupted once the number
 * of already expired keys in the database is estimated to be lower than
 * a given percentage, in order to avoid doing too much work to gain too
 * little memory.
 * 
 * 如果 type 是 ACTIVE_EXPIRE_CYCLE_SLOW，执行“慢循环”模式
 * 函数执行时限为 REDIS_HZ 周期的百分比
 * 这个百分比由 ACTIVE_EXPIRE_CYCLE_SLOW_TIME_PERC 指定
 * 
 * 在“快速循环”模式中，如果在数据库中过期键的数据低于某个百分比，
 * 则本次过期键检查将被中断，这样做的目的是避免做太多的工作却获得了少量的内存
 *
 * The configured expire "effort" will modify the baseline parameters in
 * order to do more work in both the fast and slow expire cycles.
 * 
 */

// 每个数据库检查的键数量
#define ACTIVE_EXPIRE_CYCLE_KEYS_PER_LOOP 20 /* Keys for each DB loop. */
// “快速循环”持续时间
#define ACTIVE_EXPIRE_CYCLE_FAST_DURATION 1000 /* Microseconds. */
// “慢循环”最多占用 CPU 资源
#define ACTIVE_EXPIRE_CYCLE_SLOW_TIME_PERC 25 /* Max % of CPU to use. */
// 可容忍的过期键占用百分比
#define ACTIVE_EXPIRE_CYCLE_ACCEPTABLE_STALE 10 /* % of stale keys after which
                                                   we do extra efforts. */

void activeExpireCycle(int type) {
    /* Adjust the running parameters according to the configured expire
     * effort. The default effort is 1, and the maximum configurable effort
     * is 10. */
    /**
     * 根据配置的 active_expire_effort 调整运行参数，默认 active_expire_effort 的值
     * 为 1，其最大可配 10
     */
    // effort 取值范围为 0-9
    unsigned long
    effort = server.active_expire_effort-1, /* Rescale from 0 to 9. */
    // 计算每个数据库检查的键数量
    config_keys_per_loop = ACTIVE_EXPIRE_CYCLE_KEYS_PER_LOOP +
                           ACTIVE_EXPIRE_CYCLE_KEYS_PER_LOOP/4*effort,
    // 计算“快循环”持续时间
    config_cycle_fast_duration = ACTIVE_EXPIRE_CYCLE_FAST_DURATION +
                                 ACTIVE_EXPIRE_CYCLE_FAST_DURATION/4*effort,
    // 计算“慢循环”最多占用 CPU 资源
    config_cycle_slow_time_perc = ACTIVE_EXPIRE_CYCLE_SLOW_TIME_PERC +
                                  2*effort,
    //  计算可容忍的过期键占用百分比
    config_cycle_acceptable_stale = ACTIVE_EXPIRE_CYCLE_ACCEPTABLE_STALE-
                                    effort;

    /* This function has some global state in order to continue the work
     * incrementally across calls. */
    // 上个周期结束时执行到的db
    static unsigned int current_db = 0; /* Next DB to test. */
    // 上一个周期是否因超时而退出
    static int timelimit_exit = 0;      /* Time limit hit in previous call? */
    // 上一个“快周期”的开始运行时间
    static long long last_fast_cycle = 0; /* When last fast cycle ran. */

    int j, iteration = 0;
    // 默认每次处理的数据库数量
    int dbs_per_call = CRON_DBS_PER_CALL;
    // 函数开始时间 
    long long start = ustime(), timelimit, elapsed;

    /* When clients are paused the dataset should be static not just from the
     * POV of clients not being able to write, but also from the POV of
     * expires and evictions of keys not being performed. */
    if (checkClientPauseTimeoutAndReturnIfPaused()) return;

    // 快速模式
    if (type == ACTIVE_EXPIRE_CYCLE_FAST) {
        /* Don't start a fast cycle if the previous cycle did not exit
         * for time limit, unless the percentage of estimated stale keys is
         * too high. Also never repeat a fast cycle for the same period
         * as the fast cycle total duration itself. */

        // 如果上一次循环不是因为超时而结束，且数据库过期键占比小于配置的
        // 可容忍的过期键占比(config_cycle_acceptable_stale)，则不处理
        if (!timelimit_exit &&
            server.stat_expired_stale_perc < config_cycle_acceptable_stale)
            return;
        
        // 如果两次“快速模式”开始的时间间隔小于 2*config_cycle_fast_duration 毫秒，则不处理
        if (start < last_fast_cycle + (long long)config_cycle_fast_duration*2)
            return;

        // 此处“快速模式”的开始时间
        last_fast_cycle = start;
    }

    /* We usually should test CRON_DBS_PER_CALL per iteration, with
     * two exceptions:
     *
     * 1) Don't test more DBs than we have.
     * 2) If last time we hit the time limit, we want to scan all DBs
     * in this iteration, as there is work to do in some DB and we don't want
     * expired keys to use memory for too much time. */
    // 如果每次检查的数据库数目大于数据库的总数目，则检查数据取数据库的数目
    // 如果上次循环因超时而结束，则这次检查所有数据库
    if (dbs_per_call > server.dbnum || timelimit_exit)
        dbs_per_call = server.dbnum;

    /* We can use at max 'config_cycle_slow_time_perc' percentage of CPU
     * time per iteration. Since this function gets called with a frequency of
     * server.hz times per second, the following is the max amount of
     * microseconds we can spend in this function. */
    // 计算“慢循环模式”持续的微秒时间
    // 即 ACTIVE_EXPIRE_CYCLE_SLOW_TIME_PERC + 2*effort 的 CPU 时间
    timelimit = config_cycle_slow_time_perc*1000000/server.hz/100;
    timelimit_exit = 0;
    if (timelimit <= 0) timelimit = 1;
    
    // “快循环模式”
    if (type == ACTIVE_EXPIRE_CYCLE_FAST)
        // “快循环模式”持续的时间
        timelimit = config_cycle_fast_duration; /* in microseconds. */

    /* Accumulate some global stats as we expire keys, to have some idea
     * about the number of keys that are already logically expired, but still
     * existing inside the database. */
    // 总共检查的键数量
    long total_sampled = 0;
    // 总共检查出过期的键数量
    long total_expired = 0;

    for (j = 0; j < dbs_per_call && timelimit_exit == 0; j++) {
        /* Expired and checked in a single loop. */
        // 单次循环检查出的过期键和检查的键
        unsigned long expired, sampled;

        redisDb *db = server.db+(current_db % server.dbnum);

        /* Increment the DB now so we are sure if we run out of time
         * in the current DB we'll restart from the next. This allows to
         * distribute the time evenly across DBs. */
        current_db++;

        /* Continue to expire if at the end of the cycle there are still
         * a big percentage of keys to expire, compared to the number of keys
         * we scanned. The percentage, stored in config_cycle_acceptable_stale
         * is not fixed, but depends on the Redis configured "expire effort". */
        do {
            unsigned long num, slots;
            long long now, ttl_sum;
            int ttl_samples;
            iteration++;

            /* If there is nothing to expire try next DB ASAP. */
            // 获取数据库中带过期时间的节点的数量
            // 如果该数量为 0 ，直接跳过这个数据库
            if ((num = dictSize(db->expires)) == 0) {
                db->avg_ttl = 0;
                break;
            }
            // 存放键过期时间的哈希表大小
            slots = dictSlots(db->expires);
            now = mstime();

            /* When there are less than 1% filled slots, sampling the key
             * space is expensive, so stop here waiting for better times...
             * The dictionary will be resized asap. */
            // 如果字典的节点个数/哈希表大小 < 1，则跳过这个数据库
            // 等待字典 rehash 后再处理
            if (slots > DICT_HT_INITIAL_SIZE &&
                (num*100/slots < 1)) break;

            /* The main collection cycle. Sample random keys among keys
             * with an expire set, checking for expired ones. */
            // 在设置了过期时间的键中随机采样，并检查采样的键是否过期

            // 检测出来的过期键数量
            expired = 0;
            // 总共采样检查的键数量
            sampled = 0;
            // 采样检测键中，没有过期的键的总 ttl
            ttl_sum = 0;
            // 采样检测键中，没有过期的键的数量
            ttl_samples = 0;

            if (num > config_keys_per_loop)
                num = config_keys_per_loop;

            /* Here we access the low level representation of the hash table
             * for speed concerns: this makes this code coupled with dict.c,
             * but it hardly changed in ten years.
             *
             * Note that certain places of the hash table may be empty,
             * so we want also a stop condition about the number of
             * buckets that we scanned. However scanning for free buckets
             * is very fast: we are in the cache line scanning a sequential
             * array of NULL pointers, so we can scan a lot more buckets
             * than keys in the same time. */
            /**
             * 注意：哈希表的某些位置可能为空，因此还需要把扫描桶的数量作为停止条件。
             * 但是扫描空闲桶的速度非常快：因为是在高速缓存线中扫描一系列空指针，所以在
             * 相同时间内扫描的桶比键多得多
             */
            // 每次扫描的键为 num，则最多扫描 num*20 个桶
            long max_buckets = num*20;
            // 检测的桶数量
            long checked_buckets = 0;

            while (sampled < num && checked_buckets < max_buckets) {
                for (int table = 0; table < 2; table++) {
                    if (table == 1 && !dictIsRehashing(db->expires)) break;

                    // 获取本次检测开始位置
                    unsigned long idx = db->expires_cursor;
                    // 计算哈希表桶索引
                    idx &= db->expires->ht[table].sizemask;
                    dictEntry *de = db->expires->ht[table].table[idx];
                    long long ttl;

                    /* Scan the current bucket of the current table. */
                    // 扫描桶数量自增 1 
                    checked_buckets++;
                    while(de) {
                        /* Get the next entry now since this entry may get
                         * deleted. */
                        // 纪录当前结点，并将指针指向后置节点，
                        // 因为这个节点可能在本次过期键检查中被删除
                        dictEntry *e = de;
                        de = de->next;

                        ttl = dictGetSignedIntegerVal(e)-now;
                        // 键过期了，从数据库中删除过期键、值、过期时间，
                        // 并将 expired 自增 1
                        if (activeExpireCycleTryExpire(db,e,now)) expired++;
                        if (ttl > 0) {
                            /* We want the average TTL of keys yet
                             * not expired. */
                            ttl_sum += ttl;
                            ttl_samples++;
                        }
                        sampled++;
                    }
                }
                db->expires_cursor++;
            }
            total_expired += expired;
            total_sampled += sampled;

            /* Update the average TTL stats for this database. */
            // 键平均 TTL
            if (ttl_samples) {
                long long avg_ttl = ttl_sum/ttl_samples;

                /* Do a simple running average with a few samples.
                 * We just use the current estimate with a weight of 2%
                 * and the previous estimate with a weight of 98%. */
                if (db->avg_ttl == 0) db->avg_ttl = avg_ttl;
                db->avg_ttl = (db->avg_ttl/50)*49 + (avg_ttl/50);
            }

            /* We can't block forever here even if there are many keys to
             * expire. So after a given amount of milliseconds return to the
             * caller waiting for the other active expire cycle. */
            /**
             * 为了防止大量过期 key 导致阻塞，所以每 16 次迭代，检查一次过期键检查时间。
             * 如果时间超过了最大时间限制，则退出循环
             */
            if ((iteration & 0xf) == 0) { /* check once every 16 iterations. */
                elapsed = ustime()-start;
                if (elapsed > timelimit) {
                    timelimit_exit = 1;
                    server.stat_expired_time_cap_reached_count++;
                    break;
                }
            }
            /* We don't repeat the cycle for the current database if there are
             * an acceptable amount of stale keys (logically expired but yet
             * not reclaimed). */
        } while (sampled == 0 ||
                 (expired*100/sampled) > config_cycle_acceptable_stale);
    }

    elapsed = ustime()-start;
    // 检查过期键累计消耗微秒数
    server.stat_expire_cycle_time_used += elapsed;
    latencyAddSampleIfNeeded("expire-cycle",elapsed/1000);

    /* Update our estimate of keys existing but yet to be expired.
     * Running average with this sample accounting for 5%. */
    double current_perc;
    if (total_sampled) {
        current_perc = (double)total_expired/total_sampled;
    } else
        current_perc = 0;
    server.stat_expired_stale_perc = (current_perc*0.05)+
                                     (server.stat_expired_stale_perc*0.95);
}

/*-----------------------------------------------------------------------------
 * Expires of keys created in writable slaves
 *
 * Normally slaves do not process expires: they wait the masters to synthesize
 * DEL operations in order to retain consistency. However writable slaves are
 * an exception: if a key is created in the slave and an expire is assigned
 * to it, we need a way to expire such a key, since the master does not know
 * anything about such a key.
 *
 * In order to do so, we track keys created in the slave side with an expire
 * set, and call the expireSlaveKeys() function from time to time in order to
 * reclaim the keys if they already expired.
 *
 * Note that the use case we are trying to cover here, is a popular one where
 * slaves are put in writable mode in order to compute slow operations in
 * the slave side that are mostly useful to actually read data in a more
 * processed way. Think at sets intersections in a tmp key, with an expire so
 * that it is also used as a cache to avoid intersecting every time.
 *
 * This implementation is currently not perfect but a lot better than leaking
 * the keys as implemented in 3.2.
 *----------------------------------------------------------------------------*/

/* The dictionary where we remember key names and database ID of keys we may
 * want to expire from the slave. Since this function is not often used we
 * don't even care to initialize the database at startup. We'll do it once
 * the feature is used the first time, that is, when rememberSlaveKeyWithExpire()
 * is called.
 *
 * The dictionary has an SDS string representing the key as the hash table
 * key, while the value is a 64 bit unsigned integer with the bits corresponding
 * to the DB where the keys may exist set to 1. Currently the keys created
 * with a DB id > 63 are not expired, but a trivial fix is to set the bitmap
 * to the max 64 bit unsigned value when we know there is a key with a DB
 * ID greater than 63, and check all the configured DBs in such a case. */
dict *slaveKeysWithExpire = NULL;

/* Check the set of keys created by the master with an expire set in order to
 * check if they should be evicted. */
void expireSlaveKeys(void) {
    if (slaveKeysWithExpire == NULL ||
        dictSize(slaveKeysWithExpire) == 0) return;

    int cycles = 0, noexpire = 0;
    mstime_t start = mstime();
    while(1) {
        dictEntry *de = dictGetRandomKey(slaveKeysWithExpire);
        sds keyname = dictGetKey(de);
        uint64_t dbids = dictGetUnsignedIntegerVal(de);
        uint64_t new_dbids = 0;

        /* Check the key against every database corresponding to the
         * bits set in the value bitmap. */
        int dbid = 0;
        while(dbids && dbid < server.dbnum) {
            if ((dbids & 1) != 0) {
                redisDb *db = server.db+dbid;
                dictEntry *expire = dictFind(db->expires,keyname);
                int expired = 0;

                if (expire &&
                    activeExpireCycleTryExpire(server.db+dbid,expire,start))
                {
                    expired = 1;
                }

                /* If the key was not expired in this DB, we need to set the
                 * corresponding bit in the new bitmap we set as value.
                 * At the end of the loop if the bitmap is zero, it means we
                 * no longer need to keep track of this key. */
                if (expire && !expired) {
                    noexpire++;
                    new_dbids |= (uint64_t)1 << dbid;
                }
            }
            dbid++;
            dbids >>= 1;
        }

        /* Set the new bitmap as value of the key, in the dictionary
         * of keys with an expire set directly in the writable slave. Otherwise
         * if the bitmap is zero, we no longer need to keep track of it. */
        if (new_dbids)
            dictSetUnsignedIntegerVal(de,new_dbids);
        else
            dictDelete(slaveKeysWithExpire,keyname);

        /* Stop conditions: found 3 keys we can't expire in a row or
         * time limit was reached. */
        cycles++;
        if (noexpire > 3) break;
        if ((cycles % 64) == 0 && mstime()-start > 1) break;
        if (dictSize(slaveKeysWithExpire) == 0) break;
    }
}

/* Track keys that received an EXPIRE or similar command in the context
 * of a writable slave. */
void rememberSlaveKeyWithExpire(redisDb *db, robj *key) {
    if (slaveKeysWithExpire == NULL) {
        static dictType dt = {
            dictSdsHash,                /* hash function */
            NULL,                       /* key dup */
            NULL,                       /* val dup */
            dictSdsKeyCompare,          /* key compare */
            dictSdsDestructor,          /* key destructor */
            NULL,                       /* val destructor */
            NULL                        /* allow to expand */
        };
        slaveKeysWithExpire = dictCreate(&dt,NULL);
    }
    if (db->id > 63) return;

    dictEntry *de = dictAddOrFind(slaveKeysWithExpire,key->ptr);
    /* If the entry was just created, set it to a copy of the SDS string
     * representing the key: we don't want to need to take those keys
     * in sync with the main DB. The keys will be removed by expireSlaveKeys()
     * as it scans to find keys to remove. */
    if (de->key == key->ptr) {
        de->key = sdsdup(key->ptr);
        dictSetUnsignedIntegerVal(de,0);
    }

    uint64_t dbids = dictGetUnsignedIntegerVal(de);
    dbids |= (uint64_t)1 << db->id;
    dictSetUnsignedIntegerVal(de,dbids);
}

/* Return the number of keys we are tracking. */
size_t getSlaveKeyWithExpireCount(void) {
    if (slaveKeysWithExpire == NULL) return 0;
    return dictSize(slaveKeysWithExpire);
}

/* Remove the keys in the hash table. We need to do that when data is
 * flushed from the server. We may receive new keys from the master with
 * the same name/db and it is no longer a good idea to expire them.
 *
 * Note: technically we should handle the case of a single DB being flushed
 * but it is not worth it since anyway race conditions using the same set
 * of key names in a writable slave and in its master will lead to
 * inconsistencies. This is just a best-effort thing we do. */
void flushSlaveKeysWithExpireList(void) {
    if (slaveKeysWithExpire) {
        dictRelease(slaveKeysWithExpire);
        slaveKeysWithExpire = NULL;
    }
}

int checkAlreadyExpired(long long when) {
    /* EXPIRE with negative TTL, or EXPIREAT with a timestamp into the past
     * should never be executed as a DEL when load the AOF or in the context
     * of a slave instance.
     *
     * Instead we add the already expired key to the database with expire time
     * (possibly in the past) and wait for an explicit DEL from the master. */
    return (when <= mstime() && !server.loading && !server.masterhost);
}

/*-----------------------------------------------------------------------------
 * Expires Commands
 *----------------------------------------------------------------------------*/
// Expires 命令
/* This is the generic command implementation for EXPIRE, PEXPIRE, EXPIREAT
 * and PEXPIREAT. Because the command second argument may be relative or absolute
 * the "basetime" argument is used to signal what the base time is (either 0
 * for *AT variants of the command, or the current time for relative expires).
 *
 * unit is either UNIT_SECONDS or UNIT_MILLISECONDS, and is only used for
 * the argv[2] parameter. The basetime is always specified in milliseconds. */
void expireGenericCommand(client *c, long long basetime, int unit) {
    robj *key = c->argv[1], *param = c->argv[2];
    long long when; /* unix time in milliseconds when the key will expire. */

    if (getLongLongFromObjectOrReply(c, param, &when, NULL) != C_OK)
        return;
    int negative_when = when < 0;
    // 将秒转化为毫秒
    if (unit == UNIT_SECONDS) when *= 1000;
    when += basetime;
    if (((when < 0) && !negative_when) || ((when-basetime > 0) && negative_when)) {
        /* EXPIRE allows negative numbers, but we can at least detect an
         * overflow by either unit conversion or basetime addition. */
        addReplyErrorFormat(c, "invalid expire time in %s", c->cmd->name);
        return;
    }
    /* No key, return zero. */
    if (lookupKeyWrite(c->db,key) == NULL) {
        addReply(c,shared.czero);
        return;
    }

    if (checkAlreadyExpired(when)) {
        robj *aux;

        int deleted = server.lazyfree_lazy_expire ? dbAsyncDelete(c->db,key) :
                                                    dbSyncDelete(c->db,key);
        serverAssertWithInfo(c,key,deleted);
        server.dirty++;

        /* Replicate/AOF this as an explicit DEL or UNLINK. */
        aux = server.lazyfree_lazy_expire ? shared.unlink : shared.del;
        rewriteClientCommandVector(c,2,aux,key);
        signalModifiedKey(c,c->db,key);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"del",key,c->db->id);
        addReply(c, shared.cone);
        return;
    } else {
        setExpire(c,c->db,key,when);
        addReply(c,shared.cone);
        signalModifiedKey(c,c->db,key);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"expire",key,c->db->id);
        server.dirty++;
        return;
    }
}

/* EXPIRE key seconds */
void expireCommand(client *c) {
    expireGenericCommand(c,mstime(),UNIT_SECONDS);
}

/* EXPIREAT key time */
void expireatCommand(client *c) {
    expireGenericCommand(c,0,UNIT_SECONDS);
}

/* PEXPIRE key milliseconds */
void pexpireCommand(client *c) {
    expireGenericCommand(c,mstime(),UNIT_MILLISECONDS);
}

/* PEXPIREAT key ms_time */
void pexpireatCommand(client *c) {
    expireGenericCommand(c,0,UNIT_MILLISECONDS);
}

/* Implements TTL and PTTL */
void ttlGenericCommand(client *c, int output_ms) {
    long long expire, ttl = -1;

    /* If the key does not exist at all, return -2 */
    if (lookupKeyReadWithFlags(c->db,c->argv[1],LOOKUP_NOTOUCH) == NULL) {
        addReplyLongLong(c,-2);
        return;
    }
    /* The key exists. Return -1 if it has no expire, or the actual
     * TTL value otherwise. */
    expire = getExpire(c->db,c->argv[1]);
    if (expire != -1) {
        ttl = expire-mstime();
        if (ttl < 0) ttl = 0;
    }
    if (ttl == -1) {
        addReplyLongLong(c,-1);
    } else {
        addReplyLongLong(c,output_ms ? ttl : ((ttl+500)/1000));
    }
}

/* TTL key */
void ttlCommand(client *c) {
    ttlGenericCommand(c, 0);
}

/* PTTL key */
void pttlCommand(client *c) {
    ttlGenericCommand(c, 1);
}

/* PERSIST key */
/**
 * 移除 key 的过期时间
 * 使 key 永不过期
 */
void persistCommand(client *c) {
    if (lookupKeyWrite(c->db,c->argv[1])) {
        if (removeExpire(c->db,c->argv[1])) {
            signalModifiedKey(c,c->db,c->argv[1]);
            notifyKeyspaceEvent(NOTIFY_GENERIC,"persist",c->argv[1],c->db->id);
            addReply(c,shared.cone);
            server.dirty++;
        } else {
            addReply(c,shared.czero);
        }
    } else {
        addReply(c,shared.czero);
    }
}

/* TOUCH key1 [key2 key3 ... keyN] */
void touchCommand(client *c) {
    int touched = 0;
    for (int j = 1; j < c->argc; j++)
        if (lookupKeyRead(c->db,c->argv[j]) != NULL) touched++;
    addReplyLongLong(c,touched);
}

