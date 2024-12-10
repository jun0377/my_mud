#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mud.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <sodium.h>
#include "aegis256/aegis256.h"

#if !defined MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if defined __linux__
#define MUD_V4V6 1
#else
#define MUD_V4V6 0
#endif

#if defined __APPLE__
#include <mach/mach_time.h>
#endif

#if defined IP_PKTINFO
#define MUD_PKTINFO IP_PKTINFO
// 源地址指针
#define MUD_PKTINFO_SRC(X) &((struct in_pktinfo *)(X))->ipi_addr
// 目标地址指针
#define MUD_PKTINFO_DST(X) &((struct in_pktinfo *)(X))->ipi_spec_dst

#define MUD_PKTINFO_SIZE sizeof(struct in_pktinfo)
#elif defined IP_RECVDSTADDR
#define MUD_PKTINFO IP_RECVDSTADDR
#define MUD_PKTINFO_SRC(X) (X)
#define MUD_PKTINFO_DST(X) (X)
#define MUD_PKTINFO_SIZE sizeof(struct in_addr)
#endif

#if defined IP_MTU_DISCOVER
#define MUD_DFRAG IP_MTU_DISCOVER
#define MUD_DFRAG_OPT IP_PMTUDISC_PROBE
#elif defined IP_DONTFRAG
#define MUD_DFRAG IP_DONTFRAG
#define MUD_DFRAG_OPT 1
#endif

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC  (1000 * MUD_ONE_MSEC)
#define MUD_ONE_MIN  (60 * MUD_ONE_SEC)


// 限制时间戳为48位，避免溢出; 
// 网络传输时节省带宽，因为只需要传输6byte而不是8byte
#define MUD_TIME_SIZE    (6U)                           // 6 byte
#define MUD_TIME_BITS    (MUD_TIME_SIZE * 8U)           // 48 bit
#define MUD_TIME_MASK(X) ((X) & ((UINT64_C(1) << MUD_TIME_BITS) - 2))

#define MUD_KEY_SIZE (32U)
#define MUD_MAC_SIZE (16U)

// 获取消息标识
#define MUD_MSG(X)       ((X) & UINT64_C(1))
// 给消息打上标识
#define MUD_MSG_MARK(X)  ((X) | UINT64_C(1))
// 消息发送的最大次数
#define MUD_MSG_SENT_MAX (5)

#define MUD_PKT_MIN_SIZE (MUD_TIME_SIZE + MUD_MAC_SIZE)  // 6 + 16 = 22byte
#define MUD_PKT_MAX_SIZE (1500U)

#define MUD_MTU_MIN ( 576U + MUD_PKT_MIN_SIZE)
#define MUD_MTU_MAX (1450U + MUD_PKT_MIN_SIZE)

#define MUD_CTRL_SIZE (CMSG_SPACE(MUD_PKTINFO_SIZE) + \
                       CMSG_SPACE(sizeof(struct in6_pktinfo)))

#define MUD_STORE_MSG(D,S) mud_store((D),(S),sizeof(D))
#define MUD_LOAD_MSG(S)    mud_load((S),sizeof(S))

struct mud_crypto_opt {
    unsigned char *dst;
    const unsigned char *src;
    size_t size;
};

struct mud_crypto_key {
    struct {
        unsigned char key[MUD_KEY_SIZE];
    } encrypt, decrypt;
    int aes;
};

// 兼容IPv4/IPv6的地址结构体
struct mud_addr {
    union {
        unsigned char v6[16];
        struct {
            unsigned char zero[10];
            unsigned char ff[2];
            unsigned char v4[4];
        };
    };
    unsigned char port[2];
};

// 自定义msg格式
struct mud_msg {
    unsigned char sent_time[MUD_TIME_SIZE];     // 发送时间戳
    unsigned char aes;                          // aes加密
    unsigned char pkey[MUD_PUBKEY_SIZE];        // 密钥
    struct {
        unsigned char bytes[sizeof(uint64_t)];  // 本地发送/接收字节数
        unsigned char total[sizeof(uint64_t)];  // 总发送/接收包数
    } tx, rx, fw;                               // 发送/接收/
    unsigned char max_rate[sizeof(uint64_t)];   // 最大码率
    unsigned char beat[MUD_TIME_SIZE];          // 心跳
    unsigned char mtu[2];                       // mtu
    unsigned char pref;                         // 优先级
    unsigned char loss;                         // 丢包率
    unsigned char fixed_rate;                   // 固定码率
    unsigned char loss_limit;                   // 修包限制
    struct mud_addr addr;                       // 地址
};

struct mud_keyx {
    uint64_t time;
    unsigned char secret[crypto_scalarmult_SCALARBYTES];
    unsigned char remote[MUD_PUBKEY_SIZE];
    unsigned char local[MUD_PUBKEY_SIZE];
    struct mud_crypto_key private, last, next, current;
    int use_next;
    int aes;
};

struct mud {
    int fd;                 // UDP套接字
    struct mud_conf conf;   // mud配置
    struct mud_path *paths; // 路径数组
    unsigned pref;          // 全局路径优先级
    unsigned capacity;      // 路径数量
    struct mud_keyx keyx;
    uint64_t last_recv_time;    // 最后一次收到数据的时间戳
    size_t mtu;                 // mtu
    struct mud_errors err;      // 错误统计
    uint64_t rate;              // 码率
    uint64_t window;            // 流控窗口大小
    uint64_t window_time;       // 流控窗口更新的时间戳
    uint64_t base_time;
#if defined __APPLE__
    mach_timebase_info_data_t mtid;
#endif
};

// 加密选项
static inline int
mud_encrypt_opt(const struct mud_crypto_key *k,
                const struct mud_crypto_opt *c)
{
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, c->dst, MUD_TIME_SIZE);
        return aegis256_encrypt(
            c->dst + MUD_TIME_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_TIME_SIZE,
            npub,
            k->encrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, c->dst, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_encrypt(
            c->dst + MUD_TIME_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_TIME_SIZE,
            NULL,
            npub,
            k->encrypt.key
        );
    }
}

// 解密选项
static inline int
mud_decrypt_opt(const struct mud_crypto_key *k,
                const struct mud_crypto_opt *c)
{
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, c->src, MUD_TIME_SIZE);
        return aegis256_decrypt(
            c->dst,
            NULL,
            c->src + MUD_TIME_SIZE,
            c->size - MUD_TIME_SIZE,
            c->src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, c->src, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_decrypt(
            c->dst,
            NULL,
            NULL,
            c->src + MUD_TIME_SIZE,
            c->size - MUD_TIME_SIZE,
            c->src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    }
}

// 将一个uint64_t类型的数据存储到一个unsigned char数组中
static inline void
mud_store(unsigned char *dst, uint64_t src, size_t size)
{
    dst[0] = (unsigned char)(src);
    dst[1] = (unsigned char)(src >> 8);
    if (size <= 2) return;
    dst[2] = (unsigned char)(src >> 16);
    dst[3] = (unsigned char)(src >> 24);
    dst[4] = (unsigned char)(src >> 32);
    dst[5] = (unsigned char)(src >> 40);
    if (size <= 6) return;
    dst[6] = (unsigned char)(src >> 48);
    dst[7] = (unsigned char)(src >> 56);
}

// 从一个unsigned char数组中加载一个uint64_t类型的数据
static inline uint64_t
mud_load(const unsigned char *src, size_t size)
{
    uint64_t ret = 0;
    ret = src[0];
    ret |= ((uint64_t)src[1]) << 8;
    if (size <= 2) return ret;
    ret |= ((uint64_t)src[2]) << 16;
    ret |= ((uint64_t)src[3]) << 24;
    ret |= ((uint64_t)src[4]) << 32;
    ret |= ((uint64_t)src[5]) << 40;
    if (size <= 6) return ret;
    ret |= ((uint64_t)src[6]) << 48;
    ret |= ((uint64_t)src[7]) << 56;
    return ret;
}

// 获取当前时间戳, 精确到us
static inline uint64_t
mud_time(void)
{
#if defined CLOCK_REALTIME
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_usec);
#endif
}

// 获取当前时间戳,精确到us
static inline uint64_t
mud_now(struct mud *mud)
{
#if defined __APPLE__
    return MUD_TIME_MASK(mud->base_time
            + (mach_absolute_time() * mud->mtid.numer / mud->mtid.denom)
            / 1000ULL);
#elif defined CLOCK_MONOTONIC
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return MUD_TIME_MASK(mud->base_time
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    return mud_time();
#endif
}

// 计算两个值之差的绝对值
static inline uint64_t
mud_abs_diff(uint64_t a, uint64_t b)
{
    return (a >= b) ? a - b : b - a;
}

// 判断是否超时，单位us; now - last > timeout
static inline int
mud_timeout(uint64_t now, uint64_t last, uint64_t timeout)
{
    return (!last) || (MUD_TIME_MASK(now - last) >= timeout);
}

// IPv6地址转换
static inline void
mud_unmapv4(union mud_sockaddr *addr)
{
    if (addr->sa.sa_family != AF_INET6)
        return;

    if (!IN6_IS_ADDR_V4MAPPED(&addr->sin6.sin6_addr))
        return;

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = addr->sin6.sin6_port,
    };
    memcpy(&sin.sin_addr.s_addr,
           &addr->sin6.sin6_addr.s6_addr[12],
           sizeof(sin.sin_addr.s_addr));

    addr->sin = sin;
}

// 路径选择
static struct mud_path *
mud_select_path(struct mud *mud, uint16_t cursor)
{
    // 路径选择指标，这个指标是如何计算的
    uint64_t k = (cursor * mud->rate) >> 16;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        // 跳过状态不是RUNNING的路径
        if (path->status != MUD_RUNNING)
            continue;

        // 选择路径
        if (k < path->tx.rate)
            return path;

        // 更新路径选择指标，继续检查下一个路径
        k -= path->tx.rate;
    }
    return NULL;
}

// 使用指定路径发送数据
static int
mud_send_path(struct mud *mud, struct mud_path *path, uint64_t now,
              void *data, size_t size, int flags)
{
    if (!size || !path)
        return 0;

    // 控制信息
    unsigned char ctrl[MUD_CTRL_SIZE];
    memset(ctrl, 0, sizeof(ctrl));

    // 数据包的包头
    struct msghdr msg = {
        .msg_iov = &(struct iovec) {
            .iov_base = data,
            .iov_len = size,
        },
        .msg_iovlen = 1,
        .msg_control = ctrl,
    };

    // 对端地址为IPv4
    if (path->conf.remote.sa.sa_family == AF_INET) {

        // 对端地址
        msg.msg_name = &path->conf.remote.sin;
        // 对端地址长度
        msg.msg_namelen = sizeof(struct sockaddr_in);
        // 控制信息长度
        msg.msg_controllen = CMSG_SPACE(MUD_PKTINFO_SIZE);

        // 控制信息
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        // IP层
        cmsg->cmsg_level = IPPROTO_IP;
        // 
        cmsg->cmsg_type = MUD_PKTINFO;
        // 
        cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);
        // 本地地址
        memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
               &path->conf.local.sin.sin_addr,
               sizeof(struct in_addr));
    } 
    // 对端地址为IPv6
    else if (path->conf.remote.sa.sa_family == AF_INET6) {
        msg.msg_name = &path->conf.remote.sin6;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &path->conf.local.sin6.sin6_addr,
               sizeof(struct in6_addr));
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }

    // 通过UDP发送msg
    ssize_t ret = sendmsg(mud->fd, &msg, flags);

    // 发送统计
    path->tx.total++;
    path->tx.bytes += size;
    path->tx.time = now;

    // 更新流控窗口
    if (mud->window > size) {
        mud->window -= size;
    } else {
        mud->window = 0;
    }
    return (int)ret;
}

// 设置socket选项
static int
mud_sso_int(int fd, int level, int optname, int opt)
{
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

// 两个地址是否相同
static inline int
mud_cmp_addr(union mud_sockaddr *a, union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                      sizeof(a->sin.sin_addr));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                      sizeof(a->sin6.sin6_addr));
    return 1;
}

// 两个端口是否相同
static inline int
mud_cmp_port(union mud_sockaddr *a, union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_port, &b->sin.sin_port,
                      sizeof(a->sin.sin_port));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_port, &b->sin6.sin6_port,
                      sizeof(a->sin6.sin6_port));
    return 1;
}

// 根据本地地址或远端地址来获取路径
int
mud_get_paths(struct mud *mud, struct mud_paths *paths,
              union mud_sockaddr *local, union mud_sockaddr *remote)
{
    if (!paths) {
        errno = EINVAL;
        return -1;
    }
    unsigned count = 0;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (local && local->sa.sa_family &&
            mud_cmp_addr(local, &path->conf.local))
            continue;

        if (remote && remote->sa.sa_family &&
            (mud_cmp_addr(remote, &path->conf.remote) ||
             mud_cmp_port(remote, &path->conf.remote)))
            continue;

        if (path->conf.state != MUD_EMPTY)
            paths->path[count++] = *path;
    }
    paths->count = count;
    return 0;
}

// 获取指定路径
static struct mud_path *
mud_get_path(struct mud *mud,
             union mud_sockaddr *local,
             union mud_sockaddr *remote,
             enum mud_state state)
{
    // 本地地址和远端地址的协议族不一致
    if (local->sa.sa_family != remote->sa.sa_family) {
        errno = EINVAL;
        return NULL;
    }

    // 遍历所有路径
    for (unsigned i = 0; i < mud->capacity; i++) {

        // 获取路径
        struct mud_path *path = &mud->paths[i];

        // 路径状态为空，说明没有初始化
        if (path->conf.state == MUD_EMPTY)
            continue;

        // 不是指定的路径，continue
        if (mud_cmp_addr(local, &path->conf.local)   ||
            mud_cmp_addr(remote, &path->conf.remote) ||
            mud_cmp_port(remote, &path->conf.remote))
            continue;

        // 成功找到指定的路径
        return path;
    }

    // 路径状态小于等于MUD_DOWN，说明路径没有初始化或已关闭
    if (state <= MUD_DOWN) {
        errno = 0;
        return NULL;
    }

    // 到这一步说明没有找到指定的路径，创建之

    struct mud_path *path = NULL;

    // 从数组中找到一个空路径
    for (unsigned i = 0; i < mud->capacity; i++) {
        if (mud->paths[i].conf.state == MUD_EMPTY) {
            path = &mud->paths[i];
            break;
        }
    }

    // 没有找到空路径，数组需要扩容
    if (!path) {

        // 最多32个路径
        if (mud->capacity == MUD_PATH_MAX) {
            errno = ENOMEM;
            return NULL;
        }

        // 数组扩容
        struct mud_path *paths = realloc(mud->paths,
                (mud->capacity + 1) * sizeof(struct mud_path));

        if (!paths)
            return NULL;

        path = &paths[mud->capacity];

        mud->capacity++;
        mud->paths = paths;
    }
    memset(path, 0, sizeof(struct mud_path));

    // 新路径默认配置
    path->conf.local      = *local;
    path->conf.remote     = *remote;
    path->conf.state      = state;
    path->conf.beat       = 100 * MUD_ONE_MSEC; // 心跳时间间隔，100 ms
    path->conf.fixed_rate = 1;
    path->conf.loss_limit = 255;
    path->status          = MUD_PROBING;
    path->idle            = mud_now(mud);

    return path;
}

// 错误信息
int
mud_get_errors(struct mud *mud, struct mud_errors *err)
{
    if (!err) {
        errno = EINVAL;
        return -1;
    }
    memcpy(err, &mud->err, sizeof(struct mud_errors));
    return 0;
}

// mud配置
int
mud_set(struct mud *mud, struct mud_conf *conf)
{
    struct mud_conf c = mud->conf;

    if (conf->keepalive)     c.keepalive     = conf->keepalive;
    if (conf->timetolerance) c.timetolerance = conf->timetolerance;
    if (conf->kxtimeout)     c.kxtimeout     = conf->kxtimeout;

    *conf = mud->conf = c;
    return 0;
}

// 获取MTU
size_t
mud_get_mtu(struct mud *mud)
{
    if (!mud->mtu)
        return 0;

    return mud->mtu - MUD_PKT_MIN_SIZE;
}

// 设置socket选项
static int
mud_setup_socket(int fd, int v4, int v6)
{
    if ((mud_sso_int(fd, SOL_SOCKET, SO_REUSEADDR, 1)) ||
        (v4 && mud_sso_int(fd, IPPROTO_IP, MUD_PKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, !v4)))
        return -1;

#if defined MUD_DFRAG
    if (v4)
        mud_sso_int(fd, IPPROTO_IP, MUD_DFRAG, MUD_DFRAG_OPT);
#endif
    return 0;
}

// 哈希密钥
static void
mud_hash_key(unsigned char *dst, unsigned char *key, unsigned char *secret,
             unsigned char *pk0, unsigned char *pk1)
{
    crypto_generichash_state state;

    crypto_generichash_init(&state, key, MUD_KEY_SIZE, MUD_KEY_SIZE);
    crypto_generichash_update(&state, secret, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, pk0, MUD_PUBKEY_SIZE);
    crypto_generichash_update(&state, pk1, MUD_PUBKEY_SIZE);
    crypto_generichash_final(&state, dst, MUD_KEY_SIZE);

    sodium_memzero(&state, sizeof(state));
}

static int
mud_keyx(struct mud_keyx *kx, unsigned char *remote, int aes)
{
    unsigned char secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(secret, kx->secret, remote))
        return 1;

    mud_hash_key(kx->next.encrypt.key,
                 kx->private.encrypt.key,
                 secret, remote, kx->local);

    mud_hash_key(kx->next.decrypt.key,
                 kx->private.encrypt.key,
                 secret, kx->local, remote);

    sodium_memzero(secret, sizeof(secret));

    memcpy(kx->remote, remote, MUD_PUBKEY_SIZE);
    kx->next.aes = kx->aes && aes;

    return 0;
}

static int
mud_keyx_init(struct mud *mud, uint64_t now)
{
    struct mud_keyx *kx = &mud->keyx;

    if (!mud_timeout(now, kx->time, mud->conf.kxtimeout))
        return 1;

    static const unsigned char test[crypto_scalarmult_BYTES] = {
        0x9b, 0xf4, 0x14, 0x90, 0x0f, 0xef, 0xf8, 0x2d, 0x11, 0x32, 0x6e,
        0x3d, 0x99, 0xce, 0x96, 0xb9, 0x4f, 0x79, 0x31, 0x01, 0xab, 0xaf,
        0xe3, 0x03, 0x59, 0x1a, 0xcd, 0xdd, 0xb0, 0xfb, 0xe3, 0x49
    };
    unsigned char tmp[crypto_scalarmult_BYTES];

    do {
        randombytes_buf(kx->secret, sizeof(kx->secret));
        crypto_scalarmult_base(kx->local, kx->secret);
    } while (crypto_scalarmult(tmp, test, kx->local));

    sodium_memzero(tmp, sizeof(tmp));
    kx->time = now;

    return 0;
}

// 创建mud实例
struct mud *
mud_create(union mud_sockaddr *addr, unsigned char *key, int *aes)
{
    if (!addr || !key || !aes)
        return NULL;

    int v4, v6;
    socklen_t addrlen = 0;

    // IPv4 / IPv6
    switch (addr->sa.sa_family) {
    case AF_INET:
        addrlen = sizeof(struct sockaddr_in);
        v4 = 1;
        v6 = 0;
        break;
    case AF_INET6:
        addrlen = sizeof(struct sockaddr_in6);
        v4 = MUD_V4V6;
        v6 = 1;
        break;
    default:
        return NULL;
    }

    // 初始化加/解密库libsodium
    if (sodium_init() == -1)
        return NULL;

    // 分配mud实例内存
    struct mud *mud = sodium_malloc(sizeof(struct mud));

    if (!mud)
        return NULL;

    memset(mud, 0, sizeof(struct mud));

    // 创建UDP套接字
    mud->fd = socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

    // 必须进行bind
    if ((mud->fd == -1) ||
        (mud_setup_socket(mud->fd, v4, v6)) ||
        (bind(mud->fd, &addr->sa, addrlen)) ||
        (getsockname(mud->fd, &addr->sa, &addrlen))) {
        mud_delete(mud);
        return NULL;
    }

    // 保活时间
    mud->conf.keepalive     = 25 * MUD_ONE_SEC;
    // 容忍时间
    mud->conf.timetolerance = 10 * MUD_ONE_MIN;
    // 密钥交换超时时间
    mud->conf.kxtimeout     = 60 * MUD_ONE_MIN;

    // mac os, 先忽略
#if defined __APPLE__
    mach_timebase_info(&mud->mtid);
#endif

    // 这段逻辑有什么用???
    uint64_t now = mud_now(mud);
    uint64_t base_time = mud_time();
    if (base_time > now)
        mud->base_time = base_time - now;

    // 加解密使用的密钥
    memcpy(mud->keyx.private.encrypt.key, key, MUD_KEY_SIZE);
    memcpy(mud->keyx.private.decrypt.key, key, MUD_KEY_SIZE);
    sodium_memzero(key, MUD_KEY_SIZE);

    mud->keyx.current = mud->keyx.private;
    mud->keyx.next = mud->keyx.private;
    mud->keyx.last = mud->keyx.private;

    if (*aes && !aegis256_is_available())
        *aes = 0;

    mud->keyx.aes = *aes;
    return mud;
}

// 获取UDP套接字
int
mud_get_fd(struct mud *mud)
{
    if (!mud)
        return -1;

    return mud->fd;
}

// 删除mud实例
void
mud_delete(struct mud *mud)
{
    if (!mud)
        return;

    if (mud->paths)
        free(mud->paths);

    if (mud->fd >= 0)
        close(mud->fd);

    sodium_free(mud);
}

// 加密
static size_t
mud_encrypt(struct mud *mud, uint64_t now,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    const size_t size = src_size + MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    mud_store(dst, now, MUD_TIME_SIZE);

    if (mud->keyx.use_next) {
        mud_encrypt_opt(&mud->keyx.next, &opt);
    } else {
        mud_encrypt_opt(&mud->keyx.current, &opt);
    }
    return size;
}

// 解密
static size_t
mud_decrypt(struct mud *mud,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    if (mud_decrypt_opt(&mud->keyx.current, &opt)) {
        if (!mud_decrypt_opt(&mud->keyx.next, &opt)) {
            mud->keyx.last = mud->keyx.current;
            mud->keyx.current = mud->keyx.next;
            mud->keyx.use_next = 0;
        } else {
            if (mud_decrypt_opt(&mud->keyx.last, &opt) &&
                mud_decrypt_opt(&mud->keyx.private, &opt))
                return 0;
        }
    }
    return size;
}

// 从msg包头中获取本地地址
static int
mud_localaddr(union mud_sockaddr *addr, struct msghdr *msg)
{
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == MUD_PKTINFO)) {
            addr->sa.sa_family = AF_INET;
            memcpy(&addr->sin.sin_addr,
                   MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
                   sizeof(struct in_addr));
            return 0;
        }
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            addr->sa.sa_family = AF_INET6;
            memcpy(&addr->sin6.sin6_addr,
                   &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                   sizeof(struct in6_addr));
            mud_unmapv4(addr);
            return 0;
        }
    }
    return 1;
}

// 是否是IPv6地址
static int
mud_addr_is_v6(struct mud_addr *addr)
{
    static const unsigned char v4mapped[] = {
        [10] = 255,
        [11] = 255,
    };
    return memcmp(addr->v6, v4mapped, sizeof(v4mapped));
}

// 从套接字获取地址
static int
mud_addr_from_sock(struct mud_addr *addr, union mud_sockaddr *sock)
{
    if (sock->sa.sa_family == AF_INET) {
        memset(addr->zero, 0, sizeof(addr->zero));
        memset(addr->ff, 0xFF, sizeof(addr->ff));
        memcpy(addr->v4, &sock->sin.sin_addr, 4);
        memcpy(addr->port, &sock->sin.sin_port, 2);
    } else if (sock->sa.sa_family == AF_INET6) {
        memcpy(addr->v6, &sock->sin6.sin6_addr, 16);
        memcpy(addr->port, &sock->sin6.sin6_port, 2);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return 0;
}

// 从地址获取地址
static void
mud_sock_from_addr(union mud_sockaddr *sock, struct mud_addr *addr)
{
    if (mud_addr_is_v6(addr)) {
        sock->sin6.sin6_family = AF_INET6;
        memcpy(&sock->sin6.sin6_addr, addr->v6, 16);
        memcpy(&sock->sin6.sin6_port, addr->port, 2);
    } else {
        sock->sin.sin_family = AF_INET;
        memcpy(&sock->sin.sin_addr, addr->v4, 4);
        memcpy(&sock->sin.sin_port, addr->port, 2);
    }
}

// 发送msg包
static int
mud_send_msg(struct mud *mud, struct mud_path *path, uint64_t now,
             uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total,
             size_t size)
{
    unsigned char dst[MUD_PKT_MAX_SIZE];
    unsigned char src[MUD_PKT_MAX_SIZE] = {0};
    struct mud_msg *msg = (struct mud_msg *)src;

    if (size < MUD_PKT_MIN_SIZE + sizeof(struct mud_msg))
        size = MUD_PKT_MIN_SIZE + sizeof(struct mud_msg);

    mud_store(dst, MUD_MSG_MARK(now), MUD_TIME_SIZE);
    MUD_STORE_MSG(msg->sent_time, sent_time);

    if (mud_addr_from_sock(&msg->addr, &path->conf.remote))
        return -1;

    memcpy(msg->pkey, mud->keyx.local, sizeof(mud->keyx.local));
    msg->aes = (unsigned char)mud->keyx.aes;

    if (!path->mtu.probe)
        MUD_STORE_MSG(msg->mtu, path->mtu.last);

    MUD_STORE_MSG(msg->tx.bytes, path->tx.bytes);
    MUD_STORE_MSG(msg->rx.bytes, path->rx.bytes);
    MUD_STORE_MSG(msg->tx.total, path->tx.total);
    MUD_STORE_MSG(msg->rx.total, path->rx.total);
    MUD_STORE_MSG(msg->fw.bytes, fw_bytes);
    MUD_STORE_MSG(msg->fw.total, fw_total);
    MUD_STORE_MSG(msg->max_rate, path->conf.rx_max_rate);
    MUD_STORE_MSG(msg->beat, path->conf.beat);

    msg->loss = (unsigned char)path->tx.loss;
    msg->pref = path->conf.pref;
    msg->fixed_rate = path->conf.fixed_rate;
    msg->loss_limit = path->conf.loss_limit;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = size - MUD_PKT_MIN_SIZE,
    };
    mud_encrypt_opt(&mud->keyx.private, &opt);

    return mud_send_path(mud, path, now, dst, size,
                         sent_time ? MSG_CONFIRM : 0);
}

// 解密msg包
static size_t
mud_decrypt_msg(struct mud *mud,
                unsigned char *dst, size_t dst_size,
                const unsigned char *src, size_t src_size)
{
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size < sizeof(struct mud_msg) || size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    if (mud_decrypt_opt(&mud->keyx.private, &opt))
        return 0;

    return size;
}

/* 
    更新路径参数: 发送速率和丢包率
    tx_dt: 对端两次发送的时间戳差值
    tx_bytes: 对端两次发送间隔的字节数
    tx_pkt: 对端两次发送间隔的包数
    rx_dt：对端两次接收的时间戳差值
    rx_bytes：对端两次接收间隔的字节数
    rx_pkt：对端两次接收间隔的包数
*/
static void
mud_update_rl(struct mud *mud, struct mud_path *path, uint64_t now,
              uint64_t tx_dt, uint64_t tx_bytes, uint64_t tx_pkt,
              uint64_t rx_dt, uint64_t rx_bytes, uint64_t rx_pkt)
{

    // 根据接收时间和发送时间的差值来调整传输速率: 两次接收的时间间隔 > (两次发送的时间间隔 * 1.125)
    if (rx_dt && rx_dt > tx_dt + (tx_dt >> 3)) {

        // 用户没有配置固定传输速率，计算发送速率
        if (!path->conf.fixed_rate){
            path->tx.rate = (7 * rx_bytes * MUD_ONE_SEC) / (8 * rx_dt);
        }

    } else {

        // 累计发送的包数
        uint64_t tx_acc = path->msg.tx.acc + tx_pkt;
        // 累计接收的包数
        uint64_t rx_acc = path->msg.rx.acc + rx_pkt;

        // 累计发送超过1000个包， 统计丢包率
        if (tx_acc > 1000) {
            
            // 如果发送的包数大于等于接收的包数，则计算丢包率; 这个判断条件的原因
            if (tx_acc >= rx_acc){
                path->tx.loss = (tx_acc - rx_acc) * 255U / tx_acc;
            }

            // 更新累计发送/接收的包数，更新为当前值的 15/16 = 0.9375;避免过多历史数据
            path->msg.tx.acc = tx_acc - (tx_acc >> 4);
            path->msg.rx.acc = rx_acc - (rx_acc >> 4);

        } 
        // 更新累计发送/接收的包数
        else {
            path->msg.tx.acc = tx_acc;
            path->msg.rx.acc = rx_acc;
        }

        // 用户没有配置固定传输速率，则将当前的发送速率增加10%
        if (!path->conf.fixed_rate)
            path->tx.rate += path->tx.rate / 10;
    }

    // 发送速率不能超过配置的最大传输速率
    if (path->tx.rate > path->conf.tx_max_rate)
        path->tx.rate = path->conf.tx_max_rate;
}

// MTU探测更新
static void
mud_update_mtu(struct mud_path *path, size_t size)
{
    // 没有进行MTU探测
    if (!path->mtu.probe) {

        // 没有已记录的MTU，设置为默认值
        if (!path->mtu.last) {
            path->mtu.min = MUD_MTU_MIN;
            path->mtu.max = MUD_MTU_MAX;
            path->mtu.probe = MUD_MTU_MAX;
        }
        return;
    }


    if (size) {

        // 
        if (path->mtu.min > size || path->mtu.max < size)
            return;

        path->mtu.min = size + 1;
        path->mtu.last = size;
    } else {
        path->mtu.max = path->mtu.probe - 1;
    }

    size_t probe = (path->mtu.min + path->mtu.max) >> 1;

    if (path->mtu.min > path->mtu.max) {
        path->mtu.probe = 0;
    } else {
        path->mtu.probe = probe;
    }
}

// 更新mud的rtt
static void
mud_update_stat(struct mud_stat *stat, const uint64_t val)
{
    // 开始计算rtt
    if (stat->setup) {
        
        // 计算新值与旧值之差
        const uint64_t var = mud_abs_diff(stat->val, val);
        // 平滑滤波: 旧值 * 0.75 + var * 0.25
        stat->var = ((stat->var << 1) + stat->var + var) >> 2;
        // 加权平均值
        stat->val = ((stat->val << 3) - stat->val + val) >> 3;

    } else {

        stat->setup = 1;
        stat->var = val >> 1;
        stat->val = val;
    }
}

// 接收msg包
static void
mud_recv_msg(struct mud *mud, struct mud_path *path,
             uint64_t now, uint64_t sent_time,
             unsigned char *data, size_t size)
{
    // 解析成msg
    struct mud_msg *msg = (struct mud_msg *)data;
    // 对端发送时间戳
    const uint64_t tx_time = MUD_LOAD_MSG(msg->sent_time);

    // 从msg包中获取对端地址
    mud_sock_from_addr(&path->remote, &msg->addr);

    // 对端发送时间戳有效
    if (tx_time) {

        // 更新rtt
        mud_update_stat(&path->rtt, MUD_TIME_MASK(now - tx_time));

        // 从msg中获取对端发送的字节数
        const uint64_t tx_bytes = MUD_LOAD_MSG(msg->fw.bytes);
        // 从msg中获取对端发送的包数
        const uint64_t tx_total = MUD_LOAD_MSG(msg->fw.total);
        // 从msg中获取对端接收的字节数
        const uint64_t rx_bytes = MUD_LOAD_MSG(msg->rx.bytes);
        // 从msg中获取对端接收的包数
        const uint64_t rx_total = MUD_LOAD_MSG(msg->rx.total);
        // 更新rx_time为数据包发送时间戳
        const uint64_t rx_time  = sent_time;

        /*
            对端发送时间戳 > 上次发送时间戳 && 本次对端发送的字节数 > 上次对端发送的字节数 &&

        */
        if ((tx_time > path->msg.tx.time) && (tx_bytes > path->msg.tx.bytes) &&
            (rx_time > path->msg.rx.time) && (rx_bytes > path->msg.rx.bytes)) {
            
            // 路径状态探测
            if (path->msg.set && path->status > MUD_PROBING) {

                // 更新发送速率和丢包率
                mud_update_rl(mud, path, now,
                        MUD_TIME_MASK(tx_time - path->msg.tx.time),
                        tx_bytes - path->msg.tx.bytes,
                        tx_total - path->msg.tx.total,
                        MUD_TIME_MASK(rx_time - path->msg.rx.time),
                        rx_bytes - path->msg.rx.bytes,
                        rx_total - path->msg.rx.total);
            }

            
            path->msg.tx.time = tx_time;
            path->msg.rx.time = rx_time;
            path->msg.tx.bytes = tx_bytes;
            path->msg.rx.bytes = rx_bytes;
            path->msg.tx.total = tx_total;
            path->msg.rx.total = rx_total;
            path->msg.set = 1;
        }
        path->rx.loss = (uint64_t)msg->loss;
        path->msg.sent = 0;

        if (path->conf.state == MUD_PASSIVE)
            return;

        mud_update_mtu(path, size);

        if (path->mtu.last && path->mtu.last == MUD_LOAD_MSG(msg->mtu))
            path->mtu.ok = path->mtu.last;
    } else {
        path->conf.beat = MUD_LOAD_MSG(msg->beat);

        const uint64_t max_rate = MUD_LOAD_MSG(msg->max_rate);

        if (path->conf.tx_max_rate != max_rate || msg->fixed_rate)
            path->tx.rate = max_rate;

        path->conf.tx_max_rate = max_rate;
        path->conf.pref = msg->pref;
        path->conf.fixed_rate = msg->fixed_rate;
        path->conf.loss_limit = msg->loss_limit;

        path->mtu.last = MUD_LOAD_MSG(msg->mtu);
        path->mtu.ok = path->mtu.last;

        path->msg.sent++;
        path->msg.time = now;
    }
    if (memcmp(msg->pkey, mud->keyx.remote, MUD_PUBKEY_SIZE)) {
        if (mud_keyx(&mud->keyx, msg->pkey, msg->aes)) {
            mud->err.keyx.addr = path->conf.remote;
            mud->err.keyx.time = now;
            mud->err.keyx.count++;
            return;
        }
    } else if (path->conf.state == MUD_UP) {
        mud->keyx.use_next = 1;
    }
    mud_send_msg(mud, path, now, sent_time,
                 MUD_LOAD_MSG(msg->tx.bytes),
                 MUD_LOAD_MSG(msg->tx.total),
                 size);
}

// 接收数据
int
mud_recv(struct mud *mud, void *data, size_t size)
{
    // 对端地址
    union mud_sockaddr remote;
    // 控制信息
    unsigned char ctrl[MUD_CTRL_SIZE];
    // 数据包
    unsigned char packet[MUD_PKT_MAX_SIZE];
    // msg包头
    struct msghdr msg = {
        .msg_name = &remote,                // 目标地址
        .msg_namelen = sizeof(remote),      // 目标地址长度
        .msg_iov = &(struct iovec) {        // 数据缓冲区
            .iov_base = packet,             // 数据缓冲区基地址
            .iov_len = sizeof(packet),      // 数据缓冲区长度
        },
        .msg_iovlen = 1,                    // I/O矢量数组中的元素数量，这里只有一个数据域，因此为1
        .msg_control = ctrl,                // 控制信息
        .msg_controllen = sizeof(ctrl),     // 控制信息长度
    };

    // 从UDP套接字接收数据
    const ssize_t packet_size = recvmsg(mud->fd, &msg, 0);

    // 接收失败
    if (packet_size == (ssize_t)-1)
        return -1;

    // 数据包长度超过接收缓冲区长度sizeof(packet) 或 数据包长度小于最小值，立即退出
    if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (packet_size <= (ssize_t)MUD_PKT_MIN_SIZE))
        return 0;

    // 当前时间戳
    const uint64_t now = mud_now(mud);
    // 从数据包中获取发送时间戳
    const uint64_t sent_time = mud_load(packet, MUD_TIME_SIZE);

    // 如果是IPv6地址，进行地址转换
    mud_unmapv4(&remote);

    // 数据包的接收时间和发送时间差超过了容忍时间
    if ((MUD_TIME_MASK(now - sent_time) > mud->conf.timetolerance) &&
        (MUD_TIME_MASK(sent_time - now) > mud->conf.timetolerance)) {

        // 此时认为发生了时钟同步错误
        
        mud->err.clocksync.addr = remote;   // 错误时的地址信息
        mud->err.clocksync.time = now;      // 当前时间戳
        mud->err.clocksync.count++;         // 错误次数
        return 0;
    }

    // 解密数据包，首先判断是一个msg包还是普通数据包
    const size_t ret = MUD_MSG(sent_time)
                     ? mud_decrypt_msg(mud, data, size, packet, (size_t)packet_size)
                     : mud_decrypt(mud, data, size, packet, (size_t)packet_size);
    
    // 解密失败，记录错误
    if (!ret) {
        mud->err.decrypt.addr = remote;
        mud->err.decrypt.time = now;
        mud->err.decrypt.count++;
        return 0;
    }

    // 本地地址
    union mud_sockaddr local;
    if (mud_localaddr(&local, &msg))
        return 0;

    // 获取指定路径
    struct mud_path *path = mud_get_path(mud, &local, &remote, MUD_PASSIVE);

    // 路径不存在，或者路径状态不对，则丢弃数据包
    if (!path || path->conf.state <= MUD_DOWN)
        return 0;

    // 如果是msg包，则调用mud_recv_msg处理
    if (MUD_MSG(sent_time)) {
        mud_recv_msg(mud, path, now, sent_time, data, (size_t)packet_size);
    } else {
        path->idle = now;
    }

    // 接收统计
    path->rx.total++;
    path->rx.time = now;
    path->rx.bytes += (size_t)packet_size;

    mud->last_recv_time = now;

    // 是否是一个msg包
    return MUD_MSG(sent_time) ? 0 : (int)ret;
}

// 更新路径状态
static int
mud_path_update(struct mud *mud, struct mud_path *path, uint64_t now)
{
    switch (path->conf.state) {
    
        // 连接已关闭 -> 路径正在被删除; 如果超过2分钟没有收到数据，则删除路径
        case MUD_DOWN:
            path->status = MUD_DELETING;
            if (mud_timeout(now, path->rx.time, 2 * MUD_ONE_MIN))
                memset(path, 0, sizeof(struct mud_path));
            return 0;
        // 被动连接 -> 如果超过2分钟没有新的连接，则删除路径
        case MUD_PASSIVE:
            if (mud_timeout(now, mud->last_recv_time, 2 * MUD_ONE_MIN)) {
                memset(path, 0, sizeof(struct mud_path));
                return 0;
            }
        case MUD_UP: break;
        default:     return 0;
    }

    // 每5个消息，更新一次MTU
    if (path->msg.sent >= MUD_MSG_SENT_MAX) {

        // MTU探测
        if (path->mtu.probe) {
            mud_update_mtu(path, 0);
            path->msg.sent = 0;
        } 
        // 没有开启MTU探测，认为路径质量下降
        else 
        {
            path->msg.sent = MUD_MSG_SENT_MAX;
            path->status = MUD_DEGRADED;
            return 0;
        }
    }

    // MTU探测失败
    if (!path->mtu.ok) {
        path->status = MUD_PROBING;
        return 0;
    }

    // 丢包率超过阈值
    if (path->tx.loss > path->conf.loss_limit ||
        path->rx.loss > path->conf.loss_limit) {
        path->status = MUD_LOSSY;
        return 0;
    }

    // 被动连接状态
    if (path->conf.state == MUD_PASSIVE &&
        mud_timeout(mud->last_recv_time, path->rx.time,
                    MUD_MSG_SENT_MAX * path->conf.beat)) {
        path->status = MUD_WAITING;
        return 0;
    }

    // 当前路径优先级 高于 全局优先级，则认为路径已准备好
    if (path->conf.pref > mud->pref) {
        path->status = MUD_READY;

    // 更新路径状态为RUNNING
    } else if (path->status != MUD_RUNNING) {
        path->status = MUD_RUNNING;
        path->idle = now;
    }
    return 1;
}

// 路径跟踪
static uint64_t
mud_path_track(struct mud *mud, struct mud_path *path, uint64_t now)
{
    // 只关注MUD_UP状态的路径
    if (path->conf.state != MUD_UP)
        return now;

    // 路径心跳包间隔ms
    uint64_t timeout = path->conf.beat;


    switch (path->status) {

        // 路径状态为RUNNING，且路径空闲超过1s, 则更新timeout为keepalive
        case MUD_RUNNING:
            if (mud_timeout(now, path->idle, MUD_ONE_SEC))
                timeout = mud->conf.keepalive;
            break;
        case MUD_DEGRADED:
        case MUD_LOSSY:
        case MUD_PROBING:
            break;
        default:
            return now;
    }

    // 当前时间和路径上次发送时间差大于保活时间，则发送心跳包
    if (mud_timeout(now, path->msg.time, timeout)) {
        path->msg.sent++;
        path->msg.time = now;
        mud_send_msg(mud, path, now, 0, 0, 0, path->mtu.probe);
        now = mud_now(mud);
    }
    return now;
}

static void
mud_update_window(struct mud *mud, const uint64_t now)
{
    // 当前时间 - 上次更新时间
    uint64_t elapsed = MUD_TIME_MASK(now - mud->window_time);

    // 超过1ms, 更新流控窗口
    if (elapsed > MUD_ONE_MSEC) {
        // 根据速率和时间窗口，计算流控窗口增量
        mud->window += mud->rate * elapsed / MUD_ONE_SEC;
        // 更新时间戳
        mud->window_time = now;
    }

    // 流控窗口最大值
    uint64_t window_max = mud->rate * 100 * MUD_ONE_MSEC / MUD_ONE_SEC;

    // 流控窗口最大值限制
    if (mud->window > window_max)
        mud->window = window_max;
}

// 路径状态更新
int
mud_update(struct mud *mud)
{
    unsigned count = 0;
    unsigned pref = 255;
    unsigned next_pref = 255;
    uint64_t rate = 0;
    size_t   mtu = 0;
    uint64_t now = mud_now(mud);

    // 密钥交换初始化
    if (!mud_keyx_init(mud, now))
        now = mud_now(mud);

    // 遍历所有路径，更新路径状态，发送心跳包
    for (unsigned i = 0; i < mud->capacity; i++) {

        // 当前路径
        struct mud_path *path = &mud->paths[i];

        // 更新当前路径状态
        if (mud_path_update(mud, path, now)) {

            // 当前路径优先级在mud->pref和next_pref之间，更新next_pref
            if (next_pref > path->conf.pref && path->conf.pref > mud->pref)
                next_pref = path->conf.pref;

            // 当前路径优先级小于perf,更新pref
            if (pref > path->conf.pref)
                pref = path->conf.pref;

            // 当前路径状态为RUNNING,更新rate
            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }

        // MTU探测成功，则更新mte
        if (path->mtu.ok) {
            if (!mtu || mtu > path->mtu.ok)
                mtu = path->mtu.ok;
        }

        // 路径追踪，发送心跳包
        now = mud_path_track(mud, path, now);
        count++;
    }

    // 任一路径有码率，则更新全局优先级
    if (rate) {
        mud->pref = pref;

    // 所有路径均没有码率
    } else {
        mud->pref = next_pref;

        for (unsigned i = 0; i < mud->capacity; i++) {
            struct mud_path *path = &mud->paths[i];

            // 更新路径状态
            if (!mud_path_update(mud, path, now))
                continue;

            // 当前路径状态为RUNNING,更新rate
            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
    }

    // 更新全局码率
    mud->rate = rate;
    // 更新MTU
    mud->mtu = mtu;

    // 更新流控窗口
    mud_update_window(mud, now);

    // 没有可用的路径
    if (!count)
        return -1;

    // 流控窗口是否小于1500; 流控窗口小于标准MTU1500,需要等待
    return mud->window < 1500;
}

// 设置路径
int
mud_set_path(struct mud *mud, struct mud_path_conf *conf)
{
    // 状态不对
    if (conf->state < MUD_EMPTY || conf->state >= MUD_LAST) {
        errno = EINVAL;
        return -1;
    }

    // 从数组中获取指定路径，如果路径不存在，则创建之
    struct mud_path *path = mud_get_path(mud, &conf->local,
                                              &conf->remote,
                                              conf->state);
    if (!path)
        return -1;

    struct mud_path_conf c = path->conf;

    // 配置路径，覆盖mud_get_path中的路径默认配置
    if (conf->state)       c.state       = conf->state;
    if (conf->pref)        c.pref        = conf->pref >> 1;
    if (conf->beat)        c.beat        = conf->beat * MUD_ONE_MSEC;
    if (conf->fixed_rate)  c.fixed_rate  = conf->fixed_rate >> 1;
    if (conf->loss_limit)  c.loss_limit  = conf->loss_limit;
    if (conf->tx_max_rate) c.tx_max_rate = path->tx.rate = conf->tx_max_rate;
    if (conf->rx_max_rate) c.rx_max_rate = path->rx.rate = conf->rx_max_rate;

    *conf = path->conf = c;
    return 0;
}

int
mud_send_wait(struct mud *mud)
{
    return mud->window < 1500;
}

// 发送数据
int
mud_send(struct mud *mud, const void *data, size_t size)
{
    if (!size)
        return 0;

    // 流控窗口小于标准MTU1500,返回EAGAIN错误码
    // 避免频繁发送小包，提高网络传输效率

    if (mud->window < 1500) {
        errno = EAGAIN;
        return -1;
    }

    // 1500 byte大小的包
    unsigned char packet[MUD_PKT_MAX_SIZE];

    const uint64_t now = mud_now(mud);

    // 加密
    const size_t packet_size = mud_encrypt(mud, now,
                                           packet, sizeof(packet),
                                           data, size);
    if (!packet_size) {
        errno = EMSGSIZE;   // 错误码Message too long
        return -1;
    }

    // 用于路径选择的指标
    uint16_t k;
    memcpy(&k, &packet[packet_size - sizeof(k)], sizeof(k));

    // 路径选择
    struct mud_path *path = mud_select_path(mud, k);

    // 没有可用路径
    if (!path) {
        errno = EAGAIN;
        return -1;
    }

    // 路径空闲时间戳
    path->idle = now;

    // 发送数据
    return mud_send_path(mud, path, now, packet, packet_size, 0);
}
