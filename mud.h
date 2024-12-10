#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

// 最多32个路径
#define MUD_PATH_MAX    (32U)
#define MUD_PUBKEY_SIZE (32U)

struct mud;

// mud状态
enum mud_state {
    // 初始状态，表示连接未初始化
    MUD_EMPTY = 0,
    // 连接已关闭
    MUD_DOWN,
    // 被动连接，server端
    MUD_PASSIVE,
    // 连接已建立，并正常工作
    MUD_UP,
    // 此枚举类型结束
    MUD_LAST,
};

// 路径状态
enum mud_path_status {
    // 路径正在被删除
    MUD_DELETING = 0,
    // 正在探测路径状态
    MUD_PROBING,
    // 路径降级
    MUD_DEGRADED,
    // 出现丢包
    MUD_LOSSY,
    // 等待路径就绪
    MUD_WAITING,
    // 路径就绪
    MUD_READY,
    // 正常运行中
    MUD_RUNNING,
};

struct mud_stat {
    uint64_t val;   // rtt加权平均值
    uint64_t var;   // 经过平滑滤波算法处理后的rtt平均值
    int setup;      // 
};

// mud配置
struct mud_conf {
    uint64_t keepalive;         // 保活时间
    uint64_t timetolerance;     // 容忍时间长度
    uint64_t kxtimeout;          // 密钥交换超时
};

// IPv4 or IPv6
union mud_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct mud_path_conf {
    // 状态
    enum mud_state state;
    // 本地地址
    union mud_sockaddr local;
    // 远端地址
    union mud_sockaddr remote;
    // 发送最大速率
    uint64_t tx_max_rate;
    // 接受最大速率
    uint64_t rx_max_rate;
    // 心跳时间间隔，ms
    uint64_t beat;
    // 路径优先级
    unsigned char pref;
    // 固定速率
    unsigned char fixed_rate;
    // 丢包限制
    unsigned char loss_limit;
};

// mud路径相关信息
struct mud_path {
    // 路径配置
    struct mud_path_conf conf;
    // 路径状态
    enum mud_path_status status;
    // 对端地址
    union mud_sockaddr remote;
    // 实时状态信息
    struct mud_stat rtt;

    // 发送和接收统计
    struct {
        uint64_t total;
        uint64_t bytes;
        uint64_t time;      // 
        uint64_t rate;      // 发送/接收速率,控制发送速率
        uint64_t loss;
    } tx, rx;

    // 消息统计
    struct {
        struct {
            uint64_t total;         // 消息总数
            uint64_t bytes;         // 消息总字节数
            uint64_t time;          // 最后一次传输时间
            uint64_t acc;           // 累计消息数，用于带宽计算
            uint64_t acc_time;      // 累计消息时间，用于带宽计算
        } tx, rx;
        uint64_t time;              // 当前消息时间戳
        uint64_t sent;              // 已发送消息数
        uint64_t set;               // 路径状态探测开关
    } msg;

    // MTU相关内容
    struct {
        size_t min;                 // 最小MTU
        size_t max;                 // 最大MTU
        size_t probe;               // MTU探测值
        size_t last;                // 最后一次MTU
        size_t ok;                  // MTU探测是否成功
    } mtu;
    uint64_t idle;  // 路径空闲时间统计
};

// 错误
struct mud_error {
    union mud_sockaddr addr;    // 地址信息
    uint64_t time;              // 时间戳
    uint64_t count;             // 错误计数
};

// 错误信息
struct mud_errors {
    struct mud_error decrypt;           // 加密/解密错误
    struct mud_error clocksync;         // 时钟同步错误
    struct mud_error keyx;              // 密钥错误
};

struct mud_paths {
    struct mud_path path[MUD_PATH_MAX];
    unsigned count;
};

struct mud *mud_create (union mud_sockaddr *, unsigned char *, int *);
void        mud_delete (struct mud *);

int mud_set      (struct mud *, struct mud_conf *);
int mud_set_path (struct mud *, struct mud_path_conf *);

    int fd;
    struct mud_conf conf;
    struct mud_path *paths; // 路径数组
    unsigned pref;          // 预先设置的速率
    unsigned capacity;      // 路径数量
    struct mud_keyx keyx;   // 密钥交换
    uint64_t last_recv_time; // 最后一次接收时间
    size_t mtu;            // 最大传输单元
    struct mud_errors err;  // 错误信息
    uint64_t rate;         // 速率
int    mud_get_paths  (struct mud *, struct mud_paths *,
                       union mud_sockaddr *, union mud_sockaddr *);
