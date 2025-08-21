# PF (Packet Filter) 和 pfctl 实现分析

## 一、概述

PF (Packet Filter) 是BSD系统（OpenBSD、FreeBSD、NetBSD）中的状态防火墙实现，最初由Daniel Hartmeier为OpenBSD开发，后被移植到其他BSD系统。pfctl是PF的用户空间管理工具，用于配置规则、查看状态和管理防火墙。

### 1.1 历史背景
- 2001年：PF首次在OpenBSD 3.0中发布，替代IPFilter
- 设计目标：高性能、灵活性、易用性和安全性
- 现已成为BSD系统的标准防火墙解决方案

### 1.2 核心特性
- 状态检测（Stateful Inspection）
- 网络地址转换（NAT/PAT）
- 流量整形和队列管理（ALTQ集成）
- 负载均衡
- 操作系统指纹识别
- SYN代理（SYN Proxy）
- 规则锚点（Anchors）
- 表（Tables）支持

## 二、PF架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                    用户空间                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  pfctl   │  │ authpf   │  │  pflogd  │            │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘            │
│        │             │              │                   │
│        └─────────────┴──────────────┘                   │
│                      │                                  │
│                   ioctl()                               │
├──────────────────────┼──────────────────────────────────┤
│                      ▼                                  │
│               ┌──────────────┐                         │
│               │ /dev/pf      │                         │
│               └──────┬───────┘                         │
│                      │                                  │
│                 内核空间                                 │
│                      ▼                                  │
│  ┌──────────────────────────────────────────────┐     │
│  │            PF 核心引擎                        │     │
│  │  ┌────────────┐  ┌────────────┐            │     │
│  │  │ 规则引擎   │  │ 状态表     │            │     │
│  │  └────────────┘  └────────────┘            │     │
│  │  ┌────────────┐  ┌────────────┐            │     │
│  │  │ NAT引擎    │  │ 队列管理   │            │     │
│  │  └────────────┘  └────────────┘            │     │
│  └──────────────────────────────────────────────┘     │
│                      ▲                                  │
│                      │                                  │
│               ┌──────┴───────┐                         │
│               │    pfil      │                         │
│               └──────────────┘                         │
│                      ▲                                  │
│                      │                                  │
│               ┌──────┴───────┐                         │
│               │ 网络协议栈   │                         │
│               └──────────────┘                         │
└─────────────────────────────────────────────────────────┘
```

### 2.2 核心组件

#### 2.2.1 规则引擎
- 规则解析和匹配
- 快速路径优化
- 规则集管理

#### 2.2.2 状态表
- 连接状态跟踪
- 状态查找和更新
- 垃圾回收机制

#### 2.2.3 NAT引擎
- 地址转换
- 端口映射
- 双向NAT支持

#### 2.2.4 锚点系统
- 动态规则加载
- 规则集嵌套
- 条件评估

## 三、核心数据结构

### 3.1 PF状态结构

```c
struct pf_kstate {
    /* 状态标识 */
    u_int64_t        id;           // 唯一状态ID
    u_int32_t        creatorid;    // 创建者ID
    u_int8_t         direction;    // 方向（IN/OUT）
    
    /* 状态信息 */
    u_int16_t        state_flags;  // 状态标志
    u_int8_t         timeout;      // 超时类型
    u_int8_t         sync_state;   // 同步状态（用于pfsync）
    u_int            refs;         // 引用计数
    struct mtx       *lock;        // 状态锁
    
    /* 连接跟踪 */
    struct pf_state_peer src;      // 源端状态
    struct pf_state_peer dst;      // 目的端状态
    
    /* 规则关联 */
    struct pf_krule  *rule;        // 匹配的规则
    struct pf_krule  *anchor;      // 锚点规则
    struct pf_krule  *nat_rule;    // NAT规则
    
    /* 地址信息 */
    struct pf_state_key *key[2];   // 状态键（wire和stack）
    
    /* 接口信息 */
    struct pfi_kkif  *kif;         // 接口
    struct pfi_kkif  *orig_kif;    // 原始接口
    
    /* 统计信息 */
    u_int64_t        packets[2];   // 数据包计数
    u_int64_t        bytes[2];     // 字节计数
    u_int64_t        creation;     // 创建时间
    u_int64_t        expire;       // 过期时间
    
    /* QoS相关 */
    u_int16_t        qid;          // 队列ID
    u_int16_t        pqid;         // 父队列ID
};
```

### 3.2 状态对等体（State Peer）

```c
struct pf_state_peer {
    struct pf_state_scrub *scrub;  // 数据包清理信息
    u_int32_t        seqlo;        // 最小序列号
    u_int32_t        seqhi;        // 最大序列号 + 窗口
    u_int32_t        seqdiff;      // 序列号调整值
    u_int16_t        max_win;      // 最大窗口大小
    u_int16_t        mss;          // MSS值
    u_int8_t         state;        // TCP状态
    u_int8_t         wscale;       // 窗口缩放因子
    u_int8_t         tcp_est;      // 是否已建立连接
};
```

### 3.3 规则结构

```c
struct pf_krule {
    /* 规则链表 */
    TAILQ_ENTRY(pf_krule) entries;
    
    /* 规则内容 */
    struct pf_rule_addr src;       // 源地址
    struct pf_rule_addr dst;       // 目的地址
    
    /* 动作 */
    u_int8_t         action;       // PF_PASS, PF_DROP等
    u_int8_t         direction;    // PF_IN, PF_OUT, PF_INOUT
    u_int8_t         quick;        // 快速匹配标志
    u_int8_t         keep_state;   // 状态保持类型
    
    /* 协议信息 */
    sa_family_t      af;           // 地址族
    u_int8_t         proto;        // 协议号
    
    /* 接口 */
    char             ifname[IFNAMSIZ];  // 接口名
    struct pfi_kkif  *kif;         // 接口结构
    
    /* NAT/重定向 */
    struct pf_pool   nat;          // NAT池
    struct pf_pool   rdr;          // 重定向池
    
    /* 统计 */
    struct pf_counter_u64 evaluations;  // 评估次数
    struct pf_counter_u64 packets[2];   // 数据包计数
    struct pf_counter_u64 bytes[2];     // 字节计数
    
    /* 超时和限制 */
    u_int32_t        timeout[PFTM_MAX];     // 超时值
    u_int32_t        max_states;            // 最大状态数
    u_int32_t        max_src_nodes;         // 最大源节点数
    u_int32_t        max_src_states;        // 最大源状态数
    
    /* 标签和标记 */
    char             label[PF_RULE_MAX_LABEL_COUNT][PF_RULE_LABEL_SIZE];
    u_int16_t        tag;          // 标记值
    u_int16_t        match_tag;    // 匹配标记
};
```

### 3.4 状态键（State Key）

```c
struct pf_state_key {
    struct pf_addr   addr[2];      // 地址对
    u_int16_t        port[2];      // 端口对
    sa_family_t      af;           // 地址族
    u_int8_t         proto;        // 协议
    
    LIST_ENTRY(pf_state_key) entry;
    TAILQ_HEAD(, pf_kstate) states[2];  // 关联的状态
};
```

## 四、状态表实现

### 4.1 状态查找机制

PF使用多级哈希表进行高效的状态查找：

```c
/* 状态查找函数 */
struct pf_kstate *
pf_find_state(struct pfi_kkif *kif, struct pf_state_key_cmp *key, u_int dir)
{
    struct pf_keyhash *kh;
    struct pf_state_key *sk;
    struct pf_kstate *s;
    int idx;
    
    /* 计算哈希值 */
    idx = pf_hashkey(key);
    kh = &V_pf_keyhash[idx];
    
    /* 在哈希桶中查找 */
    LIST_FOREACH(sk, &kh->keys, entry) {
        if (pf_state_key_cmp(sk, key) == 0) {
            /* 找到匹配的状态键 */
            TAILQ_FOREACH(s, &sk->states[dir], key_list[dir]) {
                if (s->kif == kif || s->kif == V_pfi_all) {
                    /* 更新访问时间 */
                    s->expire = pf_get_uptime();
                    return (s);
                }
            }
        }
    }
    
    return (NULL);
}
```

### 4.2 状态插入

```c
int
pf_state_insert(struct pfi_kkif *kif, struct pfi_kkif *orig_kif,
    struct pf_state_key *skw, struct pf_state_key *sks, struct pf_kstate *s)
{
    struct pf_idhash *ih;
    struct pf_kstate *cur;
    int error;
    
    /* 设置状态参数 */
    s->kif = kif;
    s->orig_kif = orig_kif;
    s->key[PF_SK_WIRE] = skw;
    s->key[PF_SK_STACK] = sks;
    
    /* 生成唯一ID */
    s->id = pf_get_stateid(s);
    s->creatorid = V_pf_status.hostid;
    
    /* 插入到ID哈希表 */
    ih = &V_pf_idhash[PF_IDHASH(s)];
    PF_HASHROW_LOCK(ih);
    LIST_FOREACH(cur, &ih->states, entry) {
        if (cur->id == s->id && cur->creatorid == s->creatorid) {
            PF_HASHROW_UNLOCK(ih);
            return (EEXIST);
        }
    }
    LIST_INSERT_HEAD(&ih->states, s, entry);
    PF_HASHROW_UNLOCK(ih);
    
    /* 插入到键哈希表 */
    pf_state_key_attach(skw, sks, s);
    
    /* 设置超时 */
    s->creation = s->expire = pf_get_uptime();
    s->timeout = PFTM_TCP_FIRST_PACKET;
    
    /* 更新统计 */
    V_pf_status.fcounters[FCNT_STATE_INSERT]++;
    V_pf_status.states++;
    
    /* 初始化引用计数为2 */
    refcount_init(&s->refs, 2);
    
    return (0);
}
```

### 4.3 TCP状态跟踪

#### 4.3.1 TCP状态定义

```c
/* TCP状态（使用标准TCP状态） */
#define TCPS_CLOSED         0   /* 关闭 */
#define TCPS_LISTEN         1   /* 监听 */
#define TCPS_SYN_SENT       2   /* 主动打开，发送SYN */
#define TCPS_SYN_RECEIVED   3   /* 被动打开，收到SYN */
#define TCPS_ESTABLISHED    4   /* 连接建立 */
#define TCPS_CLOSE_WAIT     5   /* 收到FIN，等待关闭 */
#define TCPS_FIN_WAIT_1     6   /* 主动关闭，发送FIN */
#define TCPS_CLOSING        7   /* 同时关闭 */
#define TCPS_LAST_ACK       8   /* 被动关闭，发送FIN */
#define TCPS_FIN_WAIT_2     9   /* 收到FIN的ACK */
#define TCPS_TIME_WAIT      10  /* 2MSL等待 */
```

#### 4.3.2 TCP状态跟踪实现

```c
static int
pf_tcp_track_full(struct pf_kstate *state, struct pf_pdesc *pd,
    u_short *reason, int *copyback, struct pf_state_peer *src,
    struct pf_state_peer *dst, u_int8_t psrc, u_int8_t pdst)
{
    struct tcphdr *th = &pd->hdr.tcp;
    u_int16_t win = ntohs(th->th_win);
    u_int32_t ack, end, data_end, seq, orig_seq;
    u_int8_t sws, dws;
    int ackskew;
    
    /* 获取窗口缩放因子 */
    if (src->wscale && dst->wscale && !(tcp_get_flags(th) & TH_SYN)) {
        sws = src->wscale & PF_WSCALE_MASK;
        dws = dst->wscale & PF_WSCALE_MASK;
    } else
        sws = dws = 0;
    
    /*
     * 序列号跟踪算法（基于Guido van Rooij的论文）
     * 检查序列号是否在有效窗口内
     */
    
    seq = ntohl(th->th_seq);
    ack = ntohl(th->th_ack);
    end = seq + pd->p_len;
    
    /* 处理序列号回绕 */
    if (src->seqdiff) {
        seq += src->seqdiff;
        end += src->seqdiff;
    }
    
    /* 检查序列号是否在窗口内 */
    if (!SEQ_GEQ(seq, src->seqlo - (dst->max_win << dws))) {
        REASON_SET(reason, PFRES_BADSTATE);
        return (PF_DROP);
    }
    
    /* 更新状态 */
    if (tcp_get_flags(th) & TH_SYN) {
        if (src->state < TCPS_SYN_SENT)
            pf_set_protostate(state, psrc, TCPS_SYN_SENT);
    }
    if (tcp_get_flags(th) & TH_FIN) {
        if (src->state < TCPS_CLOSING)
            pf_set_protostate(state, psrc, TCPS_CLOSING);
    }
    if (tcp_get_flags(th) & TH_ACK) {
        if (dst->state == TCPS_SYN_SENT) {
            pf_set_protostate(state, pdst, TCPS_ESTABLISHED);
            /* 检查连接限制 */
            if (src->state == TCPS_ESTABLISHED &&
                state->sns[PF_SN_LIMIT] != NULL &&
                pf_src_connlimit(state)) {
                REASON_SET(reason, PFRES_SRCLIMIT);
                return (PF_DROP);
            }
        } else if (dst->state == TCPS_CLOSING) {
            pf_set_protostate(state, pdst, TCPS_FIN_WAIT_2);
        } else if (src->state == TCPS_CLOSING &&
                   dst->state == TCPS_ESTABLISHED) {
            pf_set_protostate(state, pdst, TCPS_CLOSE_WAIT);
        }
    }
    
    /* 更新序列号窗口 */
    if (SEQ_GT(end, src->seqhi))
        src->seqhi = end;
    
    /* 更新窗口大小 */
    if (win > src->max_win)
        src->max_win = win;
    
    /* 更新超时 */
    state->expire = pf_get_uptime();
    if (src->state >= TCPS_FIN_WAIT_2 &&
        dst->state >= TCPS_FIN_WAIT_2)
        state->timeout = PFTM_TCP_CLOSED;
    else if (src->state >= TCPS_ESTABLISHED &&
             dst->state >= TCPS_ESTABLISHED)
        state->timeout = PFTM_TCP_ESTABLISHED;
    else
        state->timeout = PFTM_TCP_OPENING;
    
    return (PF_PASS);
}
```

### 4.4 UDP状态跟踪

```c
/* UDP状态 */
#define PFUDPS_NO_TRAFFIC   0   /* 无流量 */
#define PFUDPS_SINGLE       1   /* 单向流量 */
#define PFUDPS_MULTIPLE     2   /* 双向流量 */

static void
pf_udp_track(struct pf_kstate *state, struct pf_pdesc *pd,
    struct pf_state_peer *src, struct pf_state_peer *dst)
{
    /* 更新状态 */
    if (src->state < PFUDPS_SINGLE)
        pf_set_protostate(state, PF_PEER_SRC, PFUDPS_SINGLE);
    if (dst->state == PFUDPS_SINGLE)
        pf_set_protostate(state, PF_PEER_DST, PFUDPS_MULTIPLE);
    
    /* 更新超时 */
    state->expire = pf_get_uptime();
    if (src->state == PFUDPS_MULTIPLE && 
        dst->state == PFUDPS_MULTIPLE)
        state->timeout = PFTM_UDP_MULTIPLE;
    else
        state->timeout = PFTM_UDP_SINGLE;
}
```

## 五、规则处理引擎

### 5.1 规则匹配流程

```c
int
pf_test_rule(struct pf_krule **rm, struct pf_kstate **sm,
    struct pf_pdesc *pd, struct pf_krule **am,
    struct pf_kruleset **rsm, struct ifqueue *ifq)
{
    struct pf_krule *r, *a = NULL;
    struct pf_kruleset *ruleset = NULL;
    sa_family_t af = pd->af;
    int match = 0;
    
    r = TAILQ_FIRST(pf_main_ruleset.rules[PF_RULESET_FILTER].active.ptr);
    
    while (r != NULL) {
        /* 快速检查 */
        if (r->evaluations++ == 0)
            r->timestamp = pf_get_uptime();
        
        /* 检查方向 */
        if (r->direction && r->direction != pd->dir) {
            r = TAILQ_NEXT(r, entries);
            continue;
        }
        
        /* 检查地址族 */
        if (r->af && r->af != af) {
            r = TAILQ_NEXT(r, entries);
            continue;
        }
        
        /* 检查协议 */
        if (r->proto && r->proto != pd->proto) {
            r = TAILQ_NEXT(r, entries);
            continue;
        }
        
        /* 检查接口 */
        if (r->kif && r->kif != pd->kif) {
            r = TAILQ_NEXT(r, entries);
            continue;
        }
        
        /* 检查源地址 */
        if (!PF_MATCH_ADDR(r->src.neg, &r->src.addr,
            pd->src, af)) {
            r = TAILQ_NEXT(r, entries);
            continue;
        }
        
        /* 检查目的地址 */
        if (!PF_MATCH_ADDR(r->dst.neg, &r->dst.addr,
            pd->dst, af)) {
            r = TAILQ_NEXT(r, entries);
            continue;
        }
        
        /* 检查端口（TCP/UDP） */
        if (pd->proto == IPPROTO_TCP || pd->proto == IPPROTO_UDP) {
            if (!pf_match_port(r->src.port_op, r->src.port[0],
                r->src.port[1], pd->sport)) {
                r = TAILQ_NEXT(r, entries);
                continue;
            }
            if (!pf_match_port(r->dst.port_op, r->dst.port[0],
                r->dst.port[1], pd->dport)) {
                r = TAILQ_NEXT(r, entries);
                continue;
            }
        }
        
        /* 规则匹配 */
        match = 1;
        
        /* 处理锚点 */
        if (r->anchor != NULL) {
            /* 递归处理锚点规则集 */
            pf_step_into_anchor(r->anchor, &ruleset, &r, &a);
            continue;
        }
        
        /* 执行动作 */
        if (r->action == PF_DROP) {
            REASON_SET(&pd->reason, PFRES_MATCH);
            return (PF_DROP);
        }
        
        /* 快速规则 */
        if (r->quick) {
            *rm = r;
            *am = a;
            *rsm = ruleset;
            break;
        }
        
        /* 继续评估下一条规则 */
        r = TAILQ_NEXT(r, entries);
    }
    
    /* 创建状态 */
    if (r->keep_state && !*sm) {
        if (pf_create_state(r, pd, sm) != 0) {
            REASON_SET(&pd->reason, PFRES_MEMORY);
            return (PF_DROP);
        }
    }
    
    return (r->action);
}
```

### 5.2 规则优化

#### 5.2.1 跳表优化

```c
/* 规则跳表，用于快速跳过不匹配的规则 */
struct pf_skip_step {
    struct pf_krule *ptr;      /* 跳转目标规则 */
    u_int16_t       count;      /* 跳过的规则数 */
};

/* 构建跳表 */
void
pf_build_skip_steps(struct pf_kruleset *rs)
{
    struct pf_krule *r, *prev;
    int skip_af, skip_proto, skip_dir, skip_iface;
    
    TAILQ_FOREACH(r, rs->rules[PF_RULESET_FILTER].active.ptr, entries) {
        /* 计算可跳过的字段 */
        skip_af = (prev == NULL || prev->af != r->af);
        skip_proto = (prev == NULL || prev->proto != r->proto);
        skip_dir = (prev == NULL || prev->direction != r->direction);
        skip_iface = (prev == NULL || prev->kif != r->kif);
        
        /* 设置跳表 */
        if (skip_af)
            r->skip[PF_SKIP_AF].ptr = TAILQ_NEXT(r, entries);
        if (skip_proto)
            r->skip[PF_SKIP_PROTO].ptr = TAILQ_NEXT(r, entries);
        if (skip_dir)
            r->skip[PF_SKIP_DIR].ptr = TAILQ_NEXT(r, entries);
        if (skip_iface)
            r->skip[PF_SKIP_IFP].ptr = TAILQ_NEXT(r, entries);
        
        prev = r;
    }
}
```

## 六、pfctl工具实现

### 6.1 pfctl架构

pfctl通过ioctl系统调用与内核PF模块交互：

```c
/* pfctl主函数结构 */
int
main(int argc, char *argv[])
{
    int dev;
    int ch;
    int mode = O_RDONLY;
    
    /* 打开PF设备 */
    dev = open("/dev/pf", mode);
    if (dev == -1)
        err(1, "/dev/pf");
    
    /* 解析命令行参数 */
    while ((ch = getopt(argc, argv, 
        "a:AdD:eE:f:F:ghi:k:K:nNOqRrSs:t:T:vxz")) != -1) {
        switch (ch) {
        case 'e':   /* 启用PF */
            pfctl_enable(dev, 1);
            break;
        case 'd':   /* 禁用PF */
            pfctl_disable(dev, 1);
            break;
        case 'f':   /* 加载规则文件 */
            pfctl_load_rulefile(dev, optarg);
            break;
        case 's':   /* 显示信息 */
            pfctl_show(dev, optarg);
            break;
        /* ... 其他选项 ... */
        }
    }
    
    close(dev);
    return (0);
}
```

### 6.2 规则加载

```c
int
pfctl_load_rule(struct pfctl *pf, char *path, struct pfctl_rule *r,
    int depth)
{
    struct pfioc_rule pr;
    
    memset(&pr, 0, sizeof(pr));
    
    /* 转换pfctl_rule到pfioc_rule */
    if (strlcpy(pr.anchor, path, sizeof(pr.anchor)) >= 
        sizeof(pr.anchor)) {
        errx(1, "pfctl_load_rule: anchor name too long");
    }
    
    /* 复制规则内容 */
    memcpy(&pr.rule, r, sizeof(pr.rule));
    
    /* 设置ticket */
    pr.ticket = pf->astack[depth]->ruleset.tticket;
    
    /* 通过ioctl添加规则 */
    if (ioctl(pf->dev, DIOCADDRULE, &pr) < 0) {
        warn("DIOCADDRULE");
        return (1);
    }
    
    /* 更新规则编号 */
    r->nr = pr.nr;
    
    return (0);
}
```

### 6.3 状态查看

```c
int
pfctl_show_states(int dev, const char *iface, int opts)
{
    struct pfioc_states ps;
    struct pf_state_export *states;
    int i, nbytes;
    
    memset(&ps, 0, sizeof(ps));
    
    /* 获取状态数量 */
    if (ioctl(dev, DIOCGETSTATES, &ps) < 0) {
        warn("DIOCGETSTATES");
        return (-1);
    }
    
    /* 分配缓冲区 */
    nbytes = ps.ps_len;
    states = malloc(nbytes);
    if (states == NULL)
        err(1, "malloc");
    
    ps.ps_states = states;
    
    /* 获取状态列表 */
    if (ioctl(dev, DIOCGETSTATES, &ps) < 0) {
        warn("DIOCGETSTATES");
        free(states);
        return (-1);
    }
    
    /* 打印状态 */
    for (i = 0; i < ps.ps_len / sizeof(*states); i++) {
        print_state(&states[i], opts);
    }
    
    free(states);
    return (0);
}

void
print_state(struct pf_state_export *s, int opts)
{
    struct pf_state_peer *src, *dst;
    int min, sec;
    
    /* 格式化输出状态信息 */
    printf("%s ", s->proto == IPPROTO_TCP ? "tcp" :
                  s->proto == IPPROTO_UDP ? "udp" :
                  s->proto == IPPROTO_ICMP ? "icmp" : "other");
    
    /* 打印地址和端口 */
    print_host(&s->key[PF_SK_WIRE].addr[0], 
               s->key[PF_SK_WIRE].port[0], s->af);
    printf(" -> ");
    print_host(&s->key[PF_SK_WIRE].addr[1],
               s->key[PF_SK_WIRE].port[1], s->af);
    
    /* 打印状态 */
    if (s->proto == IPPROTO_TCP) {
        printf("   %s:%s\n",
            tcpstates[s->src.state],
            tcpstates[s->dst.state]);
    }
    
    /* 打印统计信息 */
    if (opts & PF_OPT_VERBOSE) {
        sec = s->creation % 60;
        min = s->creation / 60;
        printf("   age %02u:%02u:%02u", min/60, min%60, sec);
        printf(", %llu:%llu pkts",
            s->packets[0], s->packets[1]);
        printf(", %llu:%llu bytes",
            s->bytes[0], s->bytes[1]);
    }
}
```

## 七、NAT实现

### 7.1 NAT规则处理

```c
int
pf_get_translation(struct pf_pdesc *pd, struct mbuf *m,
    struct pf_krule **rm, struct pf_addr *saddr,
    u_int16_t *sport, struct pf_addr *daddr,
    u_int16_t *dport)
{
    struct pf_krule *r = NULL;
    
    /* 查找NAT规则 */
    if (pd->dir == PF_OUT) {
        /* 出站：查找NAT规则 */
        r = pf_match_translation(pd, m, PF_RULESET_NAT,
            saddr, sport, daddr, dport);
    } else {
        /* 入站：查找RDR规则 */
        r = pf_match_translation(pd, m, PF_RULESET_RDR,
            saddr, sport, daddr, dport);
    }
    
    if (r != NULL) {
        /* 执行地址转换 */
        switch (r->action) {
        case PF_NAT:
            /* 源地址转换 */
            pf_get_pool_addr(&r->nat, saddr, sport, pd->af);
            break;
        case PF_RDR:
            /* 目的地址转换 */
            pf_get_pool_addr(&r->rdr, daddr, dport, pd->af);
            break;
        case PF_BINAT:
            /* 双向NAT */
            if (pd->dir == PF_OUT) {
                pf_get_pool_addr(&r->nat, saddr, sport, pd->af);
            } else {
                pf_get_pool_addr(&r->rdr, daddr, dport, pd->af);
            }
            break;
        }
        
        *rm = r;
        return (1);
    }
    
    return (0);
}
```

### 7.2 地址池管理

```c
struct pf_pool {
    struct pf_palist    list;       /* 地址列表 */
    struct pf_pooladdr  *cur;       /* 当前地址 */
    u_int8_t            opts;       /* 池选项 */
};

/* 从地址池获取地址 */
int
pf_get_pool_addr(struct pf_pool *pool, struct pf_addr *addr,
    u_int16_t *port, sa_family_t af)
{
    struct pf_pooladdr *pa;
    
    /* 选择算法 */
    switch (pool->opts & PF_POOL_TYPEMASK) {
    case PF_POOL_NONE:
        /* 使用第一个地址 */
        pa = TAILQ_FIRST(&pool->list);
        break;
        
    case PF_POOL_ROUNDROBIN:
        /* 轮询 */
        pa = pool->cur;
        pool->cur = TAILQ_NEXT(pa, entries);
        if (pool->cur == NULL)
            pool->cur = TAILQ_FIRST(&pool->list);
        break;
        
    case PF_POOL_RANDOM:
        /* 随机选择 */
        pa = pf_pool_random(&pool->list);
        break;
        
    case PF_POOL_SRCHASH:
        /* 基于源地址哈希 */
        pa = pf_pool_hash(&pool->list, addr);
        break;
        
    case PF_POOL_BITMASK:
        /* 位掩码 */
        pa = pf_pool_bitmask(&pool->list, addr, af);
        break;
    }
    
    /* 复制地址 */
    PF_ACPY(addr, &pa->addr, af);
    
    /* 端口映射 */
    if (port != NULL && pa->port_op) {
        *port = pf_map_port(pa, *port);
    }
    
    return (0);
}
```

## 八、表（Tables）实现

### 8.1 表结构

```c
struct pfr_ktable {
    struct pfr_tstats    pfrkt_ts;     /* 统计信息 */
    RB_HEAD(, pfr_kentry) pfrkt_ip4;   /* IPv4地址树 */
    RB_HEAD(, pfr_kentry) pfrkt_ip6;   /* IPv6地址树 */
    struct pfr_ktable   *pfrkt_shadow; /* 影子表 */
    struct pfr_ktable   *pfrkt_root;   /* 根表 */
    struct pf_kruleset  *pfrkt_rs;     /* 规则集 */
    long                 pfrkt_larg;   /* 用户参数 */
    int                  pfrkt_nflags; /* 通知标志 */
};

struct pfr_kentry {
    struct radix_node    pfrke_node[2]; /* Radix树节点 */
    struct pf_addr       pfrke_sa;      /* 地址 */
    struct pf_addr       pfrke_smask;   /* 掩码 */
    struct pfr_kcounters pfrke_counters;/* 计数器 */
    long                 pfrke_tzero;   /* 时间戳 */
    u_int8_t            pfrke_af;       /* 地址族 */
    u_int8_t            pfrke_net;      /* 网络位数 */
    u_int8_t            pfrke_flags;    /* 标志 */
};
```

### 8.2 表操作

```c
/* 添加地址到表 */
int
pfr_add_addrs(struct pfr_table *tbl, struct pfr_addr *addr,
    int size, int *nadd, int flags)
{
    struct pfr_ktable *kt;
    struct pfr_kentry *ke;
    int i, rv = 0;
    
    /* 查找表 */
    kt = pfr_lookup_table(tbl);
    if (kt == NULL)
        return (ESRCH);
    
    /* 添加地址 */
    for (i = 0; i < size; i++) {
        ke = pfr_create_kentry(&addr[i]);
        if (ke == NULL)
            return (ENOMEM);
        
        /* 插入到Radix树 */
        if (pfr_insert_kentry(kt, ke, flags))
            (*nadd)++;
        else
            pfr_destroy_kentry(ke);
    }
    
    return (rv);
}

/* 表查找 */
int
pfr_match_addr(struct pfr_ktable *kt, struct pf_addr *a,
    sa_family_t af)
{
    struct pfr_kentry *ke;
    
    /* 在Radix树中查找 */
    if (af == AF_INET)
        ke = (struct pfr_kentry *)rn_match(&a->v4,
            &kt->pfrkt_ip4);
    else
        ke = (struct pfr_kentry *)rn_match(&a->v6,
            &kt->pfrkt_ip6);
    
    if (ke && !(ke->pfrke_flags & PFRKE_FLAG_NOT))
        return (1);  /* 匹配 */
    
    return (0);      /* 不匹配 */
}
```

## 九、性能优化

### 9.1 缓存优化

```c
/* Per-CPU状态缓存 */
struct pf_state_cache {
    struct pf_kstate    *cache[PF_STATE_CACHE_SIZE];
    u_int               cache_hits;
    u_int               cache_misses;
};

DPCPU_DEFINE(struct pf_state_cache, pf_state_cache);

/* 缓存查找 */
static struct pf_kstate *
pf_state_cache_lookup(struct pf_state_key_cmp *key)
{
    struct pf_state_cache *cache;
    u_int hash, i;
    
    cache = DPCPU_PTR(pf_state_cache);
    hash = pf_hashkey(key) % PF_STATE_CACHE_SIZE;
    
    /* 检查缓存 */
    for (i = 0; i < PF_STATE_CACHE_DEPTH; i++) {
        struct pf_kstate *s = cache->cache[hash + i];
        if (s && pf_state_key_cmp(s->key[PF_SK_WIRE], key) == 0) {
            cache->cache_hits++;
            return (s);
        }
    }
    
    cache->cache_misses++;
    return (NULL);
}
```

### 9.2 锁优化

```c
/* 读写锁保护规则集 */
struct rwlock pf_rules_lock;

/* 哈希表行锁 */
struct mtx pf_hashrow_lock[PF_HASHROW_LOCK_COUNT];

/* 细粒度锁定 */
#define PF_HASHROW_LOCK(h)    \
    mtx_lock(&pf_hashrow_lock[(h) & PF_HASHROW_LOCK_MASK])
#define PF_HASHROW_UNLOCK(h)  \
    mtx_unlock(&pf_hashrow_lock[(h) & PF_HASHROW_LOCK_MASK])

/* 使用epoch进行无锁读取 */
struct epoch_tracker pf_et;
NET_EPOCH_ENTER(pf_et);
/* 执行只读操作 */
NET_EPOCH_EXIT(pf_et);
```

### 9.3 批处理优化

```c
/* 批量状态更新 */
void
pf_purge_expired_states(void)
{
    struct pf_kstate_list freelist;
    struct pf_kstate *s, *next;
    u_int expired = 0;
    
    LIST_INIT(&freelist);
    
    /* 收集过期状态 */
    PF_HASHROW_LOCK(i);
    LIST_FOREACH_SAFE(s, &V_pf_state_list, entry, next) {
        if (pf_state_expires(s) <= pf_get_uptime()) {
            pf_unlink_state(s);
            LIST_INSERT_HEAD(&freelist, s, entry);
            expired++;
        }
    }
    PF_HASHROW_UNLOCK(i);
    
    /* 批量释放 */
    LIST_FOREACH_SAFE(s, &freelist, entry, next) {
        pf_free_state(s);
    }
    
    V_pf_status.fcounters[FCNT_STATE_EXPIRE] += expired;
}
```

## 十、高级特性

### 10.1 SYN代理（SYN Proxy）

```c
/* SYN代理实现 */
int
pf_synproxy(struct pf_pdesc *pd, struct pf_kstate **state,
    u_short *reason)
{
    struct pf_kstate *s = *state;
    struct tcphdr *th = &pd->hdr.tcp;
    
    if (s->state_flags & PFSTATE_SYNPROXY) {
        if (pd->dir == PF_IN) {
            if (tcp_get_flags(th) & TH_SYN) {
                if (tcp_get_flags(th) & TH_ACK) {
                    /* 客户端完成三次握手 */
                    pf_synproxy_send_syn(s, pd);
                    s->state_flags &= ~PFSTATE_SYNPROXY;
                    s->state_flags |= PFSTATE_SYNPROXY_INIT;
                } else {
                    /* 发送SYN+ACK给客户端 */
                    pf_synproxy_send_synack(s, pd);
                }
                return (PF_SYNPROXY_DROP);
            }
        } else if (pd->dir == PF_OUT) {
            if (s->state_flags & PFSTATE_SYNPROXY_INIT) {
                /* 服务器响应，转发给客户端 */
                if (tcp_get_flags(th) & TH_SYN) {
                    pf_synproxy_send_ack(s, pd);
                    s->state_flags &= ~PFSTATE_SYNPROXY_INIT;
                }
            }
        }
    }
    
    return (PF_PASS);
}
```

### 10.2 操作系统指纹识别

```c
/* OS指纹结构 */
struct pf_osfp_signature {
    u_int16_t   window;     /* TCP窗口大小 */
    u_int8_t    ttl;        /* TTL */
    u_int8_t    df;         /* DF标志 */
    u_int8_t    psize;      /* 数据包大小 */
    u_int8_t    optcnt;     /* TCP选项数量 */
    u_int8_t    wscale;     /* 窗口缩放 */
    u_int8_t    mss;        /* MSS */
    u_int8_t    ts;         /* 时间戳选项 */
};

/* OS指纹匹配 */
struct pf_osfp_entry *
pf_osfp_match(struct pf_pdesc *pd)
{
    struct tcphdr *th = &pd->hdr.tcp;
    struct pf_osfp_signature sig;
    struct pf_osfp_entry *entry;
    
    /* 提取签名 */
    memset(&sig, 0, sizeof(sig));
    sig.window = ntohs(th->th_win);
    sig.ttl = pd->ttl;
    sig.df = (pd->flags & PF_FRAG_DF) ? 1 : 0;
    sig.psize = pd->tot_len;
    
    /* 解析TCP选项 */
    pf_osfp_parse_tcp_options(pd, &sig);
    
    /* 在指纹数据库中查找 */
    LIST_FOREACH(entry, &V_pf_osfp_list, entries) {
        if (pf_osfp_compare(&sig, &entry->signature))
            return (entry);
    }
    
    return (NULL);
}
```

### 10.3 流量整形（ALTQ）

```c
/* ALTQ队列结构 */
struct pf_altq {
    char            ifname[IFNAMSIZ];  /* 接口名 */
    u_int32_t       bandwidth;         /* 带宽 */
    u_int32_t       qlimit;           /* 队列限制 */
    u_int32_t       qid;              /* 队列ID */
    u_int32_t       parent_qid;       /* 父队列ID */
    u_int16_t       scheduler;        /* 调度器类型 */
    u_int16_t       tbrsize;          /* 令牌桶大小 */
};

/* 队列分配 */
int
pf_altq_queue(struct pf_kstate *s, struct mbuf *m)
{
    struct pf_altq *altq;
    
    /* 查找队列 */
    if (s->qid) {
        altq = pf_altq_lookup(s->qid);
        if (altq != NULL) {
            /* 将数据包加入队列 */
            return (altq_enqueue(altq, m));
        }
    }
    
    return (0);
}
```

## 十一、安全特性

### 11.1 防DDoS攻击

```c
/* 源跟踪和限制 */
struct pf_ksrc_node {
    struct pf_addr       addr;         /* 源地址 */
    u_int32_t           states;        /* 状态计数 */
    u_int32_t           conn;          /* 连接计数 */
    struct pf_kthreshold conn_rate;    /* 连接速率 */
    u_int32_t           creation;      /* 创建时间 */
    u_int32_t           expire;        /* 过期时间 */
};

/* 检查源限制 */
int
pf_src_connlimit(struct pf_kstate *state)
{
    struct pf_ksrc_node *sn = state->sns[PF_SN_LIMIT];
    struct pf_krule *r = state->rule;
    
    /* 检查最大连接数 */
    if (r->max_src_conn && sn->conn >= r->max_src_conn)
        return (1);
    
    /* 检查连接速率 */
    if (r->max_src_conn_rate.limit) {
        if (pf_check_threshold(&sn->conn_rate,
            &r->max_src_conn_rate))
            return (1);
    }
    
    /* 检查最大状态数 */
    if (r->max_src_states && sn->states >= r->max_src_states)
        return (1);
    
    return (0);
}
```

### 11.2 分片重组

```c
/* 分片缓存 */
struct pf_fragment {
    RB_ENTRY(pf_fragment) fr_entry;
    TAILQ_HEAD(, pf_frent) fr_queue;
    struct pf_addr  fr_src;        /* 源地址 */
    struct pf_addr  fr_dst;        /* 目的地址 */
    u_int32_t       fr_id;         /* 分片ID */
    u_int16_t       fr_max;        /* 最大分片偏移 */
    u_int16_t       fr_holes;      /* 空洞数量 */
    u_int32_t       fr_timeout;    /* 超时时间 */
};

/* 分片重组 */
struct mbuf *
pf_reassemble(struct mbuf **m, struct pf_pdesc *pd)
{
    struct pf_fragment *frag;
    struct pf_frent *frent;
    
    /* 查找或创建分片缓存 */
    frag = pf_find_fragment(pd);
    if (frag == NULL) {
        frag = pf_create_fragment(pd);
        if (frag == NULL)
            return (NULL);
    }
    
    /* 插入分片 */
    frent = pf_create_frent(*m, pd);
    if (pf_frent_insert(frag, frent, pd) != 0) {
        pf_free_frent(frent);
        return (NULL);
    }
    
    /* 检查是否完整 */
    if (frag->fr_holes == 0) {
        /* 重组完成 */
        *m = pf_join_fragment(frag);
        pf_free_fragment(frag);
        return (*m);
    }
    
    return (NULL);
}
```

## 十二、调试和监控

### 12.1 统计信息

```c
/* PF统计结构 */
struct pf_status {
    u_int64_t   counters[PFRES_MAX];   /* 各种计数器 */
    u_int64_t   fcounters[FCNT_MAX];   /* 功能计数器 */
    u_int64_t   scounters[SCNT_MAX];   /* 源跟踪计数器 */
    u_int64_t   pcounters[2][2][3];    /* 协议计数器 */
    u_int64_t   bcounters[2][2];       /* 字节计数器 */
    u_int32_t   running;                /* 运行状态 */
    u_int32_t   states;                 /* 当前状态数 */
    u_int32_t   src_nodes;              /* 源节点数 */
    u_int32_t   since;                  /* 启动时间 */
    u_int32_t   debug;                  /* 调试级别 */
    char        ifname[IFNAMSIZ];      /* 日志接口 */
};
```

### 12.2 日志记录

```c
/* 日志记录 */
void
pf_log_packet(struct pf_pdesc *pd, u_int8_t reason,
    struct pf_krule *r, struct pf_krule *a,
    struct pf_kruleset *rs)
{
    struct pfloghdr hdr;
    
    if (!pf_status.ifname[0] || !pd->kif)
        return;
    
    memset(&hdr, 0, sizeof(hdr));
    hdr.length = PFLOG_REAL_HDRLEN;
    hdr.action = r->action;
    hdr.reason = reason;
    hdr.dir = pd->dir;
    hdr.af = pd->af;
    
    if (r != NULL) {
        hdr.rulenr = r->nr;
        hdr.subrulenr = a ? a->nr : -1;
        strlcpy(hdr.ruleset, rs->anchor->path,
            sizeof(hdr.ruleset));
    }
    
    /* 发送到pflog接口 */
    pflog_packet(pd->kif, &hdr, pd->m);
}
```

## 十三、总结

### 13.1 设计特点

1. **模块化架构**
   - 清晰的层次结构
   - 组件间低耦合
   - 易于扩展和维护

2. **高性能设计**
   - 多级哈希表
   - Per-CPU缓存
   - 细粒度锁
   - 批处理优化

3. **丰富的功能**
   - 完整的状态检测
   - 灵活的NAT支持
   - 高级安全特性
   - 流量控制能力

4. **优秀的可管理性**
   - 强大的pfctl工具
   - 详细的统计信息
   - 完善的日志系统
   - 实时监控能力

### 13.2 与Linux netfilter/iptables对比

| 特性 | PF | netfilter/iptables |
|------|----|--------------------|
| 架构 | 集成式 | 模块化 |
| 规则语法 | 简洁统一 | 复杂分散 |
| 性能 | 优秀 | 良好 |
| NAT集成 | 原生支持 | 独立模块 |
| 状态表 | 统一管理 | 分离实现 |
| 配置方式 | 配置文件 | 命令行 |
| 锚点支持 | 原生支持 | 需要扩展 |
| OS指纹 | 内置支持 | 需要扩展 |

### 13.3 最佳实践

1. **规则优化**
   - 使用quick规则减少评估
   - 合理使用表和宏
   - 利用锚点组织规则

2. **性能调优**
   - 调整状态表大小
   - 优化超时值
   - 使用表替代大量规则

3. **安全配置**
   - 启用SYN代理
   - 设置连接限制
   - 使用最小权限原则

4. **监控维护**
   - 定期检查统计信息
   - 监控状态表使用率
   - 分析日志发现异常

### 13.4 发展趋势

1. **性能提升**
   - 更好的多核扩展
   - 硬件加速支持
   - 无锁数据结构

2. **功能增强**
   - 应用层过滤
   - DPI集成
   - 机器学习应用

3. **云原生支持**
   - 容器网络集成
   - 微服务支持
   - 动态配置管理

PF作为BSD系统的核心防火墙组件，以其简洁的设计、强大的功能和优秀的性能，成为了网络安全基础设施的重要组成部分。通过深入理解其实现原理，我们可以更好地利用PF构建安全、高效的网络环境。