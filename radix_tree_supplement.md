# Radix树在PF中的应用 - 补充知识

## 一、Radix树概述

### 1.1 什么是Radix树

Radix树（也称为Patricia树 - Practical Algorithm to Retrieve Information Coded in Alphanumeric）是一种空间优化的前缀树（Trie），主要用于高效存储和检索具有共同前缀的字符串或二进制数据。在网络领域，Radix树广泛用于IP路由表和防火墙地址表的实现。

### 1.2 Radix树的特点

1. **空间效率高**：通过压缩共同前缀，减少节点数量
2. **查找速度快**：O(k)时间复杂度，k为键的长度
3. **支持最长前缀匹配**：天然适合IP地址查找
4. **插入和删除高效**：O(k)时间复杂度
5. **有序遍历**：支持按字典序遍历所有键

### 1.3 与普通Trie树的区别

```
普通Trie树：
    root
    /  \
   1    0
  /    /
 0    1
/    /
1   0

Radix树（压缩后）：
    root
    /  \
  101   010
```

## 二、BSD Radix树实现

### 2.1 核心数据结构

```c
/* Radix树节点结构 */
struct radix_node {
    struct radix_mask *rn_mklist;     /* 子树中包含的掩码列表 */
    struct radix_node *rn_parent;     /* 父节点 */
    short rn_bit;                     /* 位偏移；-1-index(netmask) */
    char rn_bmask;                    /* 节点：位测试的掩码 */
    u_char rn_flags;                  /* 标志位 */
    
    union {
        struct {                      /* 叶子节点数据 */
            caddr_t rn_Key;          /* 搜索对象（键） */
            caddr_t rn_Mask;         /* 网络掩码（如果存在） */
            struct radix_node *rn_Dupedkey; /* 重复键链表 */
        } rn_leaf;
        struct {                      /* 内部节点数据 */
            int rn_Off;              /* 比较开始位置 */
            struct radix_node *rn_L; /* 左子节点 */
            struct radix_node *rn_R; /* 右子节点 */
        } rn_node;
    } rn_u;
};

/* Radix树头部 */
struct radix_head {
    struct radix_node *rnh_treetop;   /* 树的根节点 */
    struct radix_mask_head *rnh_masks; /* 掩码存储 */
};

/* Radix节点头（包含操作函数） */
struct radix_node_head {
    struct radix_head rh;
    rn_matchaddr_f_t *rnh_matchaddr;  /* 最长匹配 */
    rn_addaddr_f_t *rnh_addaddr;       /* 添加地址 */
    rn_deladdr_f_t *rnh_deladdr;       /* 删除地址 */
    rn_lookup_f_t *rnh_lookup;         /* 精确查找 */
    rn_walktree_t *rnh_walktree;       /* 遍历树 */
    struct radix_node rnh_nodes[3];    /* 空树的初始节点 */
    struct rmlock rnh_lock;            /* 树的读写锁 */
};
```

### 2.2 关键字段说明

- **rn_bit**: 指示在哪个位位置进行分支判断
- **rn_bmask**: 用于测试特定位的掩码
- **rn_Key**: 存储实际的地址数据
- **rn_Mask**: 存储网络掩码（用于CIDR）
- **rn_L/rn_R**: 左右子树，基于位值0/1选择

## 三、PF中的Radix树应用

### 3.1 PF表结构

```c
/* PF表结构 */
struct pfr_ktable {
    struct pfr_tstats pfrkt_ts;           /* 统计信息 */
    struct radix_node_head *pfrkt_ip4;    /* IPv4地址Radix树 */
    struct radix_node_head *pfrkt_ip6;    /* IPv6地址Radix树 */
    struct pfr_ktable *pfrkt_shadow;      /* 影子表 */
    struct pfr_ktable *pfrkt_root;        /* 根表 */
    struct pf_kruleset *pfrkt_rs;         /* 关联的规则集 */
    long pfrkt_larg;                      /* 用户参数 */
    int pfrkt_nflags;                     /* 通知标志 */
};

/* PF表项结构 */
struct pfr_kentry {
    struct radix_node pfrke_node[2];      /* Radix树节点 */
    union sockaddr_union pfrke_sa;        /* 地址 */
    SLIST_ENTRY(pfr_kentry) pfrke_workq;  /* 工作队列 */
    struct pfr_kcounters pfrke_counters;  /* 计数器 */
    u_int8_t pfrke_af;                    /* 地址族 */
    u_int8_t pfrke_net;                   /* 网络前缀长度 */
    u_int8_t pfrke_not;                   /* 否定标志 */
    u_int8_t pfrke_flags;                 /* 其他标志 */
};
```

### 3.2 地址插入操作

```c
/* 将地址插入到Radix树 */
static int
pfr_route_kentry(struct pfr_ktable *kt, struct pfr_kentry *ke)
{
    union sockaddr_union mask;
    struct radix_node *rn;
    struct radix_head *head = NULL;
    
    /* 清空节点数组 */
    bzero(ke->pfrke_node, sizeof(ke->pfrke_node));
    
    /* 选择对应的Radix树（IPv4或IPv6） */
    switch (ke->pfrke_af) {
    case AF_INET:
        head = &kt->pfrkt_ip4->rh;
        break;
    case AF_INET6:
        head = &kt->pfrkt_ip6->rh;
        break;
    }
    
    /* 处理网络地址或主机地址 */
    if (KENTRY_NETWORK(ke)) {
        /* 网络地址：准备网络掩码 */
        pfr_prepare_network(&mask, ke->pfrke_af, ke->pfrke_net);
        rn = rn_addroute(&ke->pfrke_sa, &mask, head, ke->pfrke_node);
    } else {
        /* 主机地址：不需要掩码 */
        rn = rn_addroute(&ke->pfrke_sa, NULL, head, ke->pfrke_node);
    }
    
    return (rn == NULL ? -1 : 0);
}
```

### 3.3 地址查找操作

```c
/* 在表中查找地址 */
static struct pfr_kentry *
pfr_lookup_addr(struct pfr_ktable *kt, struct pfr_addr *ad, int exact)
{
    union sockaddr_union sa, mask;
    struct radix_head *head = NULL;
    struct radix_node *rn;
    struct pfr_kentry *ke = NULL;
    
    /* 准备查找的地址 */
    bzero(&sa, sizeof(sa));
    switch (ad->pfra_af) {
    case AF_INET:
        FILLIN_SIN(sa.sin, ad->pfra_ip4addr);
        head = &kt->pfrkt_ip4->rh;
        break;
    case AF_INET6:
        FILLIN_SIN6(sa.sin6, ad->pfra_ip6addr);
        head = &kt->pfrkt_ip6->rh;
        break;
    default:
        return (NULL);
    }
    
    /* 执行查找 */
    if (exact) {
        /* 精确匹配 */
        if (ad->pfra_net == AF_BITS(ad->pfra_af)) {
            /* 主机地址 */
            rn = rn_lookup(&sa, NULL, head);
        } else {
            /* 网络地址 */
            pfr_prepare_network(&mask, ad->pfra_af, ad->pfra_net);
            rn = rn_lookup(&sa, &mask, head);
        }
        if (rn != NULL)
            ke = (struct pfr_kentry *)rn;
    } else {
        /* 最长前缀匹配 */
        rn = rn_match(&sa, head);
        if (rn != NULL) {
            ke = (struct pfr_kentry *)rn;
            /* 检查是否需要应用否定逻辑 */
            if (ke->pfrke_not)
                ke = NULL;
        }
    }
    
    return (ke);
}
```

### 3.4 地址删除操作

```c
/* 从Radix树中删除地址 */
static int
pfr_unroute_kentry(struct pfr_ktable *kt, struct pfr_kentry *ke)
{
    union sockaddr_union mask;
    struct radix_node *rn;
    struct radix_head *head = NULL;
    
    /* 选择对应的Radix树 */
    switch (ke->pfrke_af) {
    case AF_INET:
        head = &kt->pfrkt_ip4->rh;
        break;
    case AF_INET6:
        head = &kt->pfrkt_ip6->rh;
        break;
    }
    
    /* 执行删除 */
    if (KENTRY_NETWORK(ke)) {
        /* 网络地址 */
        pfr_prepare_network(&mask, ke->pfrke_af, ke->pfrke_net);
        rn = rn_delete(&ke->pfrke_sa, &mask, head);
    } else {
        /* 主机地址 */
        rn = rn_delete(&ke->pfrke_sa, NULL, head);
    }
    
    if (rn == NULL) {
        printf("pfr_unroute_kentry: delete failed.\n");
        return (-1);
    }
    return (0);
}
```

## 四、Radix树的查找算法

### 4.1 最长前缀匹配（LPM）

```c
/* Radix树的最长前缀匹配实现 */
struct radix_node *
rn_match(const void *v_arg, struct radix_head *head)
{
    const u_char *v = v_arg;
    struct radix_node *t = head->rnh_treetop;
    struct radix_node *x;
    const u_char *cp = v;
    struct radix_node *saved_t;
    int off = t->rn_offset;
    int vlen = LEN(v);
    int matched_off;
    
    /*
     * 开始向下遍历树
     * 通过比较关键位来决定走左子树还是右子树
     */
    for (; t->rn_bit >= 0; ) {
        if (t->rn_bmask & cp[t->rn_offset])
            t = t->rn_right;
        else
            t = t->rn_left;
    }
    
    /*
     * 到达叶子节点，检查是否匹配
     * 如果不完全匹配，需要回溯找到最长的匹配前缀
     */
    cp = v;
    x = t;
    do {
        if (x->rn_mask) {
            /*
             * 如果节点有掩码，检查掩码覆盖的部分是否匹配
             */
            if (x->rn_flags & RNF_NORMAL) {
                if (rn_satisfies_leaf(v, x, matched_off))
                    return (x);
            }
        }
        /* 尝试重复键链表中的下一个 */
        x = x->rn_dupedkey;
    } while (x);
    
    /*
     * 回溯：向上查找可能的匹配
     * 这是实现最长前缀匹配的关键
     */
    saved_t = t;
    do {
        t = t->rn_parent;
        if (t->rn_flags & RNF_ROOT)
            return (NULL);
    } while (t->rn_bit >= matched_off);
    
    /* 继续搜索... */
    return (NULL);
}
```

### 4.2 精确匹配

```c
/* 精确匹配查找 */
struct radix_node *
rn_lookup(const void *v_arg, const void *m_arg, struct radix_head *head)
{
    struct radix_node *t;
    const u_char *v = v_arg;
    
    /* 首先找到可能的匹配节点 */
    t = rn_search(v, head->rnh_treetop);
    
    /* 验证是否精确匹配 */
    if (t->rn_flags & RNF_ROOT)
        return (NULL);
    
    /* 如果提供了掩码，需要精确匹配掩码 */
    if (m_arg) {
        const u_char *m = m_arg;
        if (!rn_maskcmp(m, t->rn_mask, LEN(m)))
            return (NULL);
    }
    
    /* 验证键是否完全匹配 */
    if (bcmp(v, t->rn_key, LEN(v)) != 0)
        return (NULL);
    
    return (t);
}
```

## 五、PF表的实际应用场景

### 5.1 黑名单/白名单

```bash
# 创建黑名单表
table <blacklist> persist
table <whitelist> persist

# 添加地址到表
pfctl -t blacklist -T add 192.168.1.0/24
pfctl -t blacklist -T add 10.0.0.5
pfctl -t whitelist -T add 172.16.0.0/16

# 在规则中使用表
block in quick from <blacklist>
pass in quick from <whitelist>
```

### 5.2 地理位置过滤

```bash
# 创建国家IP地址表
table <china> persist file "/etc/pf/cn_zones.txt"
table <usa> persist file "/etc/pf/us_zones.txt"

# 基于地理位置的访问控制
pass in proto tcp from <china> to any port 443
block in proto tcp from !<usa> to any port 22
```

### 5.3 动态地址管理

```c
/* 动态添加地址到表 */
int
pfr_add_addrs(struct pfr_table *tbl, struct pfr_addr *addr, 
    int size, int *nadd, int flags)
{
    struct pfr_ktable *kt;
    struct pfr_kentryworkq workq;
    struct pfr_kentry *ke;
    int i, rv = 0;
    
    /* 查找表 */
    kt = pfr_lookup_table(tbl);
    if (kt == NULL)
        return (ESRCH);
    
    /* 准备工作队列 */
    SLIST_INIT(&workq);
    
    /* 创建表项并加入工作队列 */
    for (i = 0; i < size; i++) {
        ke = pfr_create_kentry(&addr[i]);
        if (ke == NULL) {
            rv = ENOMEM;
            break;
        }
        SLIST_INSERT_HEAD(&workq, ke, pfrke_workq);
    }
    
    /* 批量插入到Radix树 */
    if (rv == 0) {
        pfr_insert_kentries(kt, &workq, time_second);
        *nadd = size;
    } else {
        pfr_destroy_kentries(&workq);
    }
    
    return (rv);
}
```

## 六、Radix树的性能特征

### 6.1 时间复杂度

| 操作 | 时间复杂度 | 说明 |
|------|-----------|------|
| 插入 | O(k) | k为地址位数（IPv4=32, IPv6=128） |
| 删除 | O(k) | 需要遍历到叶子节点 |
| 精确查找 | O(k) | 直接路径查找 |
| 最长前缀匹配 | O(k) | 可能需要回溯 |
| 遍历 | O(n) | n为节点数 |

### 6.2 空间复杂度

- 最坏情况：O(n*k)，n为存储的地址数，k为地址位数
- 实际情况：由于前缀压缩，通常远小于最坏情况
- PF优化：分离IPv4和IPv6树，减少节点大小

### 6.3 缓存友好性

```c
/* PF的缓存优化 */
struct pfr_kentry {
    /* 将Radix节点放在结构开始，提高缓存命中率 */
    struct radix_node pfrke_node[2];
    
    /* 常用字段紧凑排列 */
    union sockaddr_union pfrke_sa;
    u_int8_t pfrke_af;
    u_int8_t pfrke_net;
    u_int8_t pfrke_not;
    u_int8_t pfrke_flags;
    
    /* 统计信息放在后面 */
    struct pfr_kcounters pfrke_counters;
} __packed;
```

## 七、Radix树 vs 其他数据结构

### 7.1 对比分析

| 数据结构 | 查找 | 插入 | 删除 | 空间 | LPM支持 | 适用场景 |
|---------|------|------|------|------|---------|---------|
| Radix树 | O(k) | O(k) | O(k) | 优 | 原生 | IP路由表、防火墙表 |
| 哈希表 | O(1) | O(1) | O(1) | 中 | 需扩展 | 精确匹配为主 |
| 红黑树 | O(logn) | O(logn) | O(logn) | 良 | 需扩展 | 范围查询 |
| Trie树 | O(k) | O(k) | O(k) | 差 | 原生 | 字符串前缀 |
| B+树 | O(logn) | O(logn) | O(logn) | 优 | 需扩展 | 数据库索引 |

### 7.2 为什么PF选择Radix树

1. **天然支持CIDR**：网络地址的前缀特性完美匹配
2. **最长前缀匹配**：路由和防火墙规则的核心需求
3. **确定性性能**：O(k)复杂度，k固定（32或128）
4. **空间效率**：前缀压缩节省内存
5. **BSD传统**：成熟稳定的实现

## 八、Radix树的优化技术

### 8.1 路径压缩

```c
/* 路径压缩示例 */
传统Trie：
    root
     |
    0 (bit 0)
     |
    1 (bit 1)
     |
    0 (bit 2)
     |
    1 (bit 3)

压缩后的Radix：
    root
     |
   0101 (bits 0-3)
```

### 8.2 级别压缩（Level Compression）

```c
/* 多位分支，减少树的深度 */
struct radix_node_multibit {
    int rn_bit_width;    /* 一次检查的位数 */
    int rn_children[16]; /* 4位一组，16个子节点 */
};
```

### 8.3 缓存行对齐

```c
/* 确保热点数据在同一缓存行 */
struct pfr_kentry {
    struct radix_node pfrke_node[2] __aligned(64);
    /* ... */
} __aligned(CACHE_LINE_SIZE);
```

## 九、调试和监控

### 9.1 表统计信息

```c
/* PF表统计结构 */
struct pfr_tstats {
    struct pfr_table pfrts_t;
    u_int64_t pfrts_packets[2];  /* 入站/出站数据包 */
    u_int64_t pfrts_bytes[2];    /* 入站/出站字节 */
    u_int64_t pfrts_match;       /* 匹配次数 */
    u_int64_t pfrts_nomatch;     /* 未匹配次数 */
    long pfrts_tzero;            /* 统计清零时间 */
    int pfrts_cnt;               /* 地址计数 */
    int pfrts_refcnt;            /* 引用计数 */
};
```

### 9.2 查看表内容

```bash
# 显示表中的所有地址
pfctl -t blacklist -T show

# 显示表的统计信息
pfctl -t blacklist -T show -v

# 测试地址是否在表中
pfctl -t blacklist -T test 192.168.1.1

# 显示表的树结构（调试）
pfctl -t blacklist -T show -vv
```

### 9.3 性能监控

```c
/* 监控Radix树操作性能 */
struct pfr_kentry_stats {
    u_int64_t lookups;      /* 查找次数 */
    u_int64_t hits;         /* 命中次数 */
    u_int64_t misses;       /* 未命中次数 */
    u_int64_t insertions;   /* 插入次数 */
    u_int64_t deletions;    /* 删除次数 */
    u_int64_t traversals;   /* 遍历次数 */
    struct timespec avg_lookup_time;
    struct timespec max_lookup_time;
};
```

## 十、最佳实践

### 10.1 表设计原则

1. **合理分组**：将相关地址组织在同一个表中
2. **避免重叠**：减少地址范围的重叠，提高查找效率
3. **使用CIDR**：尽可能使用网络地址而非单个主机
4. **定期维护**：清理无用地址，保持表的精简

### 10.2 性能优化建议

1. **预加载表**：启动时一次性加载，避免动态添加开销
2. **使用persist标志**：保持表在内存中，避免重复构建
3. **批量操作**：使用批量添加/删除，减少锁开销
4. **合理设置表大小**：避免过大的表影响性能

### 10.3 安全考虑

1. **限制表大小**：防止内存耗尽攻击
2. **验证输入**：检查地址格式和范围的合法性
3. **审计日志**：记录表的修改操作
4. **备份恢复**：定期备份重要的表配置

## 十一、总结

Radix树在PF中的应用充分展现了这种数据结构在网络地址管理中的优势：

1. **高效性**：O(k)的确定性性能，适合实时网络处理
2. **灵活性**：支持主机地址、网络地址、否定匹配等多种模式
3. **可扩展性**：能够高效处理大量地址（数十万级别）
4. **实用性**：完美支持CIDR和最长前缀匹配

通过深入理解Radix树的原理和PF的实现，我们可以：
- 更好地设计和优化防火墙规则
- 理解表操作的性能特征
- 正确使用PF的表功能
- 诊断和解决性能问题

Radix树作为PF表的核心数据结构，是PF高性能和灵活性的重要基础。