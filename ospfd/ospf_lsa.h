/*
 * OSPF Link State Advertisement
 * Copyright (C) 1999, 2000 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_OSPF_LSA_H
#define _ZEBRA_OSPF_LSA_H

#include "stream.h"

/* OSPF LSA Range definition. */
#define OSPF_MIN_LSA        1  /* begin range here */
#define OSPF_MAX_LSA           12

/* OSPF LSA Type definition. */
#define OSPF_UNKNOWN_LSA          0
#define OSPF_ROUTER_LSA               1
#define OSPF_NETWORK_LSA              2
#define OSPF_SUMMARY_LSA              3
#define OSPF_ASBR_SUMMARY_LSA         4
#define OSPF_AS_EXTERNAL_LSA          5
#define OSPF_GROUP_MEMBER_LSA         6  /* Not supported. */
#define OSPF_AS_NSSA_LSA                  7
#define OSPF_EXTERNAL_ATTRIBUTES_LSA  8  /* Not supported. */
#define OSPF_OPAQUE_LINK_LSA          9
#define OSPF_OPAQUE_AREA_LSA         10
#define OSPF_OPAQUE_AS_LSA       11

#define OSPF_LSA_HEADER_SIZE         20U
#define OSPF_ROUTER_LSA_LINK_SIZE    12U
#define OSPF_ROUTER_LSA_TOS_SIZE      4U
#define OSPF_MAX_LSA_SIZE      1500U

/* AS-external-LSA refresh method. */
#define LSA_REFRESH_IF_CHANGED  0
#define LSA_REFRESH_FORCE   1

/* OSPF LSA header. */
struct lsa_header
{
    u_int16_t ls_age; /* 老化时间 */
    u_char options; /* 可选项 */
    u_char type; /* 类型 */
    struct in_addr id; /* 链路状态id */
    struct in_addr adv_router; /* 通告路由器 */
    u_int32_t ls_seqnum; /* 序列号 */
    u_int16_t checksum;
    u_int16_t length; /* 长度 */
};

/* OSPF LSA.
 * 链路状态信息通告 -- 其实就是拓扑信息
 */
struct ospf_lsa
{
    /* LSA origination flag. */
    u_char flags; /* lsa来源标记 */
#define OSPF_LSA_SELF         0x01 /* 自己产生的 */
#define OSPF_LSA_SELF_CHECKED     0x02 /* 已经检查过的lsa会打上此标记 */
#define OSPF_LSA_RECEIVED     0x04 /* 表示此lsa从别的路由器处接收到 */
/* OSPF_LSA_APPROVED这个标记仅仅由Type-3和Type-4的LSA使用 */
#define OSPF_LSA_APPROVED     0x08 /* 检查通过的lsa会被标记为approved,unapprved的lsa会被老化 */
#define OSPF_LSA_DISCARD      0x10
#define OSPF_LSA_LOCAL_XLT    0x20 /* 表示LSA从type-7转换而来 */
#define OSPF_LSA_PREMATURE_AGE    0x40
#define OSPF_LSA_IN_MAXAGE    0x80 /* 表示LSA已经老化 */

    /* LSA data. */
    struct lsa_header *data;

    /* Received time stamp. 接收到lsa的时间*/
    struct timeval tv_recv;

    /* Last time it was originated */
    struct timeval tv_orig;

    /* All of reference count, also lock to remove. */
    int lock; /* 引用计数,每一次被别的结构引用,+1,被解引用,-1,直到为0才可以被删除 */

    /* Flags for the SPF calculation. */
    int stat; /* 用于计算最小生成树的辅助标记 */
#define LSA_SPF_NOT_EXPLORED  -1
#define LSA_SPF_IN_SPFTREE    -2
    /* If stat >= 0, stat is LSA position in candidates heap. */

    /* References to this LSA in neighbor retransmission lists*/
    int retransmit_counter;

    /* Area the LSA belongs to, may be NULL if AS-external-LSA.
     * 此lsa属于哪个区域
     */
    struct ospf_area *area;

    /* Parent LSDB. */
    struct ospf_lsdb *lsdb;

    /* Related Route. */
    void *route; /* 记录相关的路由表项 */

    /* Refreshement List or Queue */
    int refresh_list; /* 记录此lsa在ospf的lsa_refresh_queue.qs中的哪一个链表之中 */

    /* For Type-9 Opaque-LSAs */
    struct ospf_interface *oi;
};

/* OSPF LSA Link Type. */
#define LSA_LINK_TYPE_POINTOPOINT      1
#define LSA_LINK_TYPE_TRANSIT          2
#define LSA_LINK_TYPE_STUB             3
#define LSA_LINK_TYPE_VIRTUALLINK      4

/* OSPF Router LSA Flag. */
#define ROUTER_LSA_BORDER          0x01 /* The router is an ABR */
#define ROUTER_LSA_EXTERNAL        0x02 /* The router is an ASBR */
#define ROUTER_LSA_VIRTUAL         0x04 /* The router has a VL in this area */
#define ROUTER_LSA_NT              0x10 /* The routers always translates Type-7 */
#define ROUTER_LSA_SHORTCUT        0x20 /* Shortcut-ABR specific flag */

#define IS_ROUTER_LSA_VIRTUAL(x)       ((x)->flags & ROUTER_LSA_VIRTUAL)
#define IS_ROUTER_LSA_EXTERNAL(x)      ((x)->flags & ROUTER_LSA_EXTERNAL)
#define IS_ROUTER_LSA_BORDER(x)        ((x)->flags & ROUTER_LSA_BORDER)
#define IS_ROUTER_LSA_SHORTCUT(x)      ((x)->flags & ROUTER_LSA_SHORTCUT)
#define IS_ROUTER_LSA_NT(x)            ((x)->flags & ROUTER_LSA_NT)

/* OSPF Router-LSA Link information.
 * router-lsa中对应的信息
 */
struct router_lsa_link
{
    struct in_addr link_id; /* 链路id */
    struct in_addr link_data; /* 链路数据 */
    struct
    {
        u_char type; /* 链路类型 */
        u_char tos_count; /* tos数目 */
        u_int16_t metric; /* 度量 */
    } m[1];
};

/* OSPF Router-LSAs structure. */
#define OSPF_ROUTER_LSA_MIN_SIZE                   4U /* w/0 link descriptors */
/* There is an edge case, when number of links in a Router-LSA may be 0 without
   breaking the specification. A router, which has no other links to backbone
   area besides one virtual link, will not put any VL descriptor blocks into
   the Router-LSA generated for area 0 until a full adjacency over the VL is
   reached (RFC2328 12.4.1.3). In this case the Router-LSA initially received
   by the other end of the VL will have 0 link descriptor blocks, but soon will
   be replaced with the next revision having 1 descriptor block. */
struct router_lsa
{
    struct lsa_header header;
    u_char flags; /* B 始发路由器是一个ASBR路由器,B始发路由器是一个ABR */
    u_char zero;
    u_int16_t links;
    struct
    {
        struct in_addr link_id;
        struct in_addr link_data;
        u_char type;
        u_char tos;
        u_int16_t metric;
    } link[1];
};

/* OSPF Network-LSAs structure. */
#define OSPF_NETWORK_LSA_MIN_SIZE                  8U /* w/1 router-ID */
struct network_lsa
{
    struct lsa_header header;
    struct in_addr mask;
    struct in_addr routers[1];
};

/* OSPF Summary-LSAs structure. */
#define OSPF_SUMMARY_LSA_MIN_SIZE                  8U /* w/1 TOS metric block */
struct summary_lsa
{
    struct lsa_header header;
    struct in_addr mask;
    u_char tos;
    u_char metric[3];
};

/* OSPF AS-external-LSAs structure. */
#define OSPF_AS_EXTERNAL_LSA_MIN_SIZE             16U /* w/1 TOS forwarding block */
/*
 * 自主系统外部LSA,也就是这里的路由信息,事实上是外部导入的
 */
struct as_external_lsa
{
    struct lsa_header header;
    struct in_addr mask; /* 网络掩码 */
    struct
    {
        u_char tos;
        u_char metric[3]; /* 度量 */
        struct in_addr fwd_addr; /* 转发地址 */
        u_int32_t route_tag; /* 外部路由标志 */
    } e[1];
};

#include "ospfd/ospf_opaque.h"

/* Macros. */
#define GET_METRIC(x) get_metric(x)
#define IS_EXTERNAL_METRIC(x)   ((x) & 0x80)

#define GET_AGE(x)     (ntohs ((x)->data->ls_age) + time (NULL) - (x)->tv_recv)
#define LS_AGE(x)      (OSPF_LSA_MAXAGE < get_age(x) ? \
                                           OSPF_LSA_MAXAGE : get_age(x))
#define IS_LSA_SELF(L)          (CHECK_FLAG ((L)->flags, OSPF_LSA_SELF))
#define IS_LSA_MAXAGE(L)        (LS_AGE ((L)) == OSPF_LSA_MAXAGE)

#define OSPF_LSA_UPDATE_DELAY       2

#define OSPF_LSA_UPDATE_TIMER_ON(T,F) \
      if (!(T)) \
        (T) = thread_add_timer (master, (F), 0, 2)

/* Prototypes. */
/* XXX: Eek, time functions, similar are in lib/thread.c */
extern struct timeval tv_adjust (struct timeval);
extern int tv_ceil (struct timeval);
extern int tv_floor (struct timeval);
extern struct timeval int2tv (int);
extern struct timeval msec2tv (int);
extern struct timeval tv_add (struct timeval, struct timeval);
extern struct timeval tv_sub (struct timeval, struct timeval);
extern int tv_cmp (struct timeval, struct timeval);

extern int get_age (struct ospf_lsa *);
extern u_int16_t ospf_lsa_checksum (struct lsa_header *);
extern int ospf_lsa_checksum_valid (struct lsa_header *);
extern int ospf_lsa_refresh_delay (struct ospf_lsa *);

extern const char *dump_lsa_key (struct ospf_lsa *);
extern u_int32_t lsa_seqnum_increment (struct ospf_lsa *);
extern void lsa_header_set (struct stream *, u_char, u_char, struct in_addr,
                            struct in_addr);
extern struct ospf_neighbor *ospf_nbr_lookup_ptop (struct ospf_interface *);
extern int ospf_check_nbr_status (struct ospf *);

/* Prototype for LSA primitive. */
extern struct ospf_lsa *ospf_lsa_new (void);
extern struct ospf_lsa *ospf_lsa_dup (struct ospf_lsa *);
extern void ospf_lsa_free (struct ospf_lsa *);
extern struct ospf_lsa *ospf_lsa_lock (struct ospf_lsa *);
extern void ospf_lsa_unlock (struct ospf_lsa **);
extern void ospf_lsa_discard (struct ospf_lsa *);

extern struct lsa_header *ospf_lsa_data_new (size_t);
extern struct lsa_header *ospf_lsa_data_dup (struct lsa_header *);
extern void ospf_lsa_data_free (struct lsa_header *);

/* Prototype for various LSAs */
extern int ospf_router_lsa_update (struct ospf *);
extern int ospf_router_lsa_update_area (struct ospf_area *);

extern void ospf_network_lsa_update (struct ospf_interface *);

extern struct ospf_lsa *ospf_summary_lsa_originate (struct prefix_ipv4 *, u_int32_t,
        struct ospf_area *);
extern struct ospf_lsa *ospf_summary_asbr_lsa_originate (struct prefix_ipv4 *,
        u_int32_t,
        struct ospf_area *);

extern struct ospf_lsa *ospf_lsa_install (struct ospf *,
        struct ospf_interface *, struct ospf_lsa *);

extern void ospf_nssa_lsa_flush (struct ospf *ospf, struct prefix_ipv4 *p);
extern void ospf_external_lsa_flush (struct ospf *, u_char, struct prefix_ipv4 *,
                                     ifindex_t /* , struct in_addr nexthop */);

extern struct in_addr ospf_get_ip_from_ifp (struct ospf_interface *);

extern struct ospf_lsa *ospf_external_lsa_originate (struct ospf *, struct external_info *);
extern int ospf_external_lsa_originate_timer (struct thread *);
extern int ospf_default_originate_timer (struct thread *);
extern struct ospf_lsa *ospf_lsa_lookup (struct ospf_area *, u_int32_t,
        struct in_addr, struct in_addr);
extern struct ospf_lsa *ospf_lsa_lookup_by_id (struct ospf_area *,
        u_int32_t,
        struct in_addr);
extern struct ospf_lsa *ospf_lsa_lookup_by_header (struct ospf_area *,
        struct lsa_header *);
extern int ospf_lsa_more_recent (struct ospf_lsa *, struct ospf_lsa *);
extern int ospf_lsa_different (struct ospf_lsa *, struct ospf_lsa *);
extern void ospf_flush_self_originated_lsas_now (struct ospf *);

extern int ospf_lsa_is_self_originated (struct ospf *, struct ospf_lsa *);

extern struct ospf_lsa *ospf_lsa_lookup_by_prefix (struct ospf_lsdb *, u_char,
        struct prefix_ipv4 *,
        struct in_addr);

extern void ospf_lsa_maxage (struct ospf *, struct ospf_lsa *);
extern u_int32_t get_metric (u_char *);

extern int ospf_lsa_maxage_walker (struct thread *);
extern struct ospf_lsa *ospf_lsa_refresh (struct ospf *, struct ospf_lsa *);

extern void ospf_external_lsa_refresh_default (struct ospf *);

extern void ospf_external_lsa_refresh_type (struct ospf *, u_char, int);
extern struct ospf_lsa *ospf_external_lsa_refresh (struct ospf *,
        struct ospf_lsa *,
        struct external_info *,
        int);
extern struct in_addr ospf_lsa_unique_id (struct ospf *, struct ospf_lsdb *, u_char,
        struct prefix_ipv4 *);
extern void ospf_schedule_lsa_flood_area (struct ospf_area *, struct ospf_lsa *);
extern void ospf_schedule_lsa_flush_area (struct ospf_area *, struct ospf_lsa *);

extern void ospf_refresher_register_lsa (struct ospf *, struct ospf_lsa *);
extern void ospf_refresher_unregister_lsa (struct ospf *, struct ospf_lsa *);
extern int ospf_lsa_refresh_walker (struct thread *);

extern void ospf_lsa_maxage_delete (struct ospf *, struct ospf_lsa *);

extern void ospf_discard_from_db (struct ospf *, struct ospf_lsdb *, struct ospf_lsa*);
extern int is_prefix_default (struct prefix_ipv4 *);

extern int metric_type (struct ospf *, u_char);
extern int metric_value (struct ospf *, u_char);

extern struct in_addr ospf_get_nssa_ip (struct ospf_area *);
extern int ospf_translated_nssa_compare (struct ospf_lsa *, struct ospf_lsa *);
extern struct ospf_lsa *ospf_translated_nssa_refresh (struct ospf *, struct ospf_lsa *,
        struct ospf_lsa *);
extern struct ospf_lsa *ospf_translated_nssa_originate (struct ospf *, struct ospf_lsa *);

#endif /* _ZEBRA_OSPF_LSA_H */
