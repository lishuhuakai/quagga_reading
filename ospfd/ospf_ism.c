/*
 * OSPF version 2  Interface State Machine
 * OSPFv2 接口状态机
 *   From RFC2328 [OSPF Version 2]
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

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_snmp.h"

/* elect DR and BDR. Refer to RFC2319 section 9.4
 * DR以及BDR的选举
 */
static struct ospf_neighbor *
ospf_dr_election_sub (struct list *routers)
{
    struct listnode *node;
    struct ospf_neighbor *nbr, *max = NULL;

    /* Choose highest router priority.
       In case of tie, choose highest Router ID.
     * 选择具有最高router优先级的邻居,如果优先级一致,那么选择具有更高router id的邻居
     */
    for (ALL_LIST_ELEMENTS_RO (routers, node, nbr))
    {
        if (max == NULL)
            max = nbr;
        else
        {
            if (max->priority < nbr->priority)
                max = nbr;
            else if (max->priority == nbr->priority)
                if (IPV4_ADDR_CMP (&max->router_id, &nbr->router_id) < 0)
                    max = nbr;
        }
    }

    return max;
}

static struct ospf_neighbor *
ospf_elect_dr (struct ospf_interface *oi, struct list *el_list)
{
    struct list *dr_list;
    struct listnode *node;
    struct ospf_neighbor *nbr, *dr = NULL, *bdr = NULL;

    dr_list = list_new ();

    /* Add neighbors to the list. */
    for (ALL_LIST_ELEMENTS_RO (el_list, node, nbr))
    {
        /* neighbor declared to be DR.
         * 将所有声明自己为DR的邻居加入dr_list
         */
        if (NBR_IS_DR (nbr))
            listnode_add (dr_list, nbr);

        /* Preserve neighbor BDR. */
        if (IPV4_ADDR_SAME (&BDR (oi), &nbr->address.u.prefix4))
            bdr = nbr;
    }

    /* Elect Designated Router. */
    if (listcount (dr_list) > 0)
        dr = ospf_dr_election_sub (dr_list);
    else
        dr = bdr; /* 如果没有邻居宣称自己为DR,那么BDR成为DR */

    /* Set DR to interface. */
    if (dr)
        DR (oi) = dr->address.u.prefix4;
    else
        DR (oi).s_addr = 0;

    list_delete (dr_list);

    return dr;
}

/*
 * 选举BDR, el_list中保存着待选邻居列表
 */
static struct ospf_neighbor *
ospf_elect_bdr (struct ospf_interface *oi, struct list *el_list)
{
    struct list *bdr_list, *no_dr_list;
    struct listnode *node;
    struct ospf_neighbor *nbr, *bdr = NULL;

    bdr_list = list_new ();
    no_dr_list = list_new ();

    /* Add neighbors to the list. */
    for (ALL_LIST_ELEMENTS_RO (el_list, node, nbr))
    {
        /* neighbor declared to be DR. */
        if (NBR_IS_DR (nbr))
            continue;

        /* neighbor declared to be BDR.
         * 将声明自己为BDR的邻居加入列表
         */
        if (NBR_IS_BDR (nbr))
            listnode_add (bdr_list, nbr);
        /* 将那些没有宣告自己为DR的邻居放入no_dr_list */
        listnode_add (no_dr_list, nbr);
    }

    /* Elect Backup Designated Router. */
    if (listcount (bdr_list) > 0)
        bdr = ospf_dr_election_sub (bdr_list);
    else /* 如果没有邻居宣告自己为bdr,那么具有最高优先级的邻居作为bdr */
        bdr = ospf_dr_election_sub (no_dr_list);

    /* Set BDR to interface. */
    if (bdr)
        BDR (oi) = bdr->address.u.prefix4;
    else
        BDR (oi).s_addr = 0;

    list_delete (bdr_list);
    list_delete (no_dr_list);

    return bdr;
}

/*
 * 判断自己是否成为了DR/BDR/DROther
 */
static int
ospf_ism_state (struct ospf_interface *oi)
{
    if (IPV4_ADDR_SAME (&DR (oi), &oi->address->u.prefix4))
        return ISM_DR;
    else if (IPV4_ADDR_SAME (&BDR (oi), &oi->address->u.prefix4))
        return ISM_Backup;
    else
        return ISM_DROther;
}

/*
 * 获得可以作为候选者router
 */
static void
ospf_dr_eligible_routers (struct route_table *nbrs, struct list *el_list)
{
    struct route_node *rn;
    struct ospf_neighbor *nbr;

    for (rn = route_top (nbrs); rn; rn = route_next (rn))
        if ((nbr = rn->info) != NULL)
            /* Ignore 0.0.0.0 node 首先要有router id  */
            if (nbr->router_id.s_addr != 0)
                /* Is neighbor eligible? 而且优先级要大于0 */
                if (nbr->priority > 0)
                    /* Is neighbor upper 2-Way? */
                    if (nbr->state >= NSM_TwoWay)
                        listnode_add (el_list, nbr);
}

/* Generate AdjOK? NSM event. */
static void
ospf_dr_change (struct ospf *ospf, struct route_table *nbrs)
{
    struct route_node *rn;
    struct ospf_neighbor *nbr;

    for (rn = route_top (nbrs); rn; rn = route_next (rn))
        if ((nbr = rn->info) != NULL)
            /* Ignore 0.0.0.0 node*/
            if (nbr->router_id.s_addr != 0)
                /* Is neighbor upper 2-Way? */
                if (nbr->state >= NSM_TwoWay)
                    /* Ignore myself. */
                    if (!IPV4_ADDR_SAME (&nbr->router_id, &ospf->router_id))
                        OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_AdjOK);
}

/*
 * DR选举
 */
static int
ospf_dr_election (struct ospf_interface *oi)
{
    struct in_addr old_dr, old_bdr;
    int old_state, new_state;
    struct list *el_list;

    /* backup current values. */
    old_dr = DR (oi);
    old_bdr = BDR (oi);
    old_state = oi->state;

    el_list = list_new (); /* 选举列表 */

    /* List eligible routers. */
    ospf_dr_eligible_routers (oi->nbrs, el_list);

    /* First election of DR and BDR.
     * 第一轮选举DR以及BDR
     */
    ospf_elect_bdr (oi, el_list);
    ospf_elect_dr (oi, el_list);

    new_state = ospf_ism_state (oi);

    zlog_debug ("DR-Election[1st]: Backup %s", inet_ntoa (BDR (oi)));
    zlog_debug ("DR-Election[1st]: DR     %s", inet_ntoa (DR (oi)));
    /* 如果此路由器是新选取的DR或者BDR,或者它不再是DR或者BDR,需要再次进行选举 */
    if (new_state != old_state &&
        !(new_state == ISM_DROther && old_state < ISM_DROther))
    {
        ospf_elect_bdr (oi, el_list);
        ospf_elect_dr (oi, el_list);
        /* 新状态 */
        new_state = ospf_ism_state (oi);

        zlog_debug ("DR-Election[2nd]: Backup %s", inet_ntoa (BDR (oi)));
        zlog_debug ("DR-Election[2nd]: DR     %s", inet_ntoa (DR (oi)));
    }

    list_delete (el_list);

    /* if DR or BDR changes, cause AdjOK? neighbor event.
     * 如果dr或者bdr发生改变
     */
    if (!IPV4_ADDR_SAME (&old_dr, &DR (oi)) ||
        !IPV4_ADDR_SAME (&old_bdr, &BDR (oi)))
        ospf_dr_change (oi->ospf, oi->nbrs);

    return new_state;
}


/*
 * 定时发送hello包
 */
int
ospf_hello_timer (struct thread *thread)
{
    struct ospf_interface *oi;

    oi = THREAD_ARG (thread);
    oi->t_hello = NULL;

    if (IS_DEBUG_OSPF (ism, ISM_TIMERS))
        zlog (NULL, LOG_DEBUG, "ISM[%s]: Timer (Hello timer expire)",
              IF_NAME (oi));

    /* Sending hello packet. */
    ospf_hello_send (oi);

    /* Hello timer set. */
    OSPF_HELLO_TIMER_ON (oi);

    return 0;
}

static int
ospf_wait_timer (struct thread *thread)
{
    struct ospf_interface *oi;

    oi = THREAD_ARG (thread);
    oi->t_wait = NULL;

    if (IS_DEBUG_OSPF (ism, ISM_TIMERS))
        zlog (NULL, LOG_DEBUG, "ISM[%s]: Timer (Wait timer expire)",
              IF_NAME (oi));

    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_WaitTimer);

    return 0;
}

/* Hook function called after ospf ISM event is occured. And vty's
   network command invoke this function after making interface
   structure.
 *
 */
static void
ism_timer_set (struct ospf_interface *oi)
{
    switch (oi->state)
    {
        case ISM_Down:
            /* First entry point of ospf interface state machine. In this state
            interface parameters must be set to initial values, and timers are
             reset also.
            * ISM的第一个状态,这个状态中,所有定时器都将设置为初始的值
            */
            OSPF_ISM_TIMER_OFF (oi->t_hello);
            OSPF_ISM_TIMER_OFF (oi->t_wait);
            OSPF_ISM_TIMER_OFF (oi->t_ls_ack);
            break;
        case ISM_Loopback:
            /* In this state, the interface may be looped back and will be
            unavailable for regular data traffic. */
            OSPF_ISM_TIMER_OFF (oi->t_hello);
            OSPF_ISM_TIMER_OFF (oi->t_wait);
            OSPF_ISM_TIMER_OFF (oi->t_ls_ack);
            break;
        case ISM_Waiting: /* 等待状态,路由器将决定DR和BDR */
            /* The router is trying to determine the identity of DRouter and
            BDRouter. The router begin to receive and send Hello Packets. */
            /* send first hello immediately */
            OSPF_ISM_TIMER_MSEC_ON (oi->t_hello, ospf_hello_timer, 1);
            OSPF_ISM_TIMER_ON (oi->t_wait, ospf_wait_timer,
                               OSPF_IF_PARAM (oi, v_wait));
            OSPF_ISM_TIMER_OFF (oi->t_ls_ack);
            break;
        case ISM_PointToPoint: /* 点到点状态 */
            /* The interface connects to a physical Point-to-point network or
            virtual link. The router attempts to form an adjacency with
             neighboring router. Hello packets are also sent. */
            /* send first hello immediately */
            OSPF_ISM_TIMER_MSEC_ON (oi->t_hello, ospf_hello_timer, 1);
            OSPF_ISM_TIMER_OFF (oi->t_wait);
            OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);
            break;
        case ISM_DROther:
            /* The network type of the interface is broadcast or NBMA network,
            and the router itself is neither Designated Router nor
             Backup Designated Router. */
            OSPF_HELLO_TIMER_ON (oi);
            OSPF_ISM_TIMER_OFF (oi->t_wait);
            OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);
            break;
        case ISM_Backup:
            /* The network type of the interface is broadcast os NBMA network,
            and the router is Backup Designated Router. */
            OSPF_HELLO_TIMER_ON (oi);
            OSPF_ISM_TIMER_OFF (oi->t_wait);
            OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);
            break;
        case ISM_DR:
            /* The network type of the interface is broadcast or NBMA network,
            and the router is Designated Router. */
            OSPF_HELLO_TIMER_ON (oi);
            OSPF_ISM_TIMER_OFF (oi->t_wait);
            OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);
            break;
    }
}

/* IE1
 * 端口起来这个事件会触发的状态更新
 */
static int
ism_interface_up (struct ospf_interface *oi)
{
    int next_state = 0;

    /* if network type is point-to-point, Point-to-MultiPoint or virtual link,
       the state transitions to Point-to-Point. */
    if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
        oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
        oi->type == OSPF_IFTYPE_VIRTUALLINK)
        next_state = ISM_PointToPoint;
    /* Else if the router is not eligible to DR, the state transitions to
       DROther. */
    else if (PRIORITY (oi) == 0) /* router is eligible? */
        next_state = ISM_DROther;
    else
        /* Otherwise, the state transitions to Waiting. */
        next_state = ISM_Waiting;

    if (oi->type == OSPF_IFTYPE_NBMA)
        ospf_nbr_nbma_if_update (oi->ospf, oi);

    /*  ospf_ism_event (t); */
    return next_state;
}

static int
ism_loop_ind (struct ospf_interface *oi)
{
    int ret = 0;

    /* call ism_interface_down. */
    /* ret = ism_interface_down (oi); */

    return ret;
}

/* Interface down event handler.
 * 端口down掉的处理函数
 */
static int
ism_interface_down (struct ospf_interface *oi)
{
    ospf_if_cleanup (oi);
    return 0;
}


static int
ism_backup_seen (struct ospf_interface *oi)
{
    return ospf_dr_election (oi);
}

static int
ism_wait_timer (struct ospf_interface *oi)
{
    return ospf_dr_election (oi);
}

static int
ism_neighbor_change (struct ospf_interface *oi)
{
    return ospf_dr_election (oi);
}

static int
ism_ignore (struct ospf_interface *oi)
{
    if (IS_DEBUG_OSPF (ism, ISM_EVENTS))
        zlog (NULL, LOG_DEBUG, "ISM[%s]: ism_ignore called", IF_NAME (oi));

    return 0;
}

/* Interface State Machine */
/* 接口状态机 */
struct
{
    int (*func) (struct ospf_interface *);
    int next_state;
} ISM [OSPF_ISM_STATE_MAX][OSPF_ISM_EVENT_MAX] =
{
    {
        /* DependUpon: dummy state. */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_DependUpon },    /* InterfaceUp    */
        { ism_ignore,          ISM_DependUpon },    /* WaitTimer      */
        { ism_ignore,          ISM_DependUpon },    /* BackupSeen     */
        { ism_ignore,          ISM_DependUpon },    /* NeighborChange */
        { ism_ignore,          ISM_DependUpon },    /* LoopInd        */
        { ism_ignore,          ISM_DependUpon },    /* UnloopInd      */
        { ism_ignore,          ISM_DependUpon },    /* InterfaceDown  */
    },
    {
        /* Down:*/
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_interface_up,    ISM_DependUpon },    /* InterfaceUp    */
        { ism_ignore,          ISM_Down },          /* WaitTimer      */
        { ism_ignore,          ISM_Down },          /* BackupSeen     */
        { ism_ignore,          ISM_Down },          /* NeighborChange */
        { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_Down },          /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
    {
        /* Loopback: */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_Loopback },      /* InterfaceUp    */
        { ism_ignore,          ISM_Loopback },      /* WaitTimer      */
        { ism_ignore,          ISM_Loopback },      /* BackupSeen     */
        { ism_ignore,          ISM_Loopback },      /* NeighborChange */
        { ism_ignore,          ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_Down },          /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
    {
        /* Waiting: */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_Waiting },       /* InterfaceUp    */
        { ism_wait_timer,      ISM_DependUpon },    /* WaitTimer      */
        { ism_backup_seen,     ISM_DependUpon },    /* BackupSeen     */
        { ism_ignore,          ISM_Waiting },       /* NeighborChange */
        { ism_loop_ind,    ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_Waiting },       /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
    {
        /* Point-to-Point: */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_PointToPoint },  /* InterfaceUp    */
        { ism_ignore,          ISM_PointToPoint },  /* WaitTimer      */
        { ism_ignore,          ISM_PointToPoint },  /* BackupSeen     */
        { ism_ignore,          ISM_PointToPoint },  /* NeighborChange */
        { ism_loop_ind,    ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_PointToPoint },  /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
    {
        /* DROther: */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_DROther },       /* InterfaceUp    */
        { ism_ignore,          ISM_DROther },       /* WaitTimer      */
        { ism_ignore,          ISM_DROther },       /* BackupSeen     */
        { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
        { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_DROther },       /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
    {
        /* Backup: */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_Backup },        /* InterfaceUp    */
        { ism_ignore,          ISM_Backup },        /* WaitTimer      */
        { ism_ignore,          ISM_Backup },        /* BackupSeen     */
        { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
        { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_Backup },        /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
    {
        /* DR: */
        { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
        { ism_ignore,          ISM_DR },            /* InterfaceUp    */
        { ism_ignore,          ISM_DR },            /* WaitTimer      */
        { ism_ignore,          ISM_DR },            /* BackupSeen     */
        { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
        { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
        { ism_ignore,          ISM_DR },            /* UnloopInd      */
        { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
    },
};

static const char *ospf_ism_event_str[] =
{
    "NoEvent",
    "InterfaceUp",
    "WaitTimer",
    "BackupSeen",
    "NeighborChange",
    "LoopInd",
    "UnLoopInd",
    "InterfaceDown",
};

/* 改变端口的状态 */
static void
ism_change_state (struct ospf_interface *oi, int state)
{
    int old_state;
    struct ospf_lsa *lsa;

    /* Logging change of state. */
    if (IS_DEBUG_OSPF (ism, ISM_STATUS))
        zlog (NULL, LOG_DEBUG, "ISM[%s]: State change %s -> %s", IF_NAME (oi),
              LOOKUP (ospf_ism_state_msg, oi->state),
              LOOKUP (ospf_ism_state_msg, state));

    old_state = oi->state;
    oi->state = state;
    oi->state_change++;

#ifdef HAVE_SNMP
    /* Terminal state or regression */
    if ((state == ISM_DR) || (state == ISM_Backup) || (state == ISM_DROther) ||
        (state == ISM_PointToPoint) || (state < old_state))
    {
        /* ospfVirtIfStateChange */
        if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
            ospfTrapVirtIfStateChange (oi);
        /* ospfIfStateChange */
        else
            ospfTrapIfStateChange (oi);
    }
#endif

    /* Set multicast memberships appropriately for new state. */
    ospf_if_set_multicast(oi);

    if (old_state == ISM_Down || state == ISM_Down)
        ospf_check_abr_status (oi->ospf);

    /* Originate router-LSA. */
    if (state == ISM_Down)
    {
        if (oi->area->act_ints > 0)
            oi->area->act_ints--;
    }
    else if (old_state == ISM_Down)
        oi->area->act_ints++; /* 端口起来 */

    /* schedule router-LSA originate. */
    ospf_router_lsa_update_area (oi->area);

    /* Originate network-LSA. */
    /* 路由器变成了DR */
    if (old_state != ISM_DR && state == ISM_DR)
        ospf_network_lsa_update (oi);
    /* 从DR变成了非DR */
    else if (old_state == ISM_DR && state != ISM_DR)
    {
        /* Free self originated network LSA. */
        lsa = oi->network_lsa_self;
        if (lsa)
            ospf_lsa_flush_area (lsa, oi->area);

        ospf_lsa_unlock (&oi->network_lsa_self);
        oi->network_lsa_self = NULL;
    }

    ospf_opaque_ism_change (oi, old_state);

    /* Check area border status.  */
    ospf_check_abr_status (oi->ospf);
}

/* Execute ISM event process.
 * 执行状态机,或者说调度状态机
 */
int
ospf_ism_event (struct thread *thread)
{
    int event;
    int next_state;
    struct ospf_interface *oi;

    oi = THREAD_ARG (thread);
    event = THREAD_VAL (thread);

    /* Call function. */
    /* 根据当前状态(oi->state),遭遇的事件(event),获取下一步应该进入的状态 */
    next_state = (*(ISM [oi->state][event].func))(oi);

    if (! next_state) /* 如果函数没有返回状态,那么使用之前的状态 */
        next_state = ISM [oi->state][event].next_state;

    if (IS_DEBUG_OSPF (ism, ISM_EVENTS))
        zlog (NULL, LOG_DEBUG, "ISM[%s]: %s (%s)", IF_NAME (oi),
              LOOKUP (ospf_ism_state_msg, oi->state),
              ospf_ism_event_str[event]);

    /* If state is changed. */
    if (next_state != oi->state)
        ism_change_state (oi, next_state);

    /* Make sure timer is set. */
    ism_timer_set (oi);

    return 0;
}

