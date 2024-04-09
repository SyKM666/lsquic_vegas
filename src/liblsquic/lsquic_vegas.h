/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cubic.h -- CUBIC congestion control protocol.
 */

#ifndef LSQUIC_VEGAS_H
#define LSQUIC_VEGAS_H 1

#include "lsquic_shared_support.h"

struct lsquic_conn;


struct lsquic_vegas {

    uint64_t BaseRTT;
    uint64_t cwnd;
    lsquic_time_t Min_RTT_last_RTT; // 上一轮测得的最小的RTT，用于更新BaseRTT； 
    uint64_t ssthresh; 
    lsquic_packno_t last_packno;
    lsquic_packno_t right_boundary_of_this_RTT;
    uint64_t num_packet_sent;
    lsquic_packno_t last_acked_p_no;
    int alpha; // 
    int beta;  // 
    int gamma;
    uint64_t    cnt_RTT;


    
    const struct lsquic_conn
                   *ve_conn;            /* Used for logging */
    const struct lsquic_rtt_stats
                   *ve_rtt_stats;
    unsigned        ve_sampling_rate; 
    lsquic_time_t   cu_last_logged;
};

#define DEFAULT_VEGAS_FLAGS (CU_TCP_FRIENDLY)

#define TCP_MSS 1460

LSQUIC_EXTERN const struct cong_ctl_if lsquic_cong_vegas_if;

#endif
