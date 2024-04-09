#include <assert.h>
#include <inttypes.h>
#include <stdint.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <stddef.h>
#include <math.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_minmax.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_bbr.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_util.h"
#include "lsquic_malo.h"
#include "lsquic_crand.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_vegas.h"
#define INITIAL_CWND 0
#define TCP_MSS 1460
#define SSTHRESH_INITIAL_VALUE 10000*1460
#define FAST_CONVERGENCE        1
#include "lsquic_logger.h"
static void
vegas_reset (struct lsquic_vegas *vegas)
{
    memset(vegas, 0, offsetof(struct lsquic_vegas, ve_conn));
    vegas->cwnd          = 32 * TCP_MSS;
    vegas->BaseRTT       =  UINT64_MAX;
    vegas->cnt_RTT       = 0;
    vegas->alpha         = 2;
    vegas->beta          = 4;
    vegas->gamma         = 1;
    vegas->right_boundary_of_this_RTT = 0;
    //vegas->CurrentRTT  = 0;?
    //vegas->cu_last_max_cwnd = 32 * TCP_MSS;
    //vegas->cu_tcp_cwnd      = 32 * TCP_MSS;
    /*  还有一些参数不知应在此处初始化还是在INIT函数里初始化  */
}
// uint64_t min(uint64_t a, uint64_t b)
// {
//     if(a > b)
//         return b;
//     return a;
// }

static void lsquic_vegas_init(void* cong_ctl, const struct lsquic_conn_public *conn_pub, 
                                                        enum quic_ft_bit UNUSED_retx_frames)                                             
{
    struct lsquic_vegas *const vegas = cong_ctl;    
    vegas_reset(vegas);
   // vegas->CurrentRTT = 0;
    vegas->ssthresh = SSTHRESH_INITIAL_VALUE;
    vegas->ve_rtt_stats = &conn_pub->lconn;
#ifndef NDEBUG
    const char *s;
    s = getenv("LSQUIC_VEGAS_SAMPLING_RATE");
    if (s)
        vegas->ve_sampling_rate = atoi(s);
    else
#endif
        vegas->ve_sampling_rate = 100000;
    LSQ_DEBUG("%s(vegas, $conn)", __func__);
    LSQ_INFO("Vegas Initialized");
    FILE *f= fopen("/home/sy/test/test.txt","a");
    fprintf(f, "Vegas Initialized\n");
    fclose(f); 
}

static void lsquic_vegas_reinit(void* cong_ctl)
{
    struct lsquic_vegas *const vegas = cong_ctl;    
    vegas_reset(vegas);
    //vegas->CurrentRTT = 0;
    vegas->ssthresh = SSTHRESH_INITIAL_VALUE;
    LSQ_DEBUG("Vegas Reinitialized");
    FILE *f= fopen("/home/sy/test/test.txt","a");
    fprintf(f, "Vegas RE Initialized\n");
    fclose(f);
}

#define LOG_CWND(c) do {                                                    \
    if (LSQ_LOG_ENABLED(LSQ_LOG_INFO)) {                                    \
        lsquic_time_t now = lsquic_time_now();                              \
        now -= now % (c)->ve_sampling_rate;                                 \
        if (now > (c)->ve_last_logged) {                                    \
            LSQ_INFO("CWND: %lu", (c)->cu_cwnd);                            \
            (c)->ve_last_logged = now;                                      \
        }                                                                   \
    }                                                                       \
} while (0)


static void
lsquic_vegas_was_quiet (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    LSQ_DEBUG("%s(vegas, %"PRIu64")", __func__, now);
   // vegas->cu_epoch_start = 0;
}



void lsquic_vegas_sent(void *cong_ctl, struct lsquic_packet_out *packet_out, size_t b_un, int app_limited)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    vegas->last_packno = packet_out->po_packno;
} 

static int
in_slow_start (void *cong_ctl)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    return vegas->cwnd < vegas->ssthresh;
}

static void
lsquic_reno_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                  unsigned n_bytes, lsquic_time_t now_time, int app_limited)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    if (in_slow_start(vegas))
    {
        vegas->cwnd *= 2;
    }
    
}

static void
lsquic_vegas_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                  unsigned n_bytes, lsquic_time_t now_time, int app_limited)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    lsquic_time_t rtt,min_rtt;
    //uint64_t ack_p_num = 0; // 这一个ack ack的数据包数量
    rtt = now_time - packet_out->po_sent; // 这个ACK对应的RTT 
    LSQ_DEBUG("%s(vegas, %"PRIu64", %"PRIu64", %d, %u)", __func__, now_time, rtt,
                                                        app_limited, n_bytes);
    vegas->Min_RTT_last_RTT = min(rtt,vegas->Min_RTT_last_RTT);// 更新过去一轮的最小RTT值 
    vegas->cnt_RTT ++; //
    vegas->BaseRTT = vegas->ve_rtt_stats->min_rtt; //更新整个连接的最小RTT值
    //vegas->BaseRTT = min(rtt,vegas->BaseRTT);
    
    //ack_p_num = packet_out->po_ack2ed - vegas->last_acked_p_no;
    vegas->last_acked_p_no = packet_out->po_ack2ed;
    lsquic_packno_t this_ack_to_packno = packet_out->po_ack2ed; // ack回复的packet编号
    //FILE *f= fopen("/home/sy/test/test.txt","a");

    //fprintf(f, "Vegas this ackpack is to ack pack %llu\n",  this_ack_to_packno);
    //fprintf(f, "Vegas newest packno sent is %llu\n",  vegas->last_packno);
    //fprintf(f, "此编号空间 %llu\n", lsquic_packet_out_pns(packet_out));
    //fprintf(f, "Vegas  Min_RTT_last_RTT is %llu\n",  vegas->Min_RTT_last_RTT);
    //fprintf(f, "Vegas  this rtt is %llu\n",  rtt);
    //fprintf(f, "Vegas this pack_no is %llu\n",  packet_out->po_packno);
    //fprintf(f, "Vegas this pack_no is to ack %llu\n",  packet_out->po_ack2ed);\
    //fclose(f);
    if (this_ack_to_packno >= vegas->right_boundary_of_this_RTT) //应该进行检测了，进行Vegas算法参数更新
    {
        vegas->right_boundary_of_this_RTT = vegas->last_packno + 1;

        if (vegas->cnt_RTT <= 2) { /* RTT样本太少，不能排除delayed ACK*/
                 /* We don't have enough RTT samples to do the Vegas calculation, 
                  * so we'll behave like Reno.
                  */
                  //进行Reno
                  if (in_slow_start(vegas))
                  {
                    //    vegas->cwnd += ack_p_num*TCP_MSS;
                    vegas->cwnd += packet_out->po_data_sz;
                  }
                  else
                  {
                        vegas->cwnd += TCP_MSS;
                  }

              }
        else{
                uint64_t diff,rtt,Expected_cwnd;
                rtt = vegas->Min_RTT_last_RTT;
                Expected_cwnd = (uint64_t)vegas->cwnd * vegas->BaseRTT;
                Expected_cwnd =  Expected_cwnd/rtt;
                diff = vegas->cwnd * (rtt-vegas->BaseRTT) / vegas->BaseRTT;

                if (diff > vegas->gamma && in_slow_start(vegas)){
                    vegas->cwnd = min(vegas->cwnd, (uint64_t) Expected_cwnd + 1);
                    vegas->ssthresh = min(vegas->ssthresh, vegas->cwnd);
                }
                else if (in_slow_start(vegas)){
                    // 进行 slow_start
                       // vegas->cwnd +=  ack_p_num*TCP_MSS;
                    vegas->cwnd += packet_out->po_data_sz;
                }
                else{
                        if(diff > vegas->beta){
                            vegas->cwnd -= TCP_MSS;
                            vegas->ssthresh = min(vegas->ssthresh, vegas->cwnd);
                        }
                        else if (diff < vegas->alpha)
                        {
                            vegas->cwnd += TCP_MSS;
                        }
                        else{
                            // do nothing;
                        }
                }
                if (vegas->cwnd < 2*TCP_MSS)
                {
                    vegas->cwnd = 2*TCP_MSS;
                }
               /*else if (tp->snd_cwnd > tp->snd_cwnd_clamp) // ??????
				tp->snd_cwnd = tp->snd_cwnd_clamp;

			tp->snd_ssthresh = tcp_current_ssthresh(sk);*/
                
            
        }

        vegas->cnt_RTT = 0;
        vegas->Min_RTT_last_RTT = UINT64_MAX;
    }
    else if (in_slow_start(vegas)) // 处于两个测量RTT之间 
    {
            //进行slow——start
            //vegas->cwnd += ack_p_num*TCP_MSS;
            vegas->cwnd += packet_out->po_data_sz;
    }  
    else{
            vegas->cwnd += TCP_MSS; //CA状态
    }  
        // FILE *fp= fopen("/home/sy/test/test.txt","a");
        // fprintf(fp, "Vegas cwnd changed new cwnd %llu\n", vegas->cwnd);
        // fclose(fp);                                                 
}

static uint64_t
lsquic_vegas_get_cwnd(void *cong_ctl)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    return vegas->cwnd;
}


static void
lsquic_vegas_loss (void *cong_ctl)
{
    /*丢包事件
    1. 拥塞窗口减小
    2. 慢启动阈值调整 
    */
    struct lsquic_vegas *const vegas = cong_ctl;
    LSQ_DEBUG("%s(vegas)", __func__);
    vegas->cwnd -= TCP_MSS;
    vegas->ssthresh = vegas->cwnd / 2;
    LSQ_INFO("loss detected, , cwnd: %lu",vegas->cwnd);
    FILE *f= fopen("/home/sy/test/test.txt","a");
    fprintf(f, "Vegas LOSS?????????\n");
    fclose(f);
}
static void
lsquic_vegas_cleanup (void *cong_ctl)
{
}
static void
lsquic_vegas_timeout (void *cong_ctl)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    unsigned long cwnd;

    cwnd = vegas->cwnd;
    LSQ_DEBUG("%s(vegas)", __func__);
    vegas_reset(vegas);
    vegas->ssthresh = cwnd / 2;
    //vegas->cu_tcp_cwnd = 2 * TCP_MSS;
    vegas->cwnd = 2 * TCP_MSS;
    vegas->cnt_RTT = 0;
    LSQ_INFO("timeout, cwnd: %lu", vegas->cwnd);
    FILE *f= fopen("/home/sy/test/test.txt","a");
    fprintf(f, "Vegas Time out!!!!!!!!!!\n");
    fclose(f);
   // LOG_CWND(vegas);
}

static uint64_t
lsquic_vegas_pacing_rate (void *cong_ctl, int in_recovery)
{
    struct lsquic_vegas *const vegas = cong_ctl;
    uint64_t bandwidth, pacing_rate;
    lsquic_time_t srtt;

    srtt = lsquic_rtt_stats_get_srtt(vegas->ve_rtt_stats);
    if (srtt == 0)
        srtt = 50000;
    bandwidth = vegas->cwnd * 1000000 / srtt;
    if (in_slow_start(vegas))
        pacing_rate = bandwidth * 2;
    else if (in_recovery)
        pacing_rate = bandwidth;
    else
        pacing_rate = bandwidth + bandwidth / 4;

    return pacing_rate;
}

const struct cong_ctl_if lsquic_cong_vegas_if =
{
    .cci_ack           = lsquic_vegas_ack,
    .cci_cleanup       = lsquic_vegas_cleanup,
    .cci_get_cwnd      = lsquic_vegas_get_cwnd,
    .cci_init          = lsquic_vegas_init,
    .cci_pacing_rate   = lsquic_vegas_pacing_rate,
    .cci_loss          = lsquic_vegas_loss,
    .cci_reinit        = lsquic_vegas_reinit,
    .cci_sent          = lsquic_vegas_sent,
    .cci_timeout       = lsquic_vegas_timeout,
    .cci_was_quiet     = lsquic_vegas_was_quiet,
};


