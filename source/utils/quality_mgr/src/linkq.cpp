/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linkq.h"
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "wifi_util.h"

extern "C" void qmgr_invoke_score(const char *str, double score);
linkq_params_t linkq_t::m_linkq_params[MAX_LINKQ_PARAMS] = {{"DOWNLINK_SNR", true}, {"DOWNLINK_PER", false}, {"DOWNLINK_PHY", true},{"UPLINK_SNR", true}, {"UPLINK_PER", false}, {"UPLINK_PHY", true}};
mac_addr_str_t linkq_t::ignite_station_mac = "";
linkq_params_t linkq_t::m_score_params[] = {
    // ---------- Aggregate metrics ----------
    { "SNR",   true  },
    { "PER",   false },
    { "PHY",   true  },

    // ---------- Downlink metrics ----------
    { "DOWNLINK_SNR",   true  },
    { "DOWNLINK_PER",   false },
    { "DOWNLINK_PHY",   true  },

    // ---------- Uplink metrics ----------
    { "UPLINK_SNR",   true  },
    { "UPLINK_PER",   false },
    { "UPLINK_PHY",   true  },
    
    { "DOWNLINK_Score", true  },
    { "UPLINK_Score", true  },
    { "Score", true  }
};

// Return pointer to the static array
linkq_params_t* linkq_t::get_score_params() {
    return m_score_params;
}

quality_flags_t linkq_t::m_quality_flag = { true, true, true, false, false, false, false,false };

static inline double apply_recovery(double norm,int remaining,
                                    int total)
{
    double factor = 1.0;
    if (total <= 0 || remaining <= 0)
        return norm;
    wifi_util_info_print(WIFI_APPS,"%s:%d,remaining=%d total=%d\n",__func__,__LINE__,remaining,total);

    double progress = (double)(total - remaining) / (double)total;

    if (progress < 0.0) progress = 0.0;
    if (progress > 1.0) progress = 1.0;
    
    factor = 1.0 - exp(-4.0 * progress);
    wifi_util_info_print(WIFI_APPS,"%s:%d factor=%f\n",__func__,__LINE__,factor);
    return norm * factor;

}

vector_t linkq_t::run_algorithm(linkq_data_t data,
                                bool &alarm,
                                bool update_alarm)
{
    vector_t v;
    alarm = false;

    double norm[6] = {0.0};
    double x, y;
    bool is_ignite_station = false;
    memset(&m_data_sample,0,sizeof(sample_t));
    const char *mac = get_mac_addr();
    if(strncmp(ignite_station_mac, mac, sizeof(ignite_station_mac)) == 0)
    {
        wifi_util_info_print(WIFI_APPS,"%s:%d mac=%s and ignite_station_mac=%s\n",
	__func__,__LINE__,mac,ignite_station_mac);
        is_ignite_station = true;
       
    }
    // -------------------------------------------------
    // Fixed vector layout (frontend decides visibility)
    // -------------------------------------------------
    wifi_util_dbg_print(WIFI_APPS,"%s:%d downlink=:%d:%d:%d uplink =%d:%d:%d agg=%d\n",__func__,__LINE__,
        m_quality_flag.downlink_snr,m_quality_flag.downlink_per,m_quality_flag.downlink_phy,m_quality_flag.uplink_snr,
        m_quality_flag.uplink_per,m_quality_flag.uplink_phy,m_quality_flag.aggregate);
    
    v.m_num = 12;
    for (int i = 0; i < v.m_num; i++)
        v.m_val[i].m_re = 0.0;

    // -------------------------------------------------
    // Normalize enabled inputs
    // -------------------------------------------------
    for (int i = 0; i < 6; i++) {
        bool enabled = false;

        switch (i) {
            case 0: enabled = m_quality_flag.downlink_snr; break;
            case 1: enabled = m_quality_flag.downlink_per; break;
            case 2: enabled = m_quality_flag.downlink_phy; break;
            case 3: enabled = m_quality_flag.uplink_snr;   break;
            case 4: enabled = m_quality_flag.uplink_per;   break;
            case 5: enabled = m_quality_flag.uplink_phy;   break;
        }

        if (!enabled) continue;

        m_seq[i] = m_seq[i] + number_t((float)data[i], 0);
        y = m_seq[i].get_max().m_re - m_seq[i].get_min().m_re;

        if (y > 0.0) {
            x = data[i] - m_seq[i].get_min().m_re;
            norm[i] = x / y;
            if (norm[i] > 1.0) norm[i] = 1.0;
        } else {
            norm[i] = 0.0;
        }
        // Smooth uplink PHY (i == 5) using last 5 samples
        if (i == 5) {
            m_uplink_phy_history.push_back(norm[i]);
            if (m_uplink_phy_history.size() > UPLINK_PHY_WINDOW)
                m_uplink_phy_history.pop_front();

            double sum = 0.0;
            for (size_t j = 0; j < m_uplink_phy_history.size(); j++)
                sum += m_uplink_phy_history[j];

            if (!m_uplink_phy_history.empty())
                norm[i] = sum / m_uplink_phy_history.size();
        }

        if (m_quality_flag.int_reconn && m_recovery_remaining > 0) {
            norm[i] = apply_recovery(norm[i],m_recovery_remaining,m_recovery_total);
        }
    }

    // -------------------------------------------------
    // Store raw normalized values
    // -------------------------------------------------
    v.m_val[3].m_re  = m_quality_flag.downlink_snr ? norm[0] : 0.0;
    v.m_val[4].m_re  = m_quality_flag.downlink_per ? norm[1] : 0.0;
    v.m_val[5].m_re  = m_quality_flag.downlink_phy ? norm[2] : 0.0;

    v.m_val[6].m_re  = m_quality_flag.uplink_snr   ? norm[3] : 0.0;
    v.m_val[7].m_re  = m_quality_flag.uplink_per   ? norm[4] : 0.0;
    v.m_val[8].m_re = m_quality_flag.uplink_phy   ? norm[5] : 0.0;

    // -------------------------------------------------
    // Aggregate SNR / PER / PHY
    // -------------------------------------------------
    int cnt;
    if (m_quality_flag.aggregate) {
        wifi_util_dbg_print(WIFI_APPS,"In Aggregte %s:%d\n",__func__,__LINE__);
        cnt = 0;
        if (m_quality_flag.downlink_snr) { v.m_val[0].m_re += norm[0]; cnt++; }
        if (m_quality_flag.uplink_snr)   { v.m_val[0].m_re += norm[3]; cnt++; }
        if (cnt) v.m_val[0].m_re /= cnt;

        cnt = 0;
        if (m_quality_flag.downlink_per) { v.m_val[1].m_re += norm[1]; cnt++; }
        if (m_quality_flag.uplink_per)   { v.m_val[1].m_re += norm[4]; cnt++; }
        if (cnt) v.m_val[1].m_re /= cnt;

        cnt = 0;
        if (m_quality_flag.downlink_phy) { v.m_val[2].m_re += norm[2]; cnt++; }
        if (m_quality_flag.uplink_phy)   { v.m_val[2].m_re += norm[5]; cnt++; }
        if (cnt) v.m_val[2].m_re /= cnt;
	m_data_sample.snr   = v.m_val[0].m_re;
        m_data_sample.per   = v.m_val[1].m_re;
        m_data_sample.phy   = v.m_val[2].m_re;
         
    } else {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Not In Aggregte\n",__func__,__LINE__);
        v.m_val[0].m_re = 0;
        v.m_val[1].m_re = 0;
        v.m_val[2].m_re = 0;
        v.m_val[11].m_re = 0;

    }
    // -------------------------------------------------
    // DOWNLINK Score
    // -------------------------------------------------
    cnt = 0;
    if (m_quality_flag.downlink_snr) {
        v.m_val[9].m_re += m_linkq_params[0].booster
            ? pow(v.m_val[3].m_re, 2)
            : -pow(v.m_val[3].m_re, 2);
        cnt++;
	m_data_sample.snr   = v.m_val[3].m_re;
    }
    if (m_quality_flag.downlink_per) {
        v.m_val[9].m_re += m_linkq_params[1].booster
            ? pow(v.m_val[4].m_re, 2)
            : -pow(v.m_val[4].m_re, 2);
        cnt++;
        m_data_sample.per   = v.m_val[4].m_re;
    }
    if (m_quality_flag.downlink_phy) {
        v.m_val[9].m_re += m_linkq_params[2].booster
            ? pow(v.m_val[5].m_re, 2)
            : -pow(v.m_val[5].m_re, 2);
        cnt++;
        m_data_sample.phy   = v.m_val[5].m_re;
    }
    if (v.m_val[9].m_re < 0.0 || cnt == 0)
        v.m_val[9].m_re = 0.0;
    else
        v.m_val[9].m_re = sqrt(v.m_val[9].m_re / cnt);
    wifi_util_dbg_print(WIFI_APPS,"%s:%dDownlink score = %f\n",__func__,__LINE__,v.m_val[9].m_re);

    // -------------------------------------------------
    // UPLINK Score
    // -------------------------------------------------
    cnt = 0;
    if (m_quality_flag.uplink_snr) {
        v.m_val[10].m_re += m_linkq_params[3].booster
            ? pow(v.m_val[6].m_re, 2)
            : -pow(v.m_val[6].m_re, 2);
        cnt++;
        m_data_sample.phy   = v.m_val[6].m_re;
    }
    if (m_quality_flag.uplink_per) {
        v.m_val[10].m_re += m_linkq_params[4].booster
            ? pow(v.m_val[7].m_re, 2)
            : -pow(v.m_val[7].m_re, 2);
        cnt++;
        m_data_sample.per   = v.m_val[7].m_re;
    }
    if (m_quality_flag.uplink_phy) {
        v.m_val[10].m_re += m_linkq_params[5].booster
            ? pow(v.m_val[8].m_re, 2)
            : -pow(v.m_val[8].m_re, 2);
        cnt++;
        m_data_sample.phy   = v.m_val[8].m_re;
    }
    if (v.m_val[10].m_re < 0.0 || cnt == 0)
        v.m_val[10].m_re = 0.0;
    else
        v.m_val[10].m_re = sqrt(v.m_val[10].m_re / cnt);
    wifi_util_dbg_print(WIFI_APPS,"%s:%dUplink score = %f\n",__func__,__LINE__,v.m_val[10].m_re);

    // -------------------------------------------------
    // Aggregate Score
    // -------------------------------------------------
    cnt = 0;
    for (int i = 0; i < 3; i++) {
        if (v.m_val[i].m_re > 0.0) {
            v.m_val[11].m_re += m_linkq_params[i].booster
                ? pow(v.m_val[i].m_re, 2)
                : -pow(v.m_val[i].m_re, 2);
            cnt++;
        }
    }
    if (v.m_val[11].m_re < 0.0 || cnt == 0)
        v.m_val[11].m_re = 0.0;
    else
        v.m_val[11].m_re = sqrt(v.m_val[11].m_re / cnt);
    wifi_util_dbg_print(WIFI_APPS,"%s:%dAggregate score = %f\n",__func__,__LINE__,v.m_val[11].m_re);
    get_local_time(m_data_sample.time, sizeof(m_data_sample.time),false);
    // -------------------------------------------------
    // Alarm logic
    // -------------------------------------------------
    m_sampled++;
    wifi_util_dbg_print(WIFI_APPS,"%s:%d aggscore = %f,downlink score=%f uplinkscore=%f\n",__func__,__LINE__,v.m_val[11].m_re,v.m_val[9].m_re,v.m_val[10].m_re);
    
    if ( (m_quality_flag.aggregate)) {
        m_data_sample.score = v.m_val[11].m_re;
        if (v.m_val[11].m_re < m_threshold) {
            m_threshold_cross_counter++;
            if (is_ignite_station && qmgr_is_score_registered) {
                wifi_util_info_print(WIFI_APPS,"%s:%d score=%f Invoking the score callback for ignite\n",__func__,__LINE__,v.m_val[11].m_re);   
                qmgr_invoke_score(mac,v.m_val[11].m_re);
            }
        }
    } else if ((m_quality_flag.downlink_snr || m_quality_flag.downlink_per || m_quality_flag.downlink_phy)
        && (m_quality_flag.uplink_snr || m_quality_flag.uplink_per || m_quality_flag.uplink_phy)) {
         m_data_sample.score  = (v.m_val[9].m_re + v.m_val[10].m_re)/2;
        if(v.m_val[9].m_re < m_threshold || v.m_val[10].m_re < m_threshold) {
            m_threshold_cross_counter++;
            if (is_ignite_station && qmgr_is_score_registered) {
                wifi_util_info_print(WIFI_APPS,"%s:%d score=%f Invoking the score callback for ignite\n",__func__,__LINE__,v.m_val[9].m_re,v.m_val[10].m_re);   
                if (v.m_val[9].m_re < m_threshold)
                    qmgr_invoke_score(mac,v.m_val[9].m_re);
                else if (v.m_val[10].m_re < m_threshold)
                    qmgr_invoke_score(mac,v.m_val[10].m_re);
	    }
        }
    } else if (m_quality_flag.downlink_snr || m_quality_flag.downlink_per || m_quality_flag.downlink_phy) {
        m_data_sample.score = v.m_val[9].m_re;
        if(v.m_val[9].m_re < m_threshold)
            m_threshold_cross_counter++;
            if ( is_ignite_station && qmgr_is_score_registered) {
                wifi_util_info_print(WIFI_APPS,"%s:%d score=%f Invoking the score callback for ignite\n",__func__,__LINE__,v.m_val[9].m_re);   
                qmgr_invoke_score(mac,v.m_val[9].m_re);
	    }
    } else if (m_quality_flag.uplink_snr || m_quality_flag.uplink_per || m_quality_flag.uplink_phy) {
        m_data_sample.score = v.m_val[10].m_re;
        if(v.m_val[10].m_re < m_threshold)
            m_threshold_cross_counter++;
            if (is_ignite_station && qmgr_is_score_registered) {
                wifi_util_info_print(WIFI_APPS,"%s:%d score=%f Invoking the score callback for ignite\n",__func__,__LINE__,v.m_val[10].m_re);   
                qmgr_invoke_score(mac,v.m_val[10].m_re);
	    }
    }
    m_window_samples.push_back(m_data_sample);
    
    if (update_alarm) {
        alarm = (m_threshold_cross_counter >= ceil(0.8 * m_sampled));
        wifi_util_dbg_print(WIFI_APPS,"Pramod in update alarm = %d counter=%d and threshold=%f\n",alarm,m_threshold_cross_counter,m_threshold);
        m_alarm = alarm;
        m_sampled = 0;
        m_threshold_cross_counter = 0;
    }
    return v;
}
vector_t linkq_t::run_test(bool &alarm, bool update_alarm, bool &rapid_disconnect)
{
    vector_t v;
    linkq_data_t data;
    pthread_mutex_lock(&m_vec_lock);
    alarm = false;
    rapid_disconnect =  false;

    // If disconnected, count missed samples
    if (m_disconnected) {
        m_disconnect_samples++;
        pthread_mutex_unlock(&m_vec_lock);
        wifi_util_info_print(WIFI_APPS,"In disconnected\n");
        rapid_disconnect =  true;
        alarm = false;
        return vector_t(0);   // no data while disconnected
    }

    // Reconnect detected: start recovery
    if (!m_disconnected && m_disconnect_samples > 0 && m_recovery_remaining == 0) {
        m_recovery_total     = m_disconnect_samples;
        m_recovery_remaining = m_disconnect_samples;
        wifi_util_info_print(WIFI_APPS,
            "Reconnect detected: recovery samples=%d\n",
            m_recovery_total);
    }

    if (m_stats_arr.empty() || m_current >= m_recs) {
        pthread_mutex_unlock(&m_vec_lock);
        wifi_util_error_print(
            WIFI_APPS,
            "%s:%d: Failed to load record \n",
            __func__, __LINE__
        );
        return vector_t(0);
    }
    const stats_arg_t stat = m_stats_arr[0];   // COPY, not reference
    pthread_mutex_unlock(&m_vec_lock);

    for (unsigned int i = 0; i < MAX_LINKQ_PARAMS; i++) {
        if (strcmp(m_linkq_params[i].name, "DOWNLINK_SNR") == 0) {
            data[i] = stat.dev.cli_SNR;
        } else if (strcmp(m_linkq_params[i].name, "DOWNLINK_PER") == 0) {
            data[i] = m_window_downlink_per; 
        } else if (strcmp(m_linkq_params[i].name, "DOWNLINK_PHY") == 0) {
            data[i] = stat.dev.cli_LastDataDownlinkRate;
        } else if (strcmp(m_linkq_params[i].name, "UPLINK_SNR") == 0) {
            data[i] = stat.dev.cli_SNR;
        } else if (strcmp(m_linkq_params[i].name, "UPLINK_PER") == 0) {
            data[i] = m_window_uplink_per; 
        } else if (strcmp(m_linkq_params[i].name, "UPLINK_PHY") == 0) {
            data[i] = stat.dev.cli_LastDataUplinkRate;
        }
    }
    v = run_algorithm(data, alarm, update_alarm);

    // One recovery step per successful sample
    if (m_recovery_remaining > 0) {
        m_recovery_remaining--;
        if (m_recovery_remaining == 0) {
            m_disconnect_samples = 0;
        }
    }

    m_current++;
    return v;
}
void linkq_t::update_window_per()
{
    pthread_mutex_lock(&m_deque_lock);
    if (m_per_window.size() < 2) {
        m_window_downlink_per = 0.0;
        m_window_uplink_per = 0.0;
        pthread_mutex_unlock(&m_deque_lock);
        return;
    }

    window_per_param_t first;
    window_per_param_t last;

    first = m_per_window.front();
    last  = m_per_window.back();

    unsigned int  sent_delta = 0,  recv_delta = 0, err_sent_delta = 0, err_recv_delta = 0;

    if (last.pkt_sent >= first.pkt_sent)
        sent_delta = last.pkt_sent - first.pkt_sent;

    if (last.pkt_recv >= first.pkt_recv)
        recv_delta = last.pkt_recv - first.pkt_recv;

    if (last.err_sent >= first.err_sent)
        err_sent_delta = last.err_sent - first.err_sent;

    if (last.err_recv >= first.err_recv)
        err_recv_delta = last.err_recv - first.err_recv;
    pthread_mutex_unlock(&m_deque_lock);
    wifi_util_dbg_print(WIFI_APPS,"DOWNLINK_PER last.pkt_sent=%d first.pkt_sent=%d sent_delta=%d err_sent_delta=%d\n",last.pkt_sent,first.pkt_sent,sent_delta,err_sent_delta);
    if (sent_delta > 0)
        m_window_downlink_per =
            ((double)err_sent_delta / (double)(sent_delta + err_sent_delta)) * 100.0;
    else
        m_window_downlink_per = 0.0;

    if (recv_delta > 0)
        m_window_uplink_per =
            ((double)err_recv_delta / (double)(recv_delta + err_recv_delta)) * 100.0;
    else
        m_window_uplink_per = 0.0;
    wifi_util_info_print(WIFI_APPS,"%s:%d DOWNLINK_PER m_window_downlink_per=%f and m_window_uplink_per=%f\n"
        ,__func__,__LINE__,m_window_downlink_per,m_window_uplink_per);
    return;

}

size_t linkq_t::get_window_samples(sample_t **out_samples)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__);
    if (!out_samples || m_window_samples.empty())
        return 0;
    if (m_window_samples.empty())
        return 0;
	
    for (size_t i = 0; i < m_window_samples.size(); i++) {
        const sample_t &s = m_window_samples[i];

        wifi_util_dbg_print(
            WIFI_CTRL,
            "[get_window_samples] [%zu] time=%s score=%.2f snr=%.2f per=%.2f phy=%.2f\n",
            i,
            s.time,
            s.score,
            s.snr,
            s.per,
            s.phy
        );
    }
    size_t count = m_window_samples.size();

    sample_t *buf = (sample_t *)calloc(count, sizeof(sample_t));
    if (!buf)
        return 0;

    memcpy(buf, m_window_samples.data(), count * sizeof(sample_t));

    *out_samples = buf;
    wifi_util_dbg_print(WIFI_CTRL," %s:%d \n",__func__,__LINE__); 
    return count;
}

void linkq_t::clear_window_samples()
{
    m_window_samples.clear();
}

char *linkq_t::get_local_time(char *str, unsigned int len, bool hourformat)
{
    struct timeval tv;
    struct tm *local_time;

    gettimeofday(&tv, NULL); // Get current time into tv
    local_time = localtime(&tv.tv_sec);
    if(hourformat)
        strftime(str, len, "%M:%S", local_time);
    else
        strftime(str, len, "%Y-%m-%d %H:%M:%S", local_time);

    return str;
}

int linkq_t::reinit(server_arg_t *arg )
{
    wifi_util_info_print(WIFI_APPS," %s:%d\n", __func__,__LINE__); 
    m_threshold = arg->threshold;
    m_reporting_mult = arg->reporting;
    wifi_util_info_print(WIFI_APPS," %s:%d m_reporting_mult =%d m_threshold=%f\n", __func__,__LINE__,m_reporting_mult,m_threshold); 
    return 0;
}
int linkq_t::init(double threshold, unsigned int reporting_mult, stats_arg_t *stats )//, const char *test_file_name)
{
    char *buff, tmp[MAX_LINE_SIZE];
    unsigned int i;
    
    m_threshold = threshold;
    m_reporting_mult = reporting_mult;
    mac_address_t sta_mac;
    pthread_mutex_lock(&m_vec_lock);
    if (m_stats_arr.empty()) {
        m_stats_arr.push_back(*stats);
    } else {
        m_stats_arr[0] = *stats;   // overwrite atomically
    }
    pthread_mutex_unlock(&m_vec_lock);
    m_recs = 1;
    m_current = 0;
    window_per_param_t sample = {};

    sample.pkt_sent = m_stats_arr[0].dev.cli_PacketsSent;
    sample.pkt_recv = m_stats_arr[0].dev.cli_PacketsReceived;
    sample.err_sent = m_stats_arr[0].dev.cli_RetransCount;
    sample.err_recv = m_stats_arr[0].dev.cli_RxRetries;
    wifi_util_dbg_print(WIFI_APPS,"DOWNLINK_PER sample.pkt_sent=%dsample.err_sent=%d\n",sample.pkt_sent,sample.err_sent);
    // Push latest sample

    pthread_mutex_lock(&m_deque_lock);

    // Maintain fixed window size
    if (m_per_window.size() > PER_WINDOW_SIZE) {
        m_per_window.pop_front();
    }
    m_per_window.push_back(sample);
    pthread_mutex_unlock(&m_deque_lock);
    update_window_per();
    if (m_disconnected) {
        wifi_util_info_print(WIFI_APPS,"reconnected the station again\n");
	m_disconnected = false;

    }
    
    for (i = 0; i < MAX_LINKQ_PARAMS; i++) {
        if (strncmp(m_linkq_params[i].name, "DOWNLINK_SNR", strlen("DOWNLINK_SNR")) == 0) {
            m_seq[i].set_max(number_t(70, 0));
            m_seq[i].set_min(number_t(0, 0));
        } else if (strncmp(m_linkq_params[i].name, "DOWNLINK_PER", strlen("DOWNLINK_PER")) == 0) {
            m_seq[i].set_max(number_t(25, 0));
            m_seq[i].set_min(number_t(0, 0));
        } else if (strncmp(m_linkq_params[i].name, "DOWNLINK_PHY", strlen("DOWNLINK_PHY")) == 0) {
            m_seq[i].set_max(number_t( m_stats_arr[0].dev.cli_MaxDownlinkRate, 0));
            m_seq[i].set_min(number_t(0, 0));
        } else if (strncmp(m_linkq_params[i].name, "UPLINK_SNR", strlen("UPLINK_SNR")) == 0) {
            m_seq[i].set_max(number_t(70, 0));
            m_seq[i].set_min(number_t(0, 0));
        } else if (strncmp(m_linkq_params[i].name, "UPLINK_PER", strlen("UPLINK_PER")) == 0) {
            m_seq[i].set_max(number_t( 25, 0));
            m_seq[i].set_min(number_t(0, 0));
        } else if (strncmp(m_linkq_params[i].name, "UPLINK_PHY", strlen("UPLINKK_PHY")) == 0) {
            m_seq[i].set_max(number_t( m_stats_arr[0].dev.cli_MaxUplinkRate, 0));
            m_seq[i].set_min(number_t(0, 0));
        }
    }
    wifi_util_dbg_print(WIFI_APPS," %s:%d  m_recs =%d m_current=%d m_max_phy=%d\n",__func__,__LINE__,m_recs,m_current,m_stats_arr[0].dev.cli_MaxDownlinkRate); 
    return 0;
}

int linkq_t::rapid_disconnect(stats_arg_t *stats)
{
    wifi_util_error_print(WIFI_APPS,"Pramod %s:%d\n",__func__,__LINE__);
    if(!m_disconnected) {
        m_disconnected = true;
        m_disconnect_samples++;
        m_recovery_remaining = 0;
        m_recovery_total = 0;
        wifi_util_error_print(WIFI_APPS,"Pramod %s:%d m_disconnected =%d,m_disconnect_samples=%d\n",__func__,__LINE__,m_disconnected,m_disconnect_samples);
    }
    return 0;
}
int linkq_t::set_quality_params(quality_flags_t *flag)
{
    wifi_util_error_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    m_quality_flag = *flag;
    wifi_util_error_print(WIFI_APPS,"Pramod %s:%d downlink=:%d:%d:%d uplink =%d:%d:%d aggregate=%d int_reconnect=%d\n",
         __func__,__LINE__,m_quality_flag.downlink_snr,m_quality_flag.downlink_per,m_quality_flag.downlink_phy,m_quality_flag.uplink_snr,
    m_quality_flag.uplink_per,m_quality_flag.uplink_phy,m_quality_flag.aggregate,m_quality_flag.int_reconn);
    return 0;
}

void linkq_t::register_station_mac(const char* str)
{
    wifi_util_error_print(WIFI_APPS,"%s:%d str=%s\n",__func__,__LINE__,str);
    if (str) {
        snprintf(ignite_station_mac, sizeof(ignite_station_mac), "%s", str);
    }
    return;
}
void linkq_t::unregister_station_mac(const char* str)
{
    wifi_util_error_print(WIFI_APPS,"%s:%d str=%s\n",__func__,__LINE__,str);
    if (!str)
        return;
    if(strncmp(ignite_station_mac, str, sizeof(ignite_station_mac)) == 0) 
    {
        ignite_station_mac[0] = '\0';
    }
    return;
}


linkq_t::linkq_t(mac_addr_str_t mac,unsigned int vap_index)
{
    strncpy(m_mac, mac, sizeof(m_mac) - 1);
    m_mac[sizeof(m_mac) - 1] = '\0';
    m_vapindex = vap_index;
    pthread_mutex_init(&m_vec_lock, NULL);
    pthread_mutex_init(&m_deque_lock, NULL);
    wifi_util_error_print(WIFI_CTRL," %s:%d m_vapindex =%d\n",__func__,__LINE__,m_vapindex); 
    m_recs = 0;
    m_alarm = false;
    m_current = 0;
    m_disconnected =  false;
    m_disconnect_samples = 0;
    m_recovery_remaining = 0;
    m_recovery_total = 0;
    m_per_window.clear(); 
    m_threshold_cross_counter = 0;
    m_sampled = 0;
}

linkq_t::~linkq_t()
{
     m_stats_arr.clear();

}

