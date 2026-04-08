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

#include "sequence.h"
#include "number.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sequence_t::print()
{
    unsigned int i;

    if (m_sampling_window == 0) {
        m_last[0].print();
        wifi_util_dbg_print(WIFI_LIB, "\n");
        return;
    }

    for (i = 0; i < m_total_samples; i++) {
        m_last[i].print();
        wifi_util_dbg_print(WIFI_LIB, "\t");
    }

    wifi_util_dbg_print(WIFI_LIB, "\n");
}

sequence_t sequence_t::operator+(number_t n)
{
    number_t temp;
    int i = 0;

    if (m_sampling_window != 0) {
        m_last[m_seq_index] = n;
        m_seq_index = (m_seq_index + 1) % m_sampling_window;
    } else {
        m_last[i] = n;
    }
    if (m_total_samples < m_sampling_window) {
        m_total_samples++;
    }

    if (m_variance.m_re != 0.0) {
        m_gaussian.m_re = expf((-0.5) * (pow(n.m_re - m_mean.m_re, 2) / (pow(m_variance.m_re, 2)))) /
            (sqrt(2 * PI * m_variance.m_re));
    }
    if (m_variance.m_im != 0.0) {
        m_gaussian.m_im = expf((-0.5) * (pow(n.m_im - m_mean.m_im, 2) / (pow(m_variance.m_im, 2)))) /
            (sqrt(2 * PI * m_variance.m_im));
    }

    if (m_sampling_window == 0) {
        m_kurtosis = (n - m_mean).power(4) / m_variance.power(2);
        m_mean = (m_mean * m_total_samples + m_last[0]) / (m_total_samples + 1);
        m_variance = (m_variance * m_total_samples + (n - m_mean).power(2)) / (m_total_samples + 1);
    } else if (m_total_samples > 0) {
        m_mean = number_t(0, 0);
        for (i = 0; i < m_total_samples; i++) {
            m_mean = m_mean + m_last[i];
        }
        m_mean = m_mean / m_total_samples;

        m_variance = number_t(0, 0);
        for (i = 0; i < m_total_samples; i++) {
            m_variance = m_variance + (m_last[i] - m_mean).power(2);
        }

        m_variance = m_variance / m_total_samples;

        m_kurtosis = number_t(0, 0);
        for (i = 0; i < m_total_samples; i++) {
            m_kurtosis = m_kurtosis + (m_last[i] - m_mean).power(4);
        }

        m_kurtosis = m_kurtosis / m_total_samples;

        temp = number_t(0, 0);
        for (i = 0; i < m_total_samples; i++) {
            temp = temp + (m_last[i] - m_mean).power(2);
        }

        temp = temp / m_total_samples;

        if (temp != number_t(0, 0)) {
            m_kurtosis = m_kurtosis / temp.power(2);
            m_mfilter = (m_kurtosis.m_re > 4) ? number_t(m_kurtosis.m_re - 4, 0) : number_t(0, 0);
        }

    } else {
        m_mean = m_last[0];
    }

    if (m_sampling_window == 0) {

        if (m_max.m_re <= n.m_re) {
            m_max = n;
        }

        if (m_min.m_re >= n.m_re) {
            m_min = n;
        }
    } else {
        m_max = m_last[0];
        m_min = m_last[0];
        for (i = 1; i < m_total_samples; i++) {
            if (m_max.m_re <= m_last[i].m_re) {
                m_max = m_last[i];
            }

            if (m_min.m_re >= m_last[i].m_re) {
                m_min = m_last[i];
            }
        }
    }

    return *this;
}

void sequence_t::reset()
{
    unsigned int i;

    m_mean = { 0, 0 };
    m_variance = { 0, 0 };
    m_max = { 0, 0 };
    m_min = { 0, 0 };

    for (i = 0; i < MAX_SAMPLING_WINDOW; i++) {
        m_last[i] = number_t(0, 0);
    }
    m_kurtosis = { 0, 0 };
    m_mfilter = { 0, 0 };

    m_total_samples = 0;
    m_seq_index = 0;
}

sequence_t::sequence_t(int sampling_window)
{
    unsigned int i;

    m_mean = { 0, 0 };
    m_variance = { 0, 0 };
    m_max = { 0, 0 };
    m_min = { 0, 0 };

    for (i = 0; i < MAX_SAMPLING_WINDOW; i++) {
        m_last[i] = number_t(0, 0);
    }
    m_kurtosis = { 0, 0 };
    m_mfilter = { 0, 0 };

    m_total_samples = 0;
    m_seq_index = 0;

    if (sampling_window < 0) {
        m_sampling_window = 0;
    } else if (sampling_window > MAX_SAMPLING_WINDOW) {
        m_sampling_window = MAX_SAMPLING_WINDOW;
    } else {
        m_sampling_window = sampling_window;
    }
}

sequence_t::sequence_t()
{
    unsigned int i;

    m_mean = { 0, 0 };
    m_variance = { 0, 0 };
    m_max = { 0, 0 };
    m_min = { 0, 0 };

    for (i = 0; i < MAX_SAMPLING_WINDOW; i++) {
        m_last[i] = number_t(0, 0);
    }
    m_kurtosis = { 0, 0 };
    m_mfilter = { 0, 0 };

    m_total_samples = 0;
    m_seq_index = 0;
    m_sampling_window = 0;
}

sequence_t::~sequence_t()
{
}
