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

#include "vector.h"
#include "number.h"
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void vector_t::print()
{
    unsigned int i;

    for (i = 0; i < m_num; i++) {
        m_val[i].print();
        wifi_util_dbg_print(WIFI_LIB, "\t\t");
    }
    wifi_util_dbg_print(WIFI_LIB, "\n");
}

void vector_t::get_highest_val_index(unsigned int &index)
{
    unsigned int i;
    double base_val = 0;

    for (i = 0; i < m_num; i++) {
        if (m_val[i].m_re > base_val) {
            base_val = m_val[i].m_re;
            index = i;
        }
    }
}

void vector_t::push_back(number_t val)
{
    m_val[m_num] = val;
    m_num++;
}

vector_t vector_t::derivative(void)
{
    vector_t d;
    int n = m_num - 1;
    number_t num_val(0.0, 0.0);

    for (int i = 0; i < n; ++i) {
        num_val.m_re = (double)(n - i);
        d.push_back(m_val[i] * num_val);
    }

    return d;
}

vector_t vector_t::operator+(vector_t v)
{
    vector_t out;
    unsigned int i;

    out.m_num = m_num;
    for (i = 0; i < m_num; i++) {
        out.m_val[i] = m_val[i] + v.m_val[i];
    }

    return out;
}

vector_t vector_t::operator-(vector_t v)
{
    vector_t out;
    unsigned int i;

    out.m_num = m_num;
    for (i = 0; i < m_num; i++) {
        out.m_val[i] = m_val[i] - v.m_val[i];
    }

    return out;
}

vector_t vector_t::operator/(number_t n)
{
    vector_t out;
    unsigned int i;

    out.m_num = m_num;
    for (i = 0; i < m_num; i++) {
        out.m_val[i] = m_val[i] / n;
    }

    return out;
}

number_t vector_t::stddev()
{
    unsigned int i;
    number_t m(0, 0), temp(0, 0), n(0, 0), r[2], out(0, 0);

    m = mean();

    for (i = 0; i < m_num; i++) {
        n = m_val[i] - m;
        temp = temp + n.power(2);
    }

    temp = temp / number_t(m_num, 0);

    temp.sqroot(r);
    out = r[0];

    return out;
}

number_t vector_t::mean()
{
    unsigned int i;
    number_t out(0, 0);

    if (m_num == 0) {
        return out;
    }

    for (i = 0; i < m_num; i++) {
        out.m_re += m_val[i].m_re;
        out.m_im += m_val[i].m_im;
    }

    return out / number_t(m_num, 0);
}

void vector_t::sort()
{
    vector_t out(0);
    unsigned int i, j;
    number_t n;

    if (m_num == 0) {
        return;
    }

    for (i = 0; i < m_num - 1; i++) {
        for (j = i + 1; j < m_num; j++) {
            if (m_val[i].mod_z() < m_val[j].mod_z()) {
                // interchange the numbers
                n = m_val[i];
                m_val[i] = m_val[j];
                m_val[j] = n;
            }
        }
    }
}

vector_t vector_t::invert()
{
    unsigned int i;
    vector_t out;

    out.m_num = m_num;

    for (i = 0; i < m_num; i++) {
        out.m_val[m_num - i - 1] = m_val[i];
    }

    return out;
}

vector_t::vector_t(unsigned int num, number_t n[])
{
    unsigned int i;

    m_num = num;

    for (i = 0; i < num; i++) {
        m_val[i] = n[i];
    }
}

vector_t::vector_t(unsigned int num)
{
    unsigned int i;

    m_num = num;

    for (i = 0; i < MAX_LEN; i++) {
        m_val[i].m_re = 0;
        m_val[i].m_im = 0;
    }
}

vector_t::vector_t()
{
    m_num = 0;
}

vector_t::~vector_t()
{
}
