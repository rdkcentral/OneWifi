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

#include "statistics.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void statistics_t::print()
{
}

number_t statistics_t::mean()
{
    return m_data.mean();
}

number_t statistics_t::stddev()
{
    return m_data.stddev();
}

number_t statistics_t::pdf(number_t x)
{
    number_t exponent, coeff, mean, std;
    vector_t v(0);

    mean = m_data.mean();
    std = m_data.stddev();

    coeff = number_t(1.0, 0) / (std * number_t(sqrt(2 * PI), 0));
    exponent = number_t(-0.5, 0) * ((x - mean) / std).power(2);
    return coeff * exponent.exponential();
}

vector_t statistics_t::pdf()
{
    number_t exponent, coeff, mean, std;
    vector_t v(0);
    unsigned int i;

    mean = m_data.mean();
    std = m_data.stddev();

    coeff = number_t(1.0, 0) / (std * number_t(sqrt(2 * PI), 0));

    for (i = 0; i < m_data.m_num; i++) {
        exponent = number_t(-0.5, 0) * ((m_data.m_val[i] - mean) / std).power(2);
        v.m_val[i] = coeff * exponent.exponential();
        v.m_num++;
    }

    return v;
}

statistics_t::statistics_t(vector_t &v)
{
    m_data = v;
}

statistics_t::~statistics_t()
{
}
