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
#include <math.h>
#include "number.h"
#include "sequence.h"

sequence_t sequence_t::operator +(number_t n)
{
    sequence_t seq;
    number_t num[2];
    m_last = n;
    
    m_mean = (m_mean * m_samples + m_last)/(m_samples + 1);
    (((m_variance.power(2) * m_samples) + (m_last - m_mean).power(2))/(m_samples + 1)).sqroot(num);
    m_variance = num[0];
   #if 0 
    if (m_max.m_re <= n.m_re) {
        m_max = n;
    }
    
    if (m_min.m_re >= n.m_re) {
        m_min = n;
    }
    #endif
    //m_variance.print();
    //printf("\n");
    
    m_samples++;
    
    return *this;
}

sequence_t::sequence_t()
{
	m_mean = {0, 0};	
	m_variance = {0, 0};
    m_max = {0, 0};
    m_min = {0, 0};
    m_last = {0, 0};
    m_samples = 0;
}

sequence_t::~sequence_t()
{
    
}

