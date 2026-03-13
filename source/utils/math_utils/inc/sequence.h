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

#ifndef SEQUENCE_H
#define SEQUENCE_H

#include "base.h"
#include "number.h"

class sequence_t {
public:
   	number_t	m_mean;
	number_t	m_variance;
    number_t    m_last;
    number_t    m_max;
    number_t    m_min;
	unsigned int	m_samples;
 
public:
    
    sequence_t operator +(number_t n);
    
    void set_max(number_t n) { m_max = n; }
    void set_min(number_t n) { m_min = n; }
    
    number_t get_max() { return m_max; }
    number_t get_min() { return m_min; }
    number_t get_mean() { return m_mean; }
    number_t get_variance() { return m_variance; }
    
    sequence_t();
	~sequence_t();
};

#endif
