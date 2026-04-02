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

#ifndef MVNPDF_H
#define MVNPDF_H

#include "base.h"
#include "number.h"
#include "vector.h"
#include "matrix.h"

#define MAX_VARIATES    5
#define MAX_WINDOW    5

class mvnpdf_t {
    unsigned int m_variates;
    unsigned int m_num;
    matrix_t m_cov;
    vector_t m_mean;
    vector_t m_variance;
    vector_t m_data[MAX_WINDOW];
    
public:
    void print();
    vector_t get_mean() { return m_mean; }
    matrix_t get_covariance() { return m_cov; }
    matrix_t get_zinverse() { return m_cov.inverse(); }
    double mvnpdf(vector_t v);
    vector_t mean();
    vector_t variance(vector_t v);
    vector_t stddev();
    
public:
    mvnpdf_t(unsigned int n);
	~mvnpdf_t();
};

#endif
