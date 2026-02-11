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
#include <assert.h>
#include "mvnpdf.h"


void mvnpdf_t::print()
{

}

vector_t mvnpdf_t::mean()
{
    unsigned int i;
    vector_t v;
    
    v.m_num = m_variates;
    for (i = 0; i < m_variates; i++) {
        v.m_val[i] = m_data[i].mean();
    }
    
    return v;
    
}

vector_t mvnpdf_t::variance(vector_t v)
{
    vector_t new_variance = {0};
    
    return m_variance;
}

vector_t mvnpdf_t::stddev()
{
    unsigned int i;
    vector_t v;
    
    v.m_num = m_variates;
    for (i = 0; i < m_variates; i++) {
        v.m_val[i] = m_data[i].stddev();
    }
    
    return v;
}

double mvnpdf_t::mvnpdf(vector_t v)
{
    matrix_t a, b, c, e;
    vector_t new_mean, new_variance;
    number_t det;
    
    if (v.m_num != m_variates) {
        printf("%s:%d: Invalid vector\n", __func__, __LINE__);
        return -1;
    }
    
    if (m_num == 0) {
        m_mean = v;
        m_num++;
        return 0;
    }
    
    new_mean = m_mean + (v - m_mean)/number_t(m_num + 1, 0);
    
    a.set_col(0, v);
    b.set_col(0, m_mean);
    c.set_col(0, new_mean);
    
    m_cov = (number_t(m_num - 1, 0)/number_t(m_num + 1, 0))*m_cov + number_t(m_num, 0)/number_t(m_num + 1, 0)*((c - b)*(c - b).transpose()) + number_t(1, 0)/number_t(m_num + 1, 0)*((a - b)*(a - b).transpose());
    
    m_num++;
    m_mean = new_mean;
    
    det = m_cov.determinant().absolute();
    if (det == number_t(0, 0)) {
        printf("%s:%d: Determinant is 0, not proceeding\n", __func__, __LINE__);
        return -1;
    }
    
    e = ((a - c).transpose()*m_cov.inverse()*(a - c));
    assert((e.m_rows == 1) || (e.m_cols == 1));
    
    return (1/(sqrt(pow(2*PI, m_variates)*det.m_re)))*exp(-0.5*e.m_val[0][0].m_re);

}

mvnpdf_t::mvnpdf_t(unsigned int n)
{
    m_cov = matrix_t(n, n);
    m_variates = n;
    m_mean = {n};
    m_num = 0;
}

mvnpdf_t::~mvnpdf_t()
{
    m_variates = 0;
    m_mean = {0};
    m_num = 0;
    m_variance = {0};
}

