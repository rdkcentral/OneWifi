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

#include "number.h"
#include "matrix.h"
#include "vector.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void number_t::print()
{
    if ((is_zero(m_re, 4) == true) && (is_zero(m_im, 4) == false)) {
        wifi_util_dbg_print(WIFI_LIB, "%0.4fi", m_im);
    } else if ((is_zero(m_re, 4) == false) && (is_zero(m_im, 4) == true)) {
        wifi_util_dbg_print(WIFI_LIB, "%0.4f", m_re);
    } else if ((is_zero(m_re, 4) == false) && (is_zero(m_im, 4) == false)) {
        if (m_im < 0) {
            wifi_util_dbg_print(WIFI_LIB, "%0.4f%0.4fi", m_re, m_im);
        } else {
            wifi_util_dbg_print(WIFI_LIB, "%0.4f+%0.4fi", m_re, m_im);
        }
    } else {
        wifi_util_dbg_print(WIFI_LIB, "0.0000");
    }
}

bool number_t::is_zero(double x, int n)
{
    if (n == 0) {
        return abs((int)x) == 0;
    }

    return fabs(x) < pow(10, -n);
}

number_t number_t::absolute()
{
    number_t out;

    out.m_re = fabs(m_re);
    out.m_im = fabs(m_im);

    return out;
}

bool number_t::is_zero(int n)
{
    return (is_zero(m_re, n)) && (is_zero(m_im, n));
}

bool number_t::operator==(number_t n)
{
    return (m_re == n.m_re) && (m_im == n.m_im);
}

number_t number_t::operator*(number_t n)
{
    return number_t(m_re * n.m_re - m_im * n.m_im, m_re * n.m_im + m_im * n.m_re);
}

number_t number_t::operator/(number_t n)
{
    return number_t((m_re * n.m_re + m_im * n.m_im) / (pow(n.m_re, 2) + pow(n.m_im, 2)),
        (m_im * n.m_re - m_re * n.m_im) / (pow(n.m_re, 2) + pow(n.m_im, 2)));
}

number_t number_t::operator+(number_t n)
{
    return number_t(m_re + n.m_re, m_im + n.m_im);
}

number_t number_t::operator-(number_t n)
{
    return number_t(m_re - n.m_re, m_im - n.m_im);
    ;
}

number_t number_t::operator-(void)
{
    number_t out;
    out.m_re = -m_re;
    out.m_im = -m_im;
    return out;
}

matrix_t number_t::operator*(matrix_t m)
{
    matrix_t out;
    unsigned int i, j;

    out = m;
    for (i = 0; i < m.m_rows; i++) {
        for (j = 0; j < m.m_cols; j++) {
            out.m_val[i][j] = (*this) * m.m_val[i][j];
        }
    }

    return out;
}

number_t number_t::exponential()
{
    return number_t(exp(m_re), 0) * number_t(cos(m_im), sin(m_im));
}

number_t number_t::power(unsigned int n)
{
    number_t num = *this;
    unsigned int i;

    if (n == 0) {
        return number_t(0, 0);
    } else if (n == 1) {
        return *this;
    }

    for (i = 1; i < n; i++) {
        num = num * (*this);
    }

    return num;
}

double number_t::mod_z()
{
    return fabs(sqrt(pow(m_re, 2) + pow(m_im, 2)));
}

double number_t::abs_val() const
{
    return sqrt(m_re * m_re + m_im * m_im);
}

void number_t::sqroot(number_t n[])
{
    double d;

    d = mod_z();

    n[0].m_re = sqrt((d + m_re) / 2);
    n[1].m_re = sqrt((d + m_re) / 2);

    if (m_im >= 0) {
        n[0].m_im = 0.0 - sqrt((d - m_re) / 2);
        n[1].m_im = sqrt((d - m_re) / 2);
    } else {
        n[0].m_im = sqrt((d - m_re) / 2);
        n[1].m_im = 0.0 - sqrt((d - m_re) / 2);
    }
}

number_t number_t::sqrt_val(void)
{
    double a = m_re;
    double b = m_im;
    double r = std::sqrt(a * a + b * b);

    double real = std::sqrt((r + a) / 2.0);
    double imag = (b >= 0) ? std::sqrt((r - a) / 2.0) : -std::sqrt((r - a) / 2.0);

    return number_t(real, imag);
}

number_t::number_t(double r, double i)
{
    m_re = r;
    m_im = i;
}

number_t::number_t(char *str)
{
    bool neg = false;
    large_expr_t e;
    char *tmp, *cmplx;

    m_im = 0;
    m_re = 0;

    if ((str != NULL) && (str[0] != 0)) {

        memset(e, 0, sizeof(expr_t));
        strncpy(e, str, strlen(str) + 1);
        tmp = e;

        if (*tmp == '-') {
            neg = true;
            tmp++;
        } else if (*tmp == '+') {
            tmp++;
        }

        if ((cmplx = strchr(tmp, 'i')) != NULL) {
            *cmplx = 0;
            m_im = (neg == true) ? -((*tmp == 0) ? 1 : atof(tmp)) : ((*tmp == 0) ? 1 : atof(tmp));
        } else {
            m_re = (neg == true) ? -((*tmp == 0) ? 1 : atof(tmp)) : ((*tmp == 0) ? 1 : atof(tmp));
        }
    }
}

number_t::number_t()
{
    m_re = 0;
    m_im = 0;
}

number_t::~number_t()
{
}
