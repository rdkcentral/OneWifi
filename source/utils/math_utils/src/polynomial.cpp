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

#include "polynomial.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void polynomial_t::print()
{
}

number_t polynomial_t::eval(vector_t &poly, number_t x)
{
    number_t res(0.0, 0.0);
    for (unsigned int i = 0; i < poly.m_num; ++i) {
        res = res * x + poly.m_val[i];
    }
    return res;
}

vector_t polynomial_t::deflate(vector_t &poly, number_t root)
{
    vector_t result;
    result.m_num = poly.m_num - 1;
    number_t b = poly.m_val[0];
    result.m_val[0] = b;
    for (unsigned int i = 1; i < result.m_num; ++i) {
        b = poly.m_val[i] + b * root;
        result.m_val[i] = b;
    }
    return result;
}

number_t polynomial_t::find_root(vector_t &poly, number_t x)
{
    int n = poly.m_num - 1;
    for (int iter = 0; iter < MAX_ITER; ++iter) {
        number_t P = eval(poly, x);
        if (P.abs_val() < TOL) {
            return x;
        }

        vector_t dP = poly.derivative();
        vector_t d2P = dP.derivative();

        number_t G = eval(dP, x) / P;
        number_t H = G * G - eval(d2P, x) / P;
        number_t sqrt_num = number_t(n - 1, 0.0) * (number_t(n, 0.0) * H - G * G);
        number_t sqrt_term = sqrt_num.sqrt_val();

        number_t denom1 = G + sqrt_term;
        number_t denom2 = G - sqrt_term;
        number_t denom = (denom1.abs_val() > denom2.abs_val()) ? denom1 : denom2;

        number_t a = number_t(n, 0.0) / denom;
        number_t x_new = x - a;

        if ((x_new - x).abs_val() < TOL) {
            return x_new;
        }
        x = x_new;
    }

    return x;
}

int polynomial_t::laguerre_resolve(vector_t &out)
{
    vector_t current = out;
    vector_t roots;

    while (current.m_num > 2) {
        number_t root = find_root(current, number_t(0.5, 0.5));
        roots.push_back(root);
        current = deflate(current, root);
    }

    if (current.m_num == 2) {
        number_t root = (-current.m_val[1] / current.m_val[0]);
        roots.push_back(root);
    }

    out = roots;

    return 0;
}

int polynomial_t::cauchy_bound(bounds_t *re, bounds_t *im)
{
    m_args.print();

    re->upper_limit = 10;
    re->lower_limit = -10;
    re->increments = 0.01;

    im->upper_limit = 10;
    im->lower_limit = -10;
    im->increments = 0.01;

    return 0;
}

int polynomial_t::resolve(vector_t &out)
{
    vector_t sum(0);
    double d, least_modz;
    bounds_t b_re;
    bounds_t b_im;
    unsigned int i;
    number_t sqrt_b[2];
    number_t roots[2], possible_root;
    bool found_root = false;

    cauchy_bound(&b_re, &b_im);

    if (m_args.m_num == 2) {
        out.m_val[out.m_num] = (number_t(0) - m_args.m_val[1]) / m_args.m_val[0];
        out.m_num++;
        return 0;
    }

    if (m_args.m_num == 3) {
        (m_args.m_val[1] * m_args.m_val[1] - number_t(4, 0) *
            (m_args.m_val[0] * m_args.m_val[2])).sqroot(sqrt_b);
        out.m_val[out.m_num] = (number_t(0) - m_args.m_val[1] + sqrt_b[1]) /
            (number_t(2, 0) * m_args.m_val[0]);
        out.m_num++;
        out.m_val[out.m_num] = (number_t(0) - m_args.m_val[1] - sqrt_b[1]) /
            (number_t(2, 0) * m_args.m_val[0]);
        out.m_num++;

        return 0;
    }

    sum.m_num = m_args.m_num;
    sum.m_val[0] = m_args.m_val[0];

    least_modz = pow(2, 64);

    roots[0].m_re = b_re.lower_limit;

    while (roots[0].m_re < b_re.upper_limit) {

        roots[0].m_im = b_im.lower_limit;

        while (roots[0].m_im < b_im.upper_limit) {
            for (i = 0; i < m_args.m_num - 1; i++) {
                sum.m_val[i + 1] = m_args.m_val[i + 1] + (roots[0] * sum.m_val[i]);
            }

            if (sum.m_val[i].is_zero(1)) {
                found_root = true;
                break;
            } else {
                if ((d = sum.m_val[i].mod_z()) < least_modz) {
                    least_modz = d;
                    possible_root = roots[0];
                }
            }

            roots[0].m_im += b_im.increments;
        }

        if (found_root == true) {
            break;
        }

        roots[0].m_re += b_re.increments;
    }

    if (found_root == false) {
        roots[0] = possible_root;
    }

    for (i = 0; i < m_args.m_num - 1; i++) {
        sum.m_val[i + 1] = m_args.m_val[i + 1] + (roots[0] * sum.m_val[i]);
    }

    out.m_val[out.m_num] = roots[0];
    out.m_num++;

    sum.m_num -= 1;
    polynomial_t(sum).resolve(out);

    return 0;
}

polynomial_t polynomial_t::operator*(polynomial_t p)
{
    matrix_t m1(0, 0), m2(0, 0), m3(0, 0);
    unsigned int i, j;
    vector_t out(0);

    m1.m_rows = m_args.m_num + p.m_args.m_num - 1;
    m1.m_cols = p.m_args.m_num;

    for (j = 0; j < m1.m_cols; j++) {
        for (i = j; i < m1.m_rows; i++) {
            m1.m_val[i][j] = m_args.m_val[i - j];
        }
    }

    m2.m_rows = p.m_args.m_num;
    m2.m_cols = 1;

    for (i = 0; i < m2.m_rows; i++) {
        m2.m_val[i][0] = p.m_args.m_val[i];
    }

    m3 = m1 * m2;
    out.m_num = m3.m_rows;

    for (i = 0; i < m3.m_rows; i++) {
        out.m_val[i] = m3.m_val[i][0];
    }

    return polynomial_t(out);
}

polynomial_t polynomial_t::operator/(polynomial_t p)
{
    vector_t out(0);

    return polynomial_t(out);
}

polynomial_t polynomial_t::operator+(polynomial_t p)
{
    vector_t out(0);

    return polynomial_t(out);
}

polynomial_t polynomial_t::operator-(polynomial_t p)
{
    vector_t out(0);

    return polynomial_t(out);
}

polynomial_t::polynomial_t(vector_t v)
{
    m_args = v;
}

polynomial_t::polynomial_t()
{
}

polynomial_t::~polynomial_t()
{
}
