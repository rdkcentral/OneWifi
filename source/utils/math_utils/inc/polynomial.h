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

#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include "base.h"
#include "matrix.h"
#include "number.h"
#include "vector.h"

const double TOL = 1e-12;
const int MAX_ITER = 100;

class polynomial_t {
public:
    vector_t m_args;

public:
    polynomial_t operator*(polynomial_t n);
    polynomial_t operator/(polynomial_t n);
    polynomial_t operator+(polynomial_t n);
    polynomial_t operator-(polynomial_t n);
    int resolve(vector_t &roots);

    number_t eval(vector_t &poly, number_t x);
    vector_t deflate(vector_t &poly, number_t root);
    number_t find_root(vector_t &poly, number_t x);
    int laguerre_resolve(vector_t &out);
    int cauchy_bound(bounds_t *re, bounds_t *im);
    void print();

    polynomial_t(vector_t v);
    polynomial_t();
    ~polynomial_t();
};

#endif
