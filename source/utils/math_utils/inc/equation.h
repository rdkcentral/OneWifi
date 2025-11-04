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

#ifndef EQUATION_H
#define EQUATION_H

#include "base.h"
#include "matrix.h"
#include "number.h"
#include "vector.h"

class equation_t {
public:
    large_expr_t m_eqn;

public:
    vector_t arguments();
    equation_t operator*(equation_t n);
    equation_t operator/(equation_t n);
    equation_t operator+(equation_t n);
    equation_t operator-(equation_t n);

    equation_t determinant(matrix_s_t *m);
    int minor(matrix_s_t *out, matrix_s_t *in, unsigned int row, unsigned int col);

    void print();
    static void print_matrix_s(matrix_s_t *m);

    equation_t(const char *s);
    equation_t(vector_t v);
    equation_t();
    ~equation_t();
};

#endif
