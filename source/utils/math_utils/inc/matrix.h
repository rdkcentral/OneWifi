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

#ifndef MATRIX_H
#define MATRIX_H

#include "base.h"
#include "number.h"
#include "vector.h"

class matrix_t {
public:
    unsigned int m_rows;
    unsigned int m_cols;
    number_t m_val[MAX_MTRX_LEN][MAX_MTRX_LEN];

private:
    void row_reduced_echelon_form(matrix_t &rref, matrix_t minor);

public:
    void set_row(unsigned int row, vector_t &v);
    void set_col(unsigned int col, vector_t &v);

    vector_t get_row(unsigned int row);
    vector_t get_col(unsigned int col);

    matrix_t operator*(matrix_t m);
    matrix_t operator+(matrix_t m);
    matrix_t operator-(matrix_t m);

    matrix_t inverse();
    matrix_t adjoint();
    number_t determinant();
    matrix_t minor(unsigned int row, unsigned int col);
    matrix_t covariance();
    matrix_t conjugate();
    matrix_t transpose();
    matrix_t hermitian();
    matrix_t center();
    number_t trace();
    vector_t linear(vector_t &right);
    int eigen(vector_t &vals, matrix_t &vecs);
    int cholesky(matrix_t &l);
    vector_t eigen_vector(number_t &val);
    number_t null_space();
    matrix_t row_reduced_echelon_form();
    vector_t faddeev_leverrier();

    void print();

    matrix_t(unsigned int rows, unsigned int cols, number_t n[]);
    matrix_t(unsigned int rows, unsigned int cols);
    matrix_t(const matrix_t &m);
    matrix_t(vector_t v, bool as_row);
    matrix_t();
    ~matrix_t();
};

#endif
