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

#include "matrix.h"
#include "equation.h"
#include "number.h"
#include "polynomial.h"
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void matrix_t::print()
{
    unsigned int i, j;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            m_val[i][j].print();
            wifi_util_dbg_print(WIFI_LIB, "\t\t");
        }
        wifi_util_dbg_print(WIFI_LIB, "\n");
    }
}

matrix_t matrix_t::inverse()
{
    matrix_t out(0, 0);

    number_t det;
    matrix_t a;
    unsigned int i, j;

    if (m_rows != m_cols) {
        wifi_util_error_print(WIFI_LIB, "%s:%d: Can not be inverted\n", __func__, __LINE__);
        return out;
    }

    det = determinant();

    if ((det.m_re == 0) && (det.m_im == 0)) {
        wifi_util_error_print(WIFI_LIB, "%s:%d: Matrix is singular\n", __func__, __LINE__);
        return out;
    }

    a = adjoint();

    out.m_rows = m_rows;
    out.m_cols = m_cols;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            out.m_val[i][j] = a.m_val[i][j] / det;
        }
    }

    return out;
}

vector_t matrix_t::linear(vector_t &right)
{
    vector_t out;
    matrix_t inv, tmp, res;
    unsigned int i;

    inv = inverse();

    tmp = matrix_t(right.m_num, 1);
    tmp.set_col(0, right);

    res = inv * tmp;

    out.m_num = m_rows;
    for (i = 0; i < out.m_num; i++) {
        out.m_val[i] = res.m_val[i][0];
    }

    return out;
}

matrix_t matrix_t::conjugate()
{
    matrix_t m;
    unsigned int i, j;

    m.m_rows = m_rows;
    m.m_cols = m_cols;
    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            m.m_val[i][j].m_re = m_val[i][j].m_re;
            m.m_val[i][j].m_im = -m_val[i][j].m_im;
        }
    }

    return m;
}

matrix_t matrix_t::hermitian()
{
    matrix_t m;

    m = conjugate();

    return m.transpose();
}

void matrix_t::row_reduced_echelon_form(matrix_t &rref, matrix_t m)
{
    unsigned int i, j;
    number_t n;

    if (m.m_rows == 1) {
        m.m_val[0][0] = number_t(1, 0);
        rref.m_val[rref.m_rows - 1][rref.m_cols - 1] = m.m_val[0][0];
        return;
    }

    // first divide the first row by element[0][0]
    n = m.m_val[0][0];
    for (j = 0; j < m_cols; j++) {
        m.m_val[0][j] = m.m_val[0][j] / n;
    }

    for (i = 1; i < m_rows; i++) {
        n = m.m_val[i][0];
        for (j = 0; j < m_cols; j++) {
            m.m_val[i][j] = m.m_val[i][j] - n * m.m_val[0][j];
        }
    }

    // copy m to rref
    for (i = 0; i < m.m_rows; i++) {
        for (j = 0; j < m.m_cols; j++) {
            rref.m_val[rref.m_rows - m.m_rows + i][rref.m_cols - m.m_cols + j] = m.m_val[i][j];
        }
    }

    // rref.print();
    // wifi_util_dbg_print(WIFI_LIB, "\n");

    row_reduced_echelon_form(rref, m.minor(0, 0));
}

matrix_t matrix_t::row_reduced_echelon_form()
{
    matrix_t rref = *this;

    this->print();
    wifi_util_dbg_print(WIFI_LIB, "\n");

    row_reduced_echelon_form(rref, *this);
    rref.print();
    wifi_util_dbg_print(WIFI_LIB, "\n");

    return rref;
}

number_t matrix_t::null_space()
{
    matrix_t echelon = *this;
    number_t out;
    unsigned int i, j;

    if (m_rows == 1) {
        return m_val[0][0];
    }

    // first divide the first row by element[0][0]
    for (j = 0; j < m_cols; j++) {
        echelon.m_val[0][j] = echelon.m_val[0][j] / echelon.m_val[0][0];
    }

    for (i = 1; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            echelon.m_val[i][j] = echelon.m_val[i][j] - echelon.m_val[i][0] * echelon.m_val[0][j];
        }
    }

    echelon.print();
    wifi_util_dbg_print(WIFI_LIB, "\n");

    return echelon.minor(0, 0).null_space();
}

vector_t matrix_t::eigen_vector(number_t &val)
{
    vector_t right, sol, out;
    matrix_t m;
    unsigned int i, j;

    m.m_rows = m_rows;
    m.m_cols = m_cols;
    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            if (i == j) {
                m.m_val[i][j].m_re = m_val[i][j].m_re - val.m_re;
                m.m_val[i][j].m_im = m_val[i][j].m_im - val.m_im;
            } else {
                m.m_val[i][j].m_re = m_val[i][j].m_re;
                m.m_val[i][j].m_im = m_val[i][j].m_im;
            }
        }
    }

    right.m_num = m.m_rows;
    for (i = 0; i < right.m_num; i++) {
        right.m_val[i] = number_t(0, 0);
    }

    right.m_val[i - 1].m_re = 1;

    sol = m.linear(right);

    out.m_num = sol.m_num;
    for (i = 0; i < sol.m_num; i++) {
        out.m_val[i] = sol.m_val[i] / sol.m_val[sol.m_num - 1];
    }

    // m = row_reduced_echelon_form();

    return out;
}

number_t matrix_t::trace()
{
    number_t n(0, 0);
    unsigned int i, j;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            if (i == j) {
                n = n + m_val[i][j];
            }
        }
    }

    return n;
}

vector_t matrix_t::faddeev_leverrier()
{
    vector_t p;
    unsigned int i, j;
    matrix_t u;
    matrix_t m;
    number_t n;

    u.m_rows = m_rows;
    u.m_cols = m_cols;
    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            if (i == j) {
                u.m_val[i][j] = number_t(1, 0);
            } else {
                u.m_val[i][j] = number_t(0, 0);
            }
        }
    }

    p.m_num = m_rows + 1;

    m = *this;
    p.m_val[0] = number_t(1, 0);

    for (i = 1; i <= m_rows; i++) {
        // n = number_t(pow(i, -1), 0);
        n = number_t(-1.0 / i, 0);
        p.m_val[i] = n * m.trace();
        // m = (*this)*(m - (p.m_val[i] * u));
        matrix_t temp, add;
        temp = p.m_val[i] * u;
        add = m + temp;
        m = (*this) * add;
    }

#if 1
    for (i = 0; i < p.m_num; ++i) {
        wifi_util_dbg_print(WIFI_LIB, "λ^%d: ", m_cols - i);
        p.m_val[i].print();
        wifi_util_dbg_print(WIFI_LIB, "\n");
    }
#endif

    return p;
}

int matrix_t::cholesky(matrix_t &l)
{
    unsigned int i, j, k;
    number_t n, root[2];

    l = matrix_t(m_rows, m_cols);

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < i + 1; j++) {
            if (i == j) {
                n = number_t(0, 0);
                for (k = 0; k < j; k++) {
                    n = n + (l.m_val[j][k] * (number_t(0, 0) - l.m_val[j][k]));
                }

                (m_val[i][j] - n).sqroot(root);

                l.m_val[i][j] = root[0];
            } else {
                n = number_t(0, 0);
                for (k = 0; k < j; k++) {
                    n = n + (l.m_val[i][k] * (number_t(0, 0) - l.m_val[j][k]));
                }

                l.m_val[i][j] = (m_val[i][j] - n) / l.m_val[j][j];
            }
        }
    }

    return 0;
}

int matrix_t::eigen(vector_t &vals, matrix_t &vecs)
{
    unsigned int i;
    vector_t v;

    if (m_rows != m_cols) {
        return -1;
    }

    // polynomial_t(faddeev_leverrier()).resolve(vals);
    // vals.sort();

    // polynomial_t(faddeev_leverrier()).laguerre_resolve(vals);
    polynomial_t eq;
    vals = faddeev_leverrier();

    vals.print();
    eq.laguerre_resolve(vals);
    vals.sort();
    vals.print();

    vecs.m_rows = vals.m_num;
    vecs.m_cols = vals.m_num;

    for (i = 0; i < vals.m_num; i++) {
        v = eigen_vector(vals.m_val[i]);
        v.print();
        vecs.set_row(i, v);
    }

    return 0;
}

matrix_t matrix_t::adjoint()
{
    matrix_t t(0, 0), m(0, 0), out(0, 0);
    number_t det, n;
    unsigned int i, j;

    if (m_rows != m_cols) {
        wifi_util_error_print(WIFI_LIB, "%s:%d: Can not find inverse of matrix\n", __func__,
            __LINE__);
        return out;
    }

    t = transpose();

    for (i = 0; i < t.m_rows; i++) {
        for (j = 0; j < t.m_cols; j++) {
            m = t.minor(i, j);
            det = m.determinant();

            n = { pow(-1, i + j), 0 };
            out.m_val[i][j] = n * det;
        }
    }

    out.m_rows = m_rows;
    out.m_cols = m_cols;

    return out;
}

matrix_t matrix_t::minor(unsigned int row, unsigned int col)
{
    unsigned int i, j, p = 0, q = 0;
    matrix_t out(0, 0);

    out.m_rows = m_rows - 1;
    out.m_cols = m_cols - 1;

    for (i = 0; i < m_rows; i++) {
        if (i == row) {
            continue;
        }
        for (j = 0; j < m_cols; j++) {
            if (j == col) {
                continue;
            }
            out.m_val[p][q] = m_val[i][j];
            q++;
        }
        q = 0;
        p++;
    }

    return out;
}

number_t matrix_t::determinant()
{
    unsigned int j;
    number_t temp(0, 0), n(0, 0), res1(0, 0), res2(0, 0), out(0, 0);
    matrix_t m(0, 0);

    if (m_rows != m_cols) {
        return n;
    }

    if (m_rows == 1) {
        n.m_re = m_val[0][0].m_re;
        n.m_im = m_val[0][0].m_im;
        return n;
    }

    if (m_rows == 2) {
        res1 = m_val[0][0] * m_val[1][1];
        res2 = m_val[0][1] * m_val[1][0];

        return res1 - res2;
    }

    for (j = 0; j < m_cols; j++) {
        m = minor(0, j);
        temp = m.determinant();

        n = { pow(-1, j), 0 };
        res1 = n * m_val[0][j];
        res2 = res1 * temp;

        out = out + res2;
    }

    return out;
}

matrix_t matrix_t::covariance()
{
    unsigned int i, j;
    matrix_t data_h, out(0, 0);

    if (m_rows == 1) {
        wifi_util_error_print(WIFI_LIB,
            "%s:%d: Cannot calculate covariance"
            " of insufficient valued matrices\n",
            __func__, __LINE__);
        return out;
    }

    data_h = hermitian();

    out = (*this) * data_h;

    for (j = 0; j < out.m_cols; j++) {
        for (i = 0; i < out.m_rows; i++) {
            out.m_val[i][j].m_re /= this->m_cols;
            out.m_val[i][j].m_im /= this->m_cols;
        }
    }

    return out;
}

matrix_t matrix_t::center()
{
    unsigned int i, j;
    vector_t v;
    number_t m(0, 0);
    matrix_t out(m_rows, m_cols);

    for (j = 0; j < m_cols; j++) {
        v = get_col(j);
        m = v.mean();
        for (i = 0; i < m_rows; i++) {
            out.m_val[i][j] = m_val[i][j] - m;
        }
    }

    return out;
}

matrix_t matrix_t::transpose()
{
    unsigned int i = 0, j = 0;
    matrix_t out(0, 0);

    out.m_rows = m_cols;
    out.m_cols = m_rows;

    for (i = 0; i < out.m_rows; i++) {
        for (j = 0; j < out.m_cols; j++) {
            out.m_val[i][j] = m_val[j][i];
        }
    }
    return out;
}

matrix_t matrix_t::operator*(matrix_t m)
{
    unsigned int i = 0, j = 0, k = 0;
    matrix_t out(0, 0);

    if (m_cols != m.m_rows) {
        wifi_util_error_print(WIFI_LIB,
            "%s:%d: Matrices can't be multipled,"
            " mismatch of 1st Matrix Columns: %d and 2nd Matrix Rows: %d\n",
            __func__, __LINE__, m_cols, m.m_rows);
        return out;
    }

    out.m_rows = m_rows;
    out.m_cols = m.m_cols;

    for (i = 0; i < out.m_rows; i++) {
        for (j = 0; j < out.m_cols; j++) {
            for (k = 0; k < m_cols; k++) {
                out.m_val[i][j].m_re += (m_val[i][k].m_re * m.m_val[k][j].m_re -
                    m_val[i][k].m_im * m.m_val[k][j].m_im);
                out.m_val[i][j].m_im += (m_val[i][k].m_re * m.m_val[k][j].m_im +
                    m_val[i][k].m_im * m.m_val[k][j].m_re);
            }
        }
    }

    return out;
}

matrix_t matrix_t::operator+(matrix_t m)
{
    matrix_t out(0, 0);
    unsigned int i, j;

    if ((m_rows != m.m_rows) || (m_cols != m.m_cols)) {
        return out;
    }

    out.m_rows = m_rows;
    out.m_cols = m_cols;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            out.m_val[i][j] = m_val[i][j] + m.m_val[i][j];
        }
    }

    return out;
}

matrix_t matrix_t::operator-(matrix_t m)
{
    matrix_t out(0, 0);
    unsigned int i, j;

    if ((m_rows != m.m_rows) || (m_cols != m.m_cols)) {
        return out;
    }

    out.m_rows = m_rows;
    out.m_cols = m_cols;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            out.m_val[i][j] = m_val[i][j] - m.m_val[i][j];
        }
    }

    return out;
}

void matrix_t::set_row(unsigned int row, vector_t &v)
{
    unsigned int j;

    if (m_rows == 0) {
        m_rows = 1;
        m_cols = v.m_num;
    }

    if (m_cols != v.m_num) {
        return;
    }

    for (j = 0; j < m_cols; j++) {
        m_val[row][j] = v.m_val[j];
    }
}

void matrix_t::set_col(unsigned int col, vector_t &v)
{
    unsigned int i;

    if (m_cols == 0) {
        m_cols = 1;
        m_rows = v.m_num;
    }

    if (m_rows != v.m_num) {
        return;
    }

    for (i = 0; i < m_rows; i++) {
        m_val[i][col] = v.m_val[i];
    }
}

vector_t matrix_t::get_row(unsigned int row)
{
    vector_t out;
    unsigned int j;

    out.m_num = m_cols;

    for (j = 0; j < m_cols; j++) {
        out.m_val[j] = m_val[row][j];
    }

    return out;
}

vector_t matrix_t::get_col(unsigned int col)
{
    vector_t out;
    unsigned int i;

    out.m_num = m_rows;

    for (i = 0; i < m_rows; i++) {
        out.m_val[i] = m_val[i][col];
    }

    return out;
}

matrix_t::matrix_t(unsigned int rows, unsigned int cols, number_t n[])
{
    unsigned int i, j, k = 0;

    m_rows = rows;
    m_cols = cols;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            m_val[i][j] = n[k];
            k++;
        }
    }
}

matrix_t::matrix_t(unsigned int rows, unsigned int cols)
{
    unsigned int i, j;

    m_rows = rows;
    m_cols = cols;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            m_val[i][j] = number_t(0, 0);
        }
    }
}

matrix_t::matrix_t(const matrix_t &m)
{
    unsigned int i, j;

    m_rows = m.m_rows;
    m_cols = m.m_cols;

    for (i = 0; i < m_rows; i++) {
        for (j = 0; j < m_cols; j++) {
            m_val[i][j] = m.m_val[i][j];
        }
    }
}

matrix_t::matrix_t(vector_t v, bool as_row)
{
    unsigned int i, j;

    if (as_row) {
        m_rows = 1;
        m_cols = v.m_num;
        for (j = 0; j < m_cols; j++) {
            m_val[0][j] = v.m_val[j];
        }
    } else {
        m_rows = v.m_num;
        m_cols = 1;
        for (i = 0; i < m_rows; i++) {
            m_val[i][0] = v.m_val[i];
        }
    }
}

matrix_t::matrix_t()
{
    m_rows = 0;
    m_cols = 0;
}

matrix_t::~matrix_t()
{
}
