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

#include "equation.h"
#include "polynomial.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void equation_t::print_matrix_s(matrix_s_t *m)
{
    unsigned int i, j;

    wifi_util_dbg_print(WIFI_LIB, "Matrix S:\n");
    for (i = 0; i < m->rows; i++) {
        for (j = 0; j < m->cols; j++) {
            wifi_util_dbg_print(WIFI_LIB, "%s\t", m->val[i][j]);
        }
        wifi_util_dbg_print(WIFI_LIB, "\n");
    }
    wifi_util_dbg_print(WIFI_LIB, "\n");
}

void equation_t::print()
{
    wifi_util_dbg_print(WIFI_LIB, "%s\n", m_eqn);
}

vector_t equation_t::arguments()
{
    vector_t out(0);
    large_expr_t copy = { 0 };
    char *tmp, *s;
    unsigned int i, degree, highest = 0;
    vector_s_t v_s_tmp = { 0 }, v_s_signed = { 0 };
    number_t n(0);

    if (m_eqn[0] == 0) {
        return 0;
    }

    strncpy(copy, m_eqn, strlen(m_eqn) + 1);
    tmp = copy;
    s = copy;

    v_s_tmp.num = 0;
    v_s_signed.num = 0;

    if (*tmp == '-') {
        strncpy(v_s_tmp.val[v_s_tmp.num], "-", strlen("-") + 1);
        v_s_tmp.num++;
        tmp++;
    } else if (*tmp == '+') {
        strncpy(v_s_tmp.val[v_s_tmp.num], "+", strlen("+") + 1);
        v_s_tmp.num++;
        tmp++;
    } else {
        strncpy(v_s_tmp.val[v_s_tmp.num], "+", strlen("+") + 1);
        v_s_tmp.num++;
    }

    while (tmp != NULL) {
        if (*tmp == '+') {
            strncpy(v_s_tmp.val[v_s_tmp.num], "+", strlen("+") + 1);
            v_s_tmp.num++;

        } else if (*tmp == '-') {
            strncpy(v_s_tmp.val[v_s_tmp.num], "-", strlen("-") + 1);
            v_s_tmp.num++;

        } else if (*tmp != ' ') {
            s = tmp;
            if ((tmp = strchr(s, ' ')) != NULL) {
                *tmp = 0;
                strncpy(v_s_tmp.val[v_s_tmp.num], s, strlen(s) + 1);
                v_s_tmp.num++;
            } else if ((tmp = strchr(s, '+')) != NULL) {
                *tmp = 0;
                strncpy(v_s_tmp.val[v_s_tmp.num], s, strlen(s) + 1);
                v_s_tmp.num++;
                strncpy(v_s_tmp.val[v_s_tmp.num], "+", strlen("+") + 1);
                v_s_tmp.num++;
            } else if ((tmp = strchr(s, '-')) != NULL) {
                *tmp = 0;
                strncpy(v_s_tmp.val[v_s_tmp.num], s, strlen(s) + 1);
                v_s_tmp.num++;
                strncpy(v_s_tmp.val[v_s_tmp.num], "-", strlen("-") + 1);
                v_s_tmp.num++;
            } else if (tmp == NULL) {
                strncpy(v_s_tmp.val[v_s_tmp.num], s, strlen(s) + 1);
                v_s_tmp.num++;
                break;
            }
        }
        tmp++;
    }

    for (i = 0; i < v_s_tmp.num / 2; i++) {
        snprintf(v_s_signed.val[i], sizeof(expr_t), "%s%s", v_s_tmp.val[2 * i],
            v_s_tmp.val[2 * i + 1]);
        v_s_signed.num++;
    }

    for (i = 0; i < v_s_signed.num; i++) {
        s = v_s_signed.val[i];
        if ((tmp = strstr(v_s_signed.val[i], "x^")) != NULL) {
            *tmp = 0;
            tmp += strlen("x^");
            degree = atof(tmp);
            if (degree > highest) {
                highest = degree;
            }
            n = number_t(s);
            out.m_val[degree] = out.m_val[degree] + n;
        } else if ((tmp = strstr(v_s_signed.val[i], "x")) != NULL) {
            *tmp = 0;
            tmp += strlen("x");
            highest = 1;
            n = number_t(s);
            out.m_val[1] = out.m_val[1] + n;
        } else {
            n = number_t(s);
            out.m_val[0] = out.m_val[0] + n;
        }
    }

    out.m_num = highest + 1;

    return out;
}

int equation_t::minor(matrix_s_t *out, matrix_s_t *in, unsigned int row, unsigned int col)
{
    unsigned int i, j, p = 0, q = 0;

    out->rows = in->rows - 1;
    out->cols = in->cols - 1;

    for (i = 0; i < out->rows; i++) {
        for (j = 0; j < out->cols; j++) {
            memset(out->val[i][j], 0, sizeof(expr_t));
        }
    }

    for (i = 0; i < in->rows; i++) {
        if (i == row) {
            continue;
        }
        for (j = 0; j < in->cols; j++) {
            if (j == col) {
                continue;
            }
            strncpy(out->val[p][q], in->val[i][j], strlen(in->val[i][j]) + 1);
            q++;
        }
        q = 0;
        p++;
    }

    return 0;
}

equation_t equation_t::determinant(matrix_s_t *in)
{
    unsigned int j;
    matrix_s_t m;
    equation_t eq;

    if (in->rows != in->cols) {
        return equation_t("");
    }

    if (in->rows == 1) {
        return equation_t(in->val[0][0]);
    }

    if (in->rows == 2) {

        return equation_t(in->val[0][0]) * equation_t(in->val[1][1]) -
            equation_t(in->val[0][1]) * equation_t(in->val[1][0]);
    }

    for (j = 0; j < in->cols; j++) {
        minor(&m, in, 0, j);
        // print_matrix_s(&m);

        if (pow(-1, j) > 0) {
            eq = eq + (equation_t(in->val[0][j]) * determinant(&m));
        } else {
            eq = eq - (equation_t(in->val[0][j]) * determinant(&m));
        }

        // eq4.print();
    }

    return eq;
}

equation_t equation_t::operator*(equation_t e)
{
    vector_t v1(0), v2(0), v3(0);
    unsigned int i;

    v1 = arguments();
    v2 = e.arguments();

    if ((v1.m_num > 1) && (v2.m_num > 1)) {
        v3 = (polynomial_t(v1) * polynomial_t(v2)).m_args;
    } else if ((v1.m_num == 1) && (v2.m_num > 1)) {
        for (i = 0; i < v2.m_num; i++) {
            v3.m_val[i].m_re = v1.m_val[0].m_re * v2.m_val[i].m_re -
                v1.m_val[0].m_im * v2.m_val[i].m_im;
            v3.m_val[i].m_im = v1.m_val[0].m_im * v2.m_val[i].m_re +
                v1.m_val[0].m_re * v2.m_val[i].m_im;
            v3.m_num++;
        }
    } else if ((v1.m_num > 1) && (v2.m_num == 1)) {
        for (i = 0; i < v1.m_num; i++) {
            v3.m_val[i].m_re = v2.m_val[0].m_re * v1.m_val[i].m_re -
                v2.m_val[0].m_im * v1.m_val[i].m_im;
            v3.m_val[i].m_im = v2.m_val[0].m_im * v1.m_val[i].m_re +
                v2.m_val[0].m_re * v1.m_val[i].m_im;
            v3.m_num++;
        }
    } else {
        v3.m_val[0].m_re = v2.m_val[0].m_re * v1.m_val[0].m_re -
            v2.m_val[0].m_im * v1.m_val[0].m_im;
        v3.m_val[0].m_im = v2.m_val[0].m_re * v1.m_val[0].m_im +
            v2.m_val[0].m_im * v1.m_val[0].m_re;
        v3.m_num = 1;
    }

    return equation_t(v3);
}

equation_t equation_t::operator/(equation_t n)
{
    return equation_t("");
}

equation_t equation_t::operator+(equation_t e)
{
    vector_t v1(0), v2(0), v3(0);
    unsigned int i, larger_num;

    v1 = arguments();
    v2 = e.arguments();

    if (v1.m_num >= v2.m_num) {
        larger_num = v1.m_num;
    } else {
        larger_num = v2.m_num;
    }

    v3.m_num = larger_num;

    for (i = 0; i < larger_num; i++) {
        v3.m_val[i].m_re = v1.m_val[i].m_re + v2.m_val[i].m_re;
        v3.m_val[i].m_im = v1.m_val[i].m_im + v2.m_val[i].m_im;
    }

    return equation_t(v3);
}

equation_t equation_t::operator-(equation_t e)
{
    vector_t v1 = (0), v2 = (0), v3 = (0);
    unsigned int i, larger_num;

    v1 = arguments();
    v2 = e.arguments();

    if (v1.m_num >= v2.m_num) {
        larger_num = v1.m_num;
    } else {
        larger_num = v2.m_num;
    }

    v3.m_num = larger_num;

    for (i = 0; i < larger_num; i++) {
        v3.m_val[i].m_re = v1.m_val[i].m_re - v2.m_val[i].m_re;
        v3.m_val[i].m_im = v1.m_val[i].m_im - v2.m_val[i].m_im;
    }

    return equation_t(v3);
}

equation_t::equation_t(const char *s)
{
    memset(m_eqn, 0, sizeof(large_expr_t));
    strncpy(m_eqn, s, strlen(s) + 1);
}

equation_t::equation_t(vector_t v)
{
    unsigned int i;
    expr_t tmp = { 0 };

    memset(m_eqn, 0, sizeof(large_expr_t));

    for (i = 0; i < v.m_num; i++) {
        if (i == 1) {
            if (fabs(v.m_val[i].m_re) != 0) {
                if (v.m_val[i].m_re < 0) {
                    snprintf(tmp, sizeof(expr_t), "- %0.4fx ", fabs(v.m_val[i].m_re));
                } else {
                    snprintf(tmp, sizeof(expr_t), "+ %0.4fx ", v.m_val[i].m_re);
                }
                strncat(m_eqn, tmp, sizeof(expr_t));
            }
            if (fabs(v.m_val[i].m_im) != 0) {
                if (v.m_val[i].m_im < 0) {
                    snprintf(tmp, sizeof(expr_t), "- %0.4fix ", fabs(v.m_val[i].m_im));
                } else {
                    snprintf(tmp, sizeof(expr_t), "+ %0.4fix ", v.m_val[i].m_im);
                }
                strncat(m_eqn, tmp, sizeof(expr_t));
            }
        } else if (i == 0) {
            if (fabs(v.m_val[i].m_re) != 0) {
                if (v.m_val[i].m_re < 0) {
                    snprintf(tmp, sizeof(expr_t), "- %0.4f ", fabs(v.m_val[i].m_re));
                } else {
                    snprintf(tmp, sizeof(expr_t), "+ %0.4f ", v.m_val[i].m_re);
                }
                strncat(m_eqn, tmp, sizeof(expr_t));
            }
            if (fabs(v.m_val[i].m_im) != 0) {
                if (v.m_val[i].m_im < 0) {
                    snprintf(tmp, sizeof(expr_t), "- %0.4fi ", fabs(v.m_val[i].m_im));
                } else {
                    snprintf(tmp, sizeof(expr_t), "+ %0.4fi ", v.m_val[i].m_im);
                }
                strncat(m_eqn, tmp, sizeof(expr_t));
            }
        } else {
            if (fabs(v.m_val[i].m_re) != 0) {
                if (v.m_val[i].m_re < 0) {
                    snprintf(tmp, sizeof(expr_t), "- %0.4fx^%d ", fabs(v.m_val[i].m_re), i);
                } else {
                    snprintf(tmp, sizeof(expr_t), "+ %0.4fx^%d ", v.m_val[i].m_re, i);
                }
                strncat(m_eqn, tmp, sizeof(expr_t));
            }

            if (fabs(v.m_val[i].m_im) != 0) {
                if (v.m_val[i].m_im < 0) {
                    snprintf(tmp, sizeof(expr_t), "- %0.4fix^%d ", fabs(v.m_val[i].m_im), i);
                } else {
                    snprintf(tmp, sizeof(expr_t), "+ %0.4fix^%d ", v.m_val[i].m_im, i);
                }
                strncat(m_eqn, tmp, sizeof(expr_t));
            }
        }
    }
}

equation_t::equation_t()
{
}

equation_t::~equation_t()
{
}
