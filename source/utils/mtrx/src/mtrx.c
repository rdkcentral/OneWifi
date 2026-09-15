/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include "mtrx.h"
#include "wifi_util.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int polynomial_3(vector_t *out, vector_t *in)
{
    double a, b, c, d;
    vector_t sum = { 4 }, temp;
    double root, lower_limit = -100;
    double upper_limit = 100;

    if (in->num != 4) {
        return -1;
    }

    a = in->val[0];
    b = in->val[1];
    c = in->val[2];
    d = in->val[3];

    out->num = 3;

    sum.val[0] = a;

    root = lower_limit;

    while (root < upper_limit) {

        sum.val[1] = b + root * sum.val[0];
        sum.val[2] = c + root * sum.val[1];
        sum.val[3] = d + root * sum.val[2];

        if (ceil(sum.val[3]) == 0.000) {
            break;
        }

        root += 0.1;
    }

    if (root == upper_limit) {
        wifi_util_error_print(WIFI_CSI,"%s:%d:Cannot find roots\n", __func__, __LINE__);
        return -1;
    }

    sum.num = 3;
    if (polynomial_2(&temp, &sum) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d:Cannot find roots\n", __func__, __LINE__);
        return -1;
    }

    out->val[0] = root;
    out->val[1] = temp.val[0];
    out->val[2] = temp.val[1];
    out->val[3] = temp.val[0];

    return 0;
}

int polynomial_2(vector_t *out, vector_t *in)
{
    double a, b, c;

    if (in->num != 3) {
        return -1;
    }

    a = in->val[0];
    b = in->val[1];
    c = in->val[2];

    out->num = 2;

    out->val[0] = (-b + sqrt(pow(b, 2) - 4 * a * c)) / (2 * a);
    out->val[1] = (-b - sqrt(pow(b, 2) - 4 * a * c)) / (2 * a);

    return 0;
}

int kurtosis(matrix_t *out, matrix_t *in)
{
    unsigned int i, j;
    matrix_t m1 = { 0, 0 }, mu4 = { 0, 0 }, mu2 = { 0, 0 };
    double mn;

    m1.rows = in->rows;
    m1.cols = 1;

    mu2.rows = 1;
    mu2.cols = in->cols;
    mu4.rows = 1;
    mu4.cols = in->cols;
    out->rows = 1;
    out->cols = in->cols;

    for (j = 0; j < in->cols; j++) {
        for (i = 0; i < in->rows; i++) {
            m1.val[i][0] = in->val[i][j];
        }
        if (mean(&mn, &m1) != 0) {
            wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate mean\n", __func__, __LINE__);
            return -1;
        }

        for (i = 0; i < in->rows; i++) {
            mu4.val[0][j] += pow((in->val[i][j] - mn), 4);
            mu2.val[0][j] += pow((in->val[i][j] - mn), 2);
        }

        mu4.val[0][j] = mu4.val[0][j] / in->rows;
        mu2.val[0][j] = mu2.val[0][j] / in->rows;

        out->val[0][j] = mu4.val[0][j] / pow(mu2.val[0][j], 2);
    }

    return 0;
}

int correlation(matrix_t *out, matrix_t *in)
{
    unsigned int i, j;
    matrix_t m1 = { 0, 0 }, m2 = { 0, 0 }, m3 = { 0, 0 }, m4 = { 0, 0 };
    double m, s;

    m2.rows = in->rows;
    m2.cols = in->cols;

    m1.rows = in->rows;
    m1.cols = 1;

    for (j = 0; j < in->cols; j++) {
        for (i = 0; i < in->rows; i++) {
            m1.val[i][0] = in->val[i][j];
        }
        if (mean(&m, &m1) != 0) {
            wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate mean\n", __func__, __LINE__);
            return -1;
        }

        if (stddev(&s, &m1) != 0) {
            wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate standard deviation\n", __func__, __LINE__);
            return -1;
        }

        for (i = 0; i < in->rows; i++) {
            m2.val[i][j] = (in->val[i][j] - m) / s;
        }
    }

    if (transpose(&m3, &m2) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate transpose\n", __func__, __LINE__);
        return -1;
    }

    if (multiply(&m4, &m3, &m2) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot multiply matrices\n", __func__, __LINE__);
        return -1;
    }

    out->rows = m4.rows;
    out->cols = m4.cols;

    for (i = 0; i < in->rows; i++) {
        for (j = 0; j < in->cols; j++) {
            out->val[i][j] = m4.val[i][j] / (in->rows - 1);
        }
    }

    return 0;
}

int covariance(matrix_t *out, matrix_t *in)
{
    unsigned int i, j;
    double m;
    matrix_t m1 = { 0, 0 }, m2 = { 0, 0 }, m3 = { 0, 0 }, m4 = { 0, 0 };

    if (in->rows == 1) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate covariance of insufficient valued matrices\n", __func__,
            __LINE__);
        return -1;
    }

    m2.rows = in->rows;
    m2.cols = in->cols;

    m1.rows = m2.rows;
    m1.cols = 1;

    for (j = 0; j < in->cols; j++) {
        for (i = 0; i < m1.rows; i++) {
            m1.val[i][j] = in->val[i][j];
        }

        if (mean(&m, &m1) != 0) {
            wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate mean\n", __func__, __LINE__);
            return -1;
        }

        for (i = 0; i < in->rows; i++) {
            m2.val[i][j] = in->val[i][j] - m;
        }
    }

    if (transpose(&m3, &m2) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate transpose\n", __func__, __LINE__);
        return -1;
    }

    if (multiply(&m4, &m3, &m2) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot multiply matrices\n", __func__, __LINE__);
        return -1;
    }

    out->rows = m4.rows;
    out->cols = m4.cols;

    for (i = 0; i < m3.rows; i++) {
        for (j = 0; j < m3.cols; j++) {
            out->val[i][j] = m3.val[i][j] / (in->rows - 1);
        }
    }

    return 0;
}

int stddev(double *out, matrix_t *in)
{
    double d;

    if (variance(&d, in) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate variance\n", __func__, __LINE__);
        return -1;
    }

    *out = sqrt(d);

    return 0;
}

int variance(double *out, matrix_t *in)
{
    unsigned int i;
    matrix_t m1 = { 0, 0 }, m2 = { 0, 0 }, m3 = { 0, 0 }, m4 = { 0, 0 };
    double m;

    if (in->rows == 1) {
        *out = in->val[0][0];
        return 0;
    }

    m1.rows = in->rows;
    m1.cols = 1;

    for (i = 0; i < m1.rows; i++) {
        m1.val[i][0] = in->val[i][0];
    }

    if (mean(&m, &m1) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate mean\n", __func__, __LINE__);
        return -1;
    }

    m2.cols = 1;
    m2.rows = in->rows;

    for (i = 0; i < in->rows; i++) {
        m2.val[i][0] = in->val[i][0] - m;
    }

    if (transpose(&m3, &m2) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot calculate transpose\n", __func__, __LINE__);
        return -1;
    }

    if (multiply(&m4, &m3, &m2) != 0) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Cannot multiply matrices\n", __func__, __LINE__);
        return -1;
    }

    *out = m4.val[0][0] / (in->rows - 1);

    return 0;
}

int mean(double *out, matrix_t *in)
{
    double sum = 0;
    unsigned int i;

    if ((in->rows == 0) || (in->cols == 0)) {
        return 0;
    }

    for (i = 0; i < in->rows; i++) {
        sum += in->val[i][0];
    }

    *out = sum / in->rows;
    return 0;
}

int transpose(matrix_t *out, matrix_t *in)
{
    unsigned int i = 0, j = 0;

    out->rows = in->cols;
    out->cols = in->rows;

    for (i = 0; i < out->rows; i++) {
        for (j = 0; j < out->cols; j++) {
            out->val[i][j] = in->val[j][i];
        }
    }
    return 0;
}

int multiply(matrix_t *out, matrix_t *m1, matrix_t *m2)
{
    unsigned int i = 0, j = 0, k = 0;

    if (m1->cols != m2->rows) {
        wifi_util_error_print(WIFI_CSI,"%s:%d: Matrices can't be multipled, mismatch of 1st Matrix Columns: %d and 2nd "
               "Matrix Rows: %d\n",
            __func__, __LINE__, m1->cols, m2->rows);
        return -1;
    }

    out->rows = m1->rows;
    out->cols = m2->cols;

    for (i = 0; i < out->rows; i++) {
        for (j = 0; j < out->cols; j++) {
            for (k = 0; k < m1->cols; k++) {
                out->val[i][j] += m1->val[i][k] * m2->val[k][j];
            }
        }
    }

    return 0;
}

int find_eigens(matrix_t *m, unsigned int num, double *eigen_vals, vector_t *eigen_vecs)
{

    if (m == NULL) {
        return -1;
    }

    if (m->rows != m->cols) {
        return -1;
    }

    if (m->rows == 0 || m->rows >= MAX_LEN) {
        return -1;
    }

    return 0;
}

int vector(vector_t *v, ...)
{
    va_list list;
    unsigned int i;

    if (v == NULL) {
        return -1;
    }

    if ((v->num == 0) || (v->num >= MAX_LEN)) {
        return -1;
    }

    va_start(list, v);

    for (i = 0; i < v->num; i++) {
        v->val[i] = va_arg(list, double);
    }

    va_end(list);

    return 0;
}

int matrix(matrix_t *m, ...)
{
    va_list list;
    unsigned int i, j;

    if (m == NULL) {
        return -1;
    }

    if ((m->rows == 0) || (m->rows >= MAX_LEN)) {
        return -1;
    }

    if ((m->cols == 0) || (m->cols >= MAX_LEN)) {
        return -1;
    }

    va_start(list, m);

    for (i = 0; i < m->rows; i++) {
        for (j = 0; j < m->cols; j++) {
            m->val[i][j] = va_arg(list, double);
        }
    }

    va_end(list);

    return 0;
}

void print_vector(vector_t *v)
{
    unsigned int i;

    wifi_util_info_print(WIFI_CSI,"Vector:");
    for (i = 0; i < v->num; i++) {
        wifi_util_info_print(WIFI_CSI,"%0.4f\t", v->val[i]);
    }

    wifi_util_info_print(WIFI_CSI,"\n");
}

void print_matrix(matrix_t *m)
{
    unsigned int i, j;

    wifi_util_info_print(WIFI_CSI,"Matrix:");
    wifi_util_info_print(WIFI_CSI,"\n");
    for (i = 0; i < m->rows; i++) {
        for (j = 0; j < m->cols; j++) {
            wifi_util_info_print(WIFI_CSI,"%0.4f\t", m->val[i][j]);
        }
        wifi_util_info_print(WIFI_CSI,"\n");
    }

    wifi_util_info_print(WIFI_CSI,"\n");
}
