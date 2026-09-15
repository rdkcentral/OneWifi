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

/*
 * NOTE: This file is included also in OneWifi project which is C based, thus
 * there should be only usage of C based constructs in this file.
 * C++ constructs are not allowed in this file.
 */
#ifndef MTRX_H
#define MTRX_H

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_LEN 256

typedef struct {
    unsigned int num;
    double val[MAX_LEN];
} vector_t;

typedef struct {
    unsigned int rows;
    unsigned int cols;
    double val[MAX_LEN][MAX_LEN];
} matrix_t;

int vector(vector_t *v, ...);
void print_vector(vector_t *v);

int matrix(matrix_t *m, ...);
void print_matrix(matrix_t *m);

int multiply(matrix_t *out, matrix_t *m1, matrix_t *m2);
int transpose(matrix_t *out, matrix_t *in);

int mean(double *out, matrix_t *in);
int variance(double *out, matrix_t *in);
int stddev(double *out, matrix_t *in);
int covariance(matrix_t *out, matrix_t *in);
int correlation(matrix_t *out, matrix_t *in);
int kurtosis(matrix_t *out, matrix_t *in);
int polynomial_2(vector_t *out, vector_t *in);
int polynomial_3(vector_t *out, vector_t *in);

int find_eigens(matrix_t *m, unsigned int num, double *eigen_vals, vector_t *eigen_vecs);

#ifdef __cplusplus
}
#endif

#endif // MTRX_H
