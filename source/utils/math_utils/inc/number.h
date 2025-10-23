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

#ifndef NUMBER_H
#define NUMBER_H

#include "base.h"

class matrix_t;
class vector_t;

class number_t {
public:
    double m_re;
    double m_im;

    bool is_zero(double x, int n);

public:
    bool operator==(number_t n);
    number_t operator*(number_t n);
    number_t operator/(number_t n);
    number_t operator+(number_t n);
    number_t operator-(number_t n);

    number_t operator-(void);

    matrix_t operator*(matrix_t m);

    void sqroot(number_t n[]);
    number_t sqrt_val(void);
    double mod_z();
    double abs_val() const;
    number_t absolute();
    number_t exponential();
    number_t power(unsigned int n);
    bool is_zero(int n);

    void set_real(double d)
    {
        m_re = d;
    }
    void set_imag(double d)
    {
        m_im = d;
    }

    double get_real()
    {
        return m_re;
    }
    double get_imag()
    {
        return m_im;
    }

    void print();

    number_t(double r, double i);
    number_t(char *str);
    number_t();
    ~number_t();
};

#endif
