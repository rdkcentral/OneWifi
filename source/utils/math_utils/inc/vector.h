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

#ifndef VECTOR_H
#define VECTOR_H

#include "base.h"
#include "number.h"

class vector_t {
public:
    unsigned int m_num;
    number_t m_val[MAX_LEN];

public:
    void print();
    unsigned int get_capacity()
    {
        return MAX_LEN;
    }
    vector_t invert();
    void sort();
    number_t mean();
    number_t stddev();

    void push_back(number_t val);
    vector_t derivative(void);
    void get_highest_val_index(unsigned int &index);
    vector_t operator+(vector_t v);
    vector_t operator-(vector_t v);
    vector_t operator/(number_t n);
    vector_t(unsigned int num, number_t n[]);
    vector_t(unsigned int num);
    vector_t();
    ~vector_t();
};

#endif
