/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2023 RDK Management

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

#ifndef _UTILS_TIMESPEC_MACRO_H_
#define _UTILS_TIMESPEC_MACRO_H_

#ifndef timespecclear
#define timespecclear(tsp) (tsp)->tv_sec = (tsp)->tv_nsec = 0
#endif

#ifndef timespecisset
#define timespecisset(tsp) ((tsp)->tv_sec || (tsp)->tv_nsec)
#endif

#ifndef timespeccmp
#define timespeccmp(a, b, CMP)                                                 \
  (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_nsec CMP (b)->tv_nsec)              \
                                : ((a)->tv_sec CMP (b)->tv_sec))
#endif

#ifndef timespecadd
#define timespecadd(a, b, result)                                              \
  do {                                                                         \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                              \
    (result)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec;                           \
    if ((result)->tv_nsec >= (1000 * 1000 * 1000)) {                           \
      (result)->tv_sec++;                                                      \
      (result)->tv_nsec -= (1000 * 1000 * 1000);                               \
    }                                                                          \
  } while (0)
#endif

#ifndef timespecsub
#define timespecsub(a, b, result)                                              \
  do {                                                                         \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                              \
    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;                           \
    if ((result)->tv_nsec < 0) {                                               \
      (result)->tv_sec--;                                                      \
      (result)->tv_nsec += (1000 * 1000 * 1000);                               \
    }                                                                          \
  } while (0)
#endif

#endif /* _UTILS_TIMESPEC_MACRO_H_ */
