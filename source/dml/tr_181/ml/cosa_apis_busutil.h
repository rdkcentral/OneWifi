/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


/**********************************************************************

    module: dslh_dmagnt_exported.c

        For DSL Home Model Implementation (DSLH),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the framework's exported functions
        by the Dslh DataModelAgent object;

        *   CosaGetParamValueUlong2
        *   CosaGetParamValueString
        *   CosaGetParamValueBool
        *   CosaGetInstanceNumberByIndex

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        01/06/2011    initial revision.
        01/11/2011    added SLAP related apis.
        03/21/2011    added api to retrieve instance number by index

**********************************************************************/
#ifndef  _COSA_APIS_BUSUTIL_H
#define  _COSA_APIS_BUSUTIL_H


ULONG
CosaGetParamValueUlong
    (
        char*                       pParamName
    );

int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    );

BOOL
CosaGetParamValueBool
    (
        char*                       pParamName
    );

ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    );


#endif
