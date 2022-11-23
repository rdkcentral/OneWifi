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

        *   CosaGetParamValueUlong
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

#include "cosa_apis.h"

#include "plugin_main_apis.h"
#include "cosa_apis_busutil.h"
#include "ansc_platform.h"

extern void* g_pDslhDmlAgent;

/**********************************************************************

    prototype:

        ULONG
        CosaGetParamValueUlong2
            (
                char*                       pParamName
            )

    description:

        This function is called to retrieve a UONG value of a parameter;

    argument:   
            char*                       pParamName
            The full name of the parameter;

    return:     the ULONG value;

**********************************************************************/
ULONG
CosaGetParamValueUlong
    (
        char*                       pParamName
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable 
            Currently, we suppose all the parameter is from P&M. */

    return g_GetParamValueUlong(g_pDslhDmlAgent, pParamName);
}

/**********************************************************************

    prototype:

        int
        CosaGetParamValueString
            (
                char*                       pParamName,
                char*                       pBuffer,
                PULONG                      pulSize
            )

    description:

        This function is called to retrieve a string value of a parameter;

    argument:   
            char*                       pParamName
            The full name of the parameter;

            char*                       pBuffer,
            The buffer for the value;

            PULONG                      pulSize
            The buffer of size;

    return:     0 = SUCCESS; -1 = FAILURE; 1 = NEW_SIZE;

**********************************************************************/
int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable 
            Currently, we suppose all the parameter is from P&M. */


    return g_GetParamValueString(g_pDslhDmlAgent, pParamName, pBuffer, pulSize);

}

/**********************************************************************

    prototype:

        BOOL
        CosaGetParamValueBool
            (
                char*                       pParamName
            )

    description:

        This function is called to retrieve a UONG value of a parameter;

    argument:   
            char*                       pParamName
            The full name of the parameter;

    return:     the BOOL value;

**********************************************************************/
BOOL
CosaGetParamValueBool
    (
        char*                       pParamName
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable 
            Currently, we suppose all the parameter is from P&M. */

    return g_GetParamValueBool(g_pDslhDmlAgent, pParamName);
}

/**********************************************************************

    prototype:

        ULONG
        CosaGetInstanceNumberByIndex
            (
                char*                      pObjName,
                ULONG                      ulIndex
            );

    description:

        This function is called to retrieve the instance number specified by index;

    argument:   char*                      pObjName,
                The full object name;

                ULONG                      ulIndex
                The index specified;
            
    return:     the instance number;

**********************************************************************/
ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable 
            Currently, we suppose all the parameter is from P&M. */


    return g_GetInstanceNumberByIndex(g_pDslhDmlAgent, pObjName, ulIndex);
}

