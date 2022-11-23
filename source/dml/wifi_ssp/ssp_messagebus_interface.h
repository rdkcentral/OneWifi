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

    module: ssp_messagebus_interface.h

        For CCSP Secure Software Download

    ---------------------------------------------------------------

    description:

        The header file for the CCSP Message Bus Interface
        Service.

    ---------------------------------------------------------------

    environment:

        Embedded Linux

    ---------------------------------------------------------------

    author:

        Tom Chang

    ---------------------------------------------------------------

    revision:

        06/23/2011  initial revision.

**********************************************************************/

#ifndef  _SSP_MESSAGEBUS_INTERFACE_
#define  _SSP_MESSAGEBUS_INTERFACE_

ANSC_STATUS
ssp_WifiMbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    );

int
ssp_WifiMbi_Initialize
    (
        void * user_data
    );

int
ssp_WifiMbi_Finalize
    (
        void * user_data
    );

int
ssp_WifiMbi_Buscheck
    (
        void * user_data
    );

int
ssp_WifiMbi_FreeResources
    (
        int priority,
        void * user_data
    );

ANSC_STATUS
ssp_WifiMbi_SendParameterValueChangeSignal
    (
        char * pPamameterName,
        SLAP_VARIABLE * oldValue,
        SLAP_VARIABLE * newValue,
        char * pAccessList
    );

ANSC_STATUS
ssp_WifiMbi_SendTransferCompleteSignal
    (
        void
    );

DBusHandlerResult
CcspPandM_path_message_func
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    );

/*
static DBusHandlerResult
path_message_func 
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    );
*/

ANSC_STATUS 
ssp_WifiMbi_RegisterToCR
    (
        ANSC_HANDLE                     hThisObject,
        name_spaceType_t*               pParameterArray
    );

BOOLEAN 
waitConditionReady
    (
        void* hMBusHandle, 
        const char* dst_component_id, 
        char* dbus_path, 
        char *src_component_id
    );

#endif
