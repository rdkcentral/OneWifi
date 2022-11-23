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

    module: ssp_messagebus_interface.c

        For CCSP Secure Software Download

    ---------------------------------------------------------------

    description:

        SSP implementation of the CCSP Message Bus Interface
        Service.

        *   ssp_WifiMbi_MessageBusEngage
        *   ssp_WifiMbi_EventCallback
        
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

#include "ssp_global.h"


ANSC_HANDLE                 bus_handle         = NULL;
extern  BOOL                g_bActive;
extern  char                g_Subsystem[32];
extern  PCOMPONENT_COMMON_DM g_pComponent_Common_Dm;

int ssp_WifiMbi_GetHealth ( )
{
    return g_pComponent_Common_Dm->Health;
}

#ifdef _ANSC_LINUX
ANSC_STATUS
ssp_WifiMbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    )
{
    ANSC_STATUS                 returnStatus       = ANSC_STATUS_SUCCESS;
    CCSP_Base_Func_CB           cb                 = {0};
    
    char PsmName[256];

    if ( ! component_id || ! path )
    {
        CcspTraceError((" !!! ssp_WifiMbi_MessageBusEngage: component_id or path is NULL !!!\n"));
        /*CID: 144415,55876  Dereference after null check*/
        return ANSC_STATUS_FAILURE;
    }

    /* Connect to message bus */
    returnStatus = 
        CCSP_Message_Bus_Init
            (
                component_id,
                config_file,
                &bus_handle,
                (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback,           /* mallocfc, use default */
                Ansc_FreeMemory_Callback            /* freefc,   use default */
            );

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        CcspTraceError((" !!! Wifi Message Bus Init ERROR !!!\n"));

        return returnStatus;
    }

    if ( g_Subsystem[0] != 0 )
    {
        _ansc_sprintf(PsmName, "%s%s", g_Subsystem, CCSP_DBUS_PSM);
    }
    else
    {
        AnscCopyString(PsmName, CCSP_DBUS_PSM);
    }

    /* Wait for PSM */
    waitConditionReady(bus_handle, PsmName, CCSP_DBUS_PATH_PSM, component_id);

    CcspTraceInfo(("!!! Connected to message bus... bus_handle: 0x%8p !!!\n", bus_handle));

    CCSP_Msg_SleepInMilliSeconds(1000);

    /* Base interface implementation that will be used cross components */
    cb.getParameterValues     = CcspCcMbi_GetParameterValues;
    cb.setParameterValues     = CcspCcMbi_SetParameterValues;
    cb.setCommit              = CcspCcMbi_SetCommit;
    cb.setParameterAttributes = CcspCcMbi_SetParameterAttributes;
    cb.getParameterAttributes = CcspCcMbi_GetParameterAttributes;
    cb.AddTblRow              = CcspCcMbi_AddTblRow;
    cb.DeleteTblRow           = CcspCcMbi_DeleteTblRow;
    cb.getParameterNames      = CcspCcMbi_GetParameterNames;
    cb.currentSessionIDSignal = CcspCcMbi_CurrentSessionIdSignal;

    /* Base interface implementation that will only be used by pnm */
    cb.initialize             = ssp_WifiMbi_Initialize;
    cb.finalize               = ssp_WifiMbi_Finalize;
    cb.freeResources          = ssp_WifiMbi_FreeResources;
    cb.busCheck               = ssp_WifiMbi_Buscheck;
    cb.getHealth              = ssp_WifiMbi_GetHealth;

    CcspBaseIf_SetCallback(bus_handle, &cb);


    /* Register service callback functions */
    returnStatus =
        CCSP_Message_Bus_Register_Path
            (
                bus_handle,
                path,
                CcspPandM_path_message_func,
                bus_handle
            );

    if ( returnStatus != CCSP_Message_Bus_OK )
    {
        CcspTraceError((" !!! CCSP_Message_Bus_Register_Path ERROR returnStatus: %ld\n!!!\n", returnStatus));

        return returnStatus;
    }


    /* Register event/signal */
    returnStatus = 
        CcspBaseIf_Register_Event
            (
                bus_handle,
                0,
                "currentSessionIDSignal"
            );

    if ( returnStatus != CCSP_Message_Bus_OK )
    {
        CcspTraceError((" !!! CCSP_Message_Bus_Register_Event: CurrentSessionIDSignal ERROR returnStatus: %ld!!!\n", returnStatus));

        return returnStatus;
    }

    return ANSC_STATUS_SUCCESS;
}

DBusHandlerResult
CcspPandM_path_message_func
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    )
{
    CCSP_MESSAGE_BUS_INFO *bus_info =(CCSP_MESSAGE_BUS_INFO *) user_data;
    const char *interface = dbus_message_get_interface(message);
    const char *method   = dbus_message_get_member(message);
    DBusMessage *reply;
    reply = dbus_message_new_method_return (message);
    if (reply == NULL)
    {
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return CcspBaseIf_base_path_message_func
               (
                   conn,
                   message,
                   reply,
                   interface,
                   method,
                   bus_info
               );
}

#if 0
static DBusHandlerResult
ssp_WifiMbi_EventCallback
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    )
{
    const char *interface = dbus_message_get_interface(message);
    const char *method    = dbus_message_get_member(message);

    /* TODO */
    printf("ssp_WifiMbi_EventCallback %s %s \n", interface , method);

    return DBUS_HANDLER_RESULT_HANDLED;

}
#endif

#if 0
static DBusHandlerResult
path_message_func 
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    )
{
    CCSP_MESSAGE_BUS_INFO *bus_info =(CCSP_MESSAGE_BUS_INFO *) user_data;
    CCSP_Base_Func_CB* func = (CCSP_Base_Func_CB*)bus_info->CcspBaseIf_func;
    const char *interface = dbus_message_get_interface(message);
    const char *method   = dbus_message_get_member(message);
    DBusMessage *reply;
//        char tmp[4098];

    CcspTraceDebug(("!!! interface: %s, method: %s !!!\n", interface, method));

    if ( g_bActive != TRUE )
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED; /* Should be try again here */
    }

    CcspTraceDebug(("!!! Ready to handle message...\n"));

    reply = dbus_message_new_method_return (message);
    if (reply == NULL)
    {
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if(!strcmp("org.freedesktop.DBus.Introspectable", interface)  && !strcmp(method, "Introspect"))
    {

        if ( !dbus_message_append_args (reply, DBUS_TYPE_STRING, &Base_Introspect_msg, DBUS_TYPE_INVALID))
//        if ( !dbus_message_append_args (reply, DBUS_TYPE_STRING, &CR_Introspect_msg, DBUS_TYPE_INVALID))
            printf ("No memory\n");

        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;

    }
    
//    printf("dbus_message_is_method_call %d\n", UserGetTickInMilliSeconds2());
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("initialize", method) )
    {
        DBusMessageIter iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;

        result = func->initialize(NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("finalize", method) )
    {
        DBusMessageIter iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;

        result = func->finalize(NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("freeResources", method) )
    {
        DBusMessageIter iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;
        dbus_int32_t priority ;
        

        dbus_message_iter_init (message, &iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_INT32)
        {
            dbus_message_iter_get_basic (&iter, &priority);
        }


        result = func->freeResources(priority, NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("busCheck", method) )
    {
        DBusMessageIter iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;

        result = func->busCheck(NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("setParameterValues", method) && func->setParameterValues)
    {
        DBusMessageIter iter;
        DBusMessageIter array_iter;
        DBusMessageIter struct_iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;
        dbus_int32_t sessionId ;
        dbus_uint32_t writeID ;
        int param_size;
        parameterValStruct_t * parameterVal = 0;
        dbus_bool commit;

        dbus_message_iter_init (message, &iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_INT32)
        {
            dbus_message_iter_get_basic (&iter, &sessionId);
        }
        dbus_message_iter_next (&iter);

        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_UINT32)
        {
            dbus_message_iter_get_basic (&iter, &writeID);
        }
        dbus_message_iter_next (&iter);

        DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, 0);
        param_size = 0;
        do
        {
            int type = dbus_message_iter_get_arg_type (&array_iter);

            if (type == DBUS_TYPE_INVALID)
                break;
            param_size = param_size + 1;
        }
        while (dbus_message_iter_next (&array_iter));

        if(param_size)
        {
            parameterVal = bus_info->mallocfunc(param_size*sizeof(parameterValStruct_t ));
            memset(parameterVal, 0, param_size*sizeof(parameterValStruct_t ));
            DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, parameterVal);
        }

        int i;
        for(i = 0; i < param_size; i++)
        {

            DBUS_MESSAGE_ITER_RECURSE_SRV(&array_iter, &struct_iter , DBUS_TYPE_STRUCT, parameterVal);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_STRING)
            {
                parameterVal[i].parameterName = NULL;
                dbus_message_iter_get_basic (&struct_iter, &parameterVal[i].parameterName);
            }
            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_STRING)
            {
                parameterVal[i].parameterValue = NULL;
                dbus_message_iter_get_basic (&struct_iter, &parameterVal[i].parameterValue);
            }
            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_INT32)
            {
                dbus_message_iter_get_basic (&struct_iter, &parameterVal[i].type);
            }

            dbus_message_iter_next (&array_iter);
        }
        dbus_message_iter_next (&iter); //pass size
        dbus_message_iter_next (&iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_BOOLEAN)
        {
            dbus_message_iter_get_basic (&iter, &commit);
        }

        char *invalidParameterName = 0;
        result = func->setParameterValues(sessionId, writeID, parameterVal, param_size, commit,&invalidParameterName, NULL );
        
        bus_info->freefunc(parameterVal);
        bus_info->freefunc(invalidParameterName);

        dbus_message_iter_init_append (reply, &iter);

        DBUS_MESSAGE_APPEND_STRING (&iter, invalidParameterName);
        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("setCommit", method) && func->setCommit)
    {
        DBusMessageIter iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;
        dbus_int32_t sessionId ;
        dbus_uint32_t writeID ;
        dbus_bool commit;

        dbus_message_iter_init (message, &iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_INT32)
        {
            dbus_message_iter_get_basic (&iter, &sessionId);
        }
        dbus_message_iter_next (&iter);

        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_UINT32)
        {
            dbus_message_iter_get_basic (&iter, &writeID);
        }

        dbus_message_iter_next (&iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_BOOLEAN)
        {
            dbus_message_iter_get_basic (&iter, &commit);
        }


        result = func->setCommit(sessionId, writeID, commit, NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("getParameterValues", method) && func->getParameterValues)
    {
        DBusMessageIter iter;
        DBusMessageIter array_iter;
        DBusMessageIter struct_iter;
        dbus_int32_t tmp ;
        int ret;
        dbus_int32_t result ;
        int param_size;
        char ** parameterNames = 0;

        dbus_message_iter_init (message, &iter);
        DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, 0);
        param_size = 0;
        do
        {
            int type = dbus_message_iter_get_arg_type (&array_iter);

            if (type == DBUS_TYPE_INVALID)
                break;
            param_size = param_size + 1;
        }
        while (dbus_message_iter_next (&array_iter));

        if(param_size)
        {
            parameterNames = bus_info->mallocfunc(param_size*sizeof(char *));
            memset(parameterNames, 0, param_size*sizeof(char *));
        }
		DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, parameterNames);
        int i;
        for(i = 0; i < param_size; i++)
        {
            if(dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
            {
                parameterNames[i] = NULL;
                dbus_message_iter_get_basic (&array_iter, &parameterNames[i]);
            }
            dbus_message_iter_next (&array_iter);
        }

        parameterValStruct_t **val = 0;
        int size = 0;

        result = func->getParameterValues(parameterNames,param_size, &size, &val, NULL);
        bus_info->freefunc(parameterNames);

        dbus_message_iter_init_append (reply, &iter);

        ret = dbus_message_iter_open_container (&iter,
                                                DBUS_TYPE_ARRAY,
                                                "(ssi)",
                                                &array_iter);
        if(result == CCSP_SUCCESS)
        {

            int i;
            for(i = 0; i < size; i++)
            {
                dbus_message_iter_open_container (&array_iter,
                                                  DBUS_TYPE_STRUCT,
                                                  "ssi",
                                                  &struct_iter);

                DBUS_MESSAGE_APPEND_STRING (&struct_iter, val[i]->parameterName);

                DBUS_MESSAGE_APPEND_STRING (&struct_iter, val[i]->parameterValue);
                tmp = val[i]->type;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_INT32, &tmp);

                dbus_message_iter_close_container (&array_iter,
                                                   &struct_iter);
            }
        }

        ret = dbus_message_iter_close_container (&iter,
                &array_iter);


        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        free_parameterValStruct_t(bus_info, size, val);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("setParameterAttributes", method) && func->setParameterAttributes)
    {
        DBusMessageIter iter;
        DBusMessageIter array_iter;
        DBusMessageIter struct_iter;
        dbus_int32_t tmp ;
        dbus_uint32_t utmp ;
        dbus_int32_t sessionId ;
        dbus_int32_t result ;
        int param_size;
        parameterAttributeStruct_t * parameterAttribute = 0;

        dbus_message_iter_init (message, &iter);

        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_INT32)
        {
            dbus_message_iter_get_basic (&iter, &sessionId);
        }
        dbus_message_iter_next (&iter);

        DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, 0);
        param_size = 0;
        do
        {
            int type = dbus_message_iter_get_arg_type (&array_iter);

            if (type == DBUS_TYPE_INVALID)
                break;
            param_size = param_size + 1;
        }
        while (dbus_message_iter_next (&array_iter));

        DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, 0);
        if(param_size)
        {
            parameterAttribute = bus_info->mallocfunc(param_size*sizeof(parameterAttributeStruct_t));
            memset(parameterAttribute, 0, param_size*sizeof(parameterAttributeStruct_t));
        }
        int i;
        for(i = 0; i < param_size; i++)
        {

            DBUS_MESSAGE_ITER_RECURSE_SRV(&array_iter, &struct_iter , DBUS_TYPE_STRUCT, parameterAttribute);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_STRING)
            {
                parameterAttribute[i].parameterName = NULL;
                dbus_message_iter_get_basic (&struct_iter, &parameterAttribute[i].parameterName);
            }
            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_BOOLEAN)
            {
                dbus_message_iter_get_basic (&struct_iter, &parameterAttribute[i].notificationChanged);
            }
            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_BOOLEAN)
            {
                dbus_message_iter_get_basic (&struct_iter, &parameterAttribute[i].notification);
            }
            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_INT32)
            {
                dbus_message_iter_get_basic (&struct_iter, &tmp);
                parameterAttribute[i].access = tmp;
            }

            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_BOOLEAN)
            {
                dbus_message_iter_get_basic (&struct_iter, &parameterAttribute[i].accessControlChanged);
            }

            dbus_message_iter_next (&struct_iter);
            if(dbus_message_iter_get_arg_type (&struct_iter) == DBUS_TYPE_UINT32)
            {
                dbus_message_iter_get_basic (&struct_iter, &utmp);
                parameterAttribute[i].accessControlBitmask = utmp;
            }

            dbus_message_iter_next (&array_iter);
        }

        result = func->setParameterAttributes(sessionId, parameterAttribute ,param_size, NULL);
        bus_info->freefunc(parameterAttribute);

        dbus_message_iter_init_append (reply, &iter);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("getParameterAttributes", method) && func->getParameterAttributes)
    {
        DBusMessageIter iter;
        DBusMessageIter array_iter;
        DBusMessageIter struct_iter;
        dbus_int32_t tmp ;
        dbus_uint32_t utmp ;
        dbus_bool_t btmp ;
        int ret;
        dbus_int32_t result ;
        int param_size;
        char ** parameterNames = 0;
        parameterAttributeStruct_t **val = 0;

        dbus_message_iter_init (message, &iter);
        DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, 0);
        param_size = 0;
        do
        {
            int type = dbus_message_iter_get_arg_type (&array_iter);

            if (type == DBUS_TYPE_INVALID)
                break;
            param_size = param_size + 1;
        }
        while (dbus_message_iter_next (&array_iter));

        if(param_size)
        {
            parameterNames = bus_info->mallocfunc(param_size*sizeof(char *));
            memset(parameterNames, 0, param_size*sizeof(char *));
        }
        DBUS_MESSAGE_ITER_RECURSE_SRV(&iter, &array_iter , DBUS_TYPE_ARRAY, parameterNames);
        int i;
        for(i = 0; i < param_size; i++)
        {
            if(dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
            {
                parameterNames[i] = NULL;
                dbus_message_iter_get_basic (&array_iter, &parameterNames[i]);
            }
            dbus_message_iter_next (&array_iter);
        }

        int size = 0;

        result = func->getParameterAttributes(parameterNames,param_size, &size, &val, NULL);
        bus_info->freefunc(parameterNames);

        dbus_message_iter_init_append (reply, &iter);

        ret = dbus_message_iter_open_container (&iter,
                                                DBUS_TYPE_ARRAY,
                                                "(sbbibu)",
                                                &array_iter);
        if(result == CCSP_SUCCESS)
        {

            int i;
            for(i = 0; i < size; i++)
            {
                dbus_message_iter_open_container (&array_iter,
                                                  DBUS_TYPE_STRUCT,
                                                  "sbbibu",
                                                  &struct_iter);

                DBUS_MESSAGE_APPEND_STRING (&struct_iter, val[i]->parameterName);

                btmp = val[i]->notificationChanged;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_BOOLEAN, &btmp);
                btmp = val[i]->notification;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_BOOLEAN, &btmp);

                tmp = val[i]->access;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_INT32, &tmp);
                btmp = val[i]->accessControlChanged;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_BOOLEAN, &btmp);
                utmp = val[i]->accessControlBitmask;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_UINT32, &utmp);

                dbus_message_iter_close_container (&array_iter,
                                                   &struct_iter);
            }
        }

        ret = dbus_message_iter_close_container (&iter,
                &array_iter);


        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        free_parameterAttributeStruct_t(bus_info, size, val);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("AddTblRow", method) && func->AddTblRow)
    {
        DBusMessageIter iter;
        int instanceNumber ;
        dbus_int32_t result ;
        dbus_int32_t tmp ;
        dbus_int32_t sessionId ;
        char * str;

        dbus_message_iter_init (message, &iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_INT32)
        {
            dbus_message_iter_get_basic (&iter, &sessionId);
        }
        dbus_message_iter_next (&iter);

        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_STRING)
        {
            dbus_message_iter_get_basic (&iter, &str);
        }


        result = func->AddTblRow(sessionId, str, &instanceNumber, NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = instanceNumber;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);

        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
            
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("DeleteTblRow", method) && func->DeleteTblRow)
    {
        DBusMessageIter iter;
        dbus_int32_t tmp ;
        dbus_int32_t result ;
        dbus_int32_t sessionId ;
        char * str;
        int  instanceNumber;
        

        dbus_message_iter_init (message, &iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_INT32)
        {
            dbus_message_iter_get_basic (&iter, &sessionId);
        }
        dbus_message_iter_next (&iter);

        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_STRING)
        {
            dbus_message_iter_get_basic (&iter, &str);
        }


        result = func->DeleteTblRow(sessionId, str , &instanceNumber, NULL);

        dbus_message_iter_init_append (reply, &iter);

        tmp = instanceNumber;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    
    else if (!strcmp(CCSP_DBUS_INTERFACE_BASE, interface) && !strcmp("getParameterNames", method) && func->getParameterNames)
    {
        DBusMessageIter iter;
        DBusMessageIter array_iter;
        DBusMessageIter struct_iter;
        dbus_int32_t tmp ;
        dbus_bool_t btmp ;
        int ret;
        dbus_int32_t result ;
        int size;
        char * parameterName = 0;
        parameterInfoStruct_t **val = 0;

        dbus_message_iter_init (message, &iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_STRING)
        {
            dbus_message_iter_get_basic (&iter, &parameterName);
        }

        dbus_message_iter_next (&iter);
        if(dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_BOOLEAN)
        {
            dbus_message_iter_get_basic (&iter, &btmp);
        }
        result = func->getParameterNames(parameterName,btmp, &size, &val, NULL);

        dbus_message_iter_init_append (reply, &iter);

        ret = dbus_message_iter_open_container (&iter,
                                                DBUS_TYPE_ARRAY,
                                                "(sb)",
                                                &array_iter);
        if(result == CCSP_SUCCESS)
        {

            int i;
            for(i = 0; i < size; i++)
            {
                dbus_message_iter_open_container (&array_iter,
                                                  DBUS_TYPE_STRUCT,
                                                  "sb",
                                                  &struct_iter);

                DBUS_MESSAGE_APPEND_STRING (&struct_iter, val[i]->parameterName);
                btmp = val[i]->writable;
                ret = dbus_message_iter_append_basic (&struct_iter, DBUS_TYPE_BOOLEAN, &btmp);
                dbus_message_iter_close_container (&array_iter,
                                                   &struct_iter);
            }
        }

        ret = dbus_message_iter_close_container (&iter,
                &array_iter);


        tmp = result;
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &tmp);
        if (!dbus_connection_send (conn, reply, NULL))
            printf ("No memory\n");

        dbus_message_unref (reply);
        free_parameterInfoStruct_t(bus_info, size, val);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
            
    dbus_message_unref (reply);
    reply = dbus_message_new_error (message,
                                    DBUS_ERROR_UNKNOWN_METHOD,
                                    "Unknown method invoked ");

    dbus_connection_send (conn, reply, NULL);
    dbus_message_unref (reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}
#endif
#endif

int
ssp_WifiMbi_Initialize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;
    
    printf("In %s()\n", __FUNCTION__);
    
    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}

int
ssp_WifiMbi_Finalize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    printf("In %s()\n", __FUNCTION__);

    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}


int
ssp_WifiMbi_Buscheck
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    printf("In %s()\n", __FUNCTION__);

    return 0;
}


int
ssp_WifiMbi_FreeResources
    (
        int priority,
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    UNREFERENCED_PARAMETER(priority);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    printf("In %s()\n", __FUNCTION__);

    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}

