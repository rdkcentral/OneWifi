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


#include "ansc_platform.h"
#include "cosa_dbus_api.h"
#include "dslh_definitions_database.h"
#include "safec_lib_common.h"

/* Cosa specific stuff */
#ifdef _COSA_SIM_
/* for PC simu only, Out/$Board/snmp/snmpd and Out/$Board/ccsp_msg.cfg */
#define CCSP_AGENT_PA_SUBSYSTEM		""
#else
#define CCSP_AGENT_PA_SUBSYSTEM		"eRT."
#endif

void * bus_handle           = NULL;
char   dst_pathname_cr[64]  =  {0};

/* Init COSA */
BOOL Cosa_Init(void * pbus_handle)
{
#ifdef _COSA_SIM_
//#if 1
    snprintf(dst_pathname_cr, sizeof(dst_pathname_cr), "com.cisco.spvtg.ccsp.CR");
#else
    /*
     *  Hardcoding "eRT." is just a workaround. We need to feed the subsystem
     *  info into this initialization routine.
     */
    errno_t rc = -1;
    rc = sprintf_s(dst_pathname_cr, sizeof(dst_pathname_cr), "%s%s", CCSP_AGENT_PA_SUBSYSTEM, CCSP_DBUS_INTERFACE_CR);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
#endif
    bus_handle = pbus_handle;
    return TRUE;
}

/* Exit COSA */
BOOL Cosa_Shutdown(void)
{
    return TRUE;
}


/* retrieve the CCSP Component name and path who supports specified name space */
BOOL Cosa_FindDestComp(char* pObjName,char** ppDestComponentName, char** ppDestPath)
{
	int                         ret;
	int                         size = 0;
	componentStruct_t **        ppComponents = NULL;

	ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle,
				dst_pathname_cr,
				pObjName,
				"",        /* prefix */
				&ppComponents,
				&size);

	if ( ret == CCSP_SUCCESS && size >= 1)
	{
		*ppDestComponentName = AnscCloneString(ppComponents[0]->componentName);
		*ppDestPath    = AnscCloneString(ppComponents[0]->dbusPath);

        free_componentStruct_t(bus_handle, size, ppComponents);
		return  TRUE;
	}
	else
	{
		return  FALSE;
	}
}

/* GetParameterValues */
BOOL Cosa_GetParamValues
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char**						pParamArray, 
		int 						uParamSize,
		int* 						puValueSize,
		parameterValStruct_t***  	pppValueArray
	)
{
		int							iStatus = 0;
		iStatus = 
			CcspBaseIf_getParameterValues
				(
					bus_handle,
					pDestComp,
					pDestPath,
					pParamArray,
					uParamSize,
					puValueSize,
					pppValueArray
				);

		return iStatus == CCSP_SUCCESS;
}

/* SetParameterValues */
BOOL Cosa_SetParamValuesNoCommit
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		parameterValStruct_t		*val,
		int							size
	)
{
	int                        iStatus     = 0;
	char                       *faultParam = NULL;
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;

    iStatus = CcspBaseIf_setParameterValues
				(
					bus_handle, 
					pDestComp, 
					pDestPath,
					0, DSLH_MPA_ACCESS_CONTROL_CLI,   /* session id and write id */
					val, 
					size, 
					FALSE,   /* no commit */
					&faultParam
				);	

    if (iStatus != CCSP_SUCCESS && faultParam)
    {
		AnscTraceError(("Error:Failed to SetValue for param '%s'\n", faultParam));
		bus_info->freefunc(faultParam);
	}

	return iStatus == CCSP_SUCCESS;
}

/* SetCommit */
BOOL Cosa_SetCommit
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		BOOL						bSet
	)
{
	int								iReturn = 0;

	iReturn = 
		CcspBaseIf_setCommit
		(
			bus_handle,
			pDestComp,
			pDestPath,
			0,
			DSLH_MPA_ACCESS_CONTROL_CLI,
			bSet
		);

	return iReturn == CCSP_SUCCESS;

}

/* GetInstanceNums */
BOOL 
Cosa_GetInstanceNums
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*						pObjName,
		unsigned int**              pInsNumList,
		unsigned int*				pInsNum
    )
{
	int								iStatus = TRUE;

    iStatus = 
		CcspBaseIf_GetNextLevelInstances
		(
			bus_handle, 
			pDestComp,
			pDestPath,
			pObjName,
			pInsNum,
			pInsNumList
		);

	if( iStatus != CCSP_SUCCESS)
	{
		AnscTraceWarning(("Failed to find the instances of table:'%s'\n", pObjName));
	}

	return iStatus == CCSP_SUCCESS;
}

/* add entry in a table */
int 
Cosa_AddEntry
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*					    pTableName
	)
{
	int								iReturn  = 0;
	int								insNum   = 0;

    iReturn =
			CcspBaseIf_AddTblRow
			(
                bus_handle,
                pDestComp,
                pDestPath,
                0,          /* session id */
                pTableName,
                &insNum
			);
    
    if ( iReturn != CCSP_SUCCESS )
    {
        return 0;
    }
    else
    {
        return insNum;
    }
}

/* delete an entry */
BOOL 
Cosa_DelEntry
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*					    pEntryName
	)
{
	int								iReturn  = 0;

    iReturn =
		CcspBaseIf_DeleteTblRow
		(
                bus_handle,
                pDestComp,
                pDestPath,
                0,          /* session id */
                pEntryName
		);


	return iReturn == CCSP_SUCCESS;
}


/* Free Parameter Values */
BOOL 
Cosa_FreeParamValues
	(
		int 						uSize,
		parameterValStruct_t**  	ppValueArray
	)
{
	free_parameterValStruct_t(bus_handle, uSize, ppValueArray);
    
    return TRUE;
}

typedef struct _commitParams {
		char*	   				    pDestComp;
		char*						pDestPath;
		BOOL						bSet;
} COMMIT_PARAMS, *PCOMMIT_PARAMS;

static void* commitThread(void* arg) {
    PCOMMIT_PARAMS params = (PCOMMIT_PARAMS) arg;
    Cosa_SetCommit(params->pDestComp, params->pDestPath, params->bSet);
    free(arg);
    return NULL;
}

void Cosa_BackgroundCommit
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		BOOL						bSet
	)
{
    PCOMMIT_PARAMS params = malloc(sizeof(COMMIT_PARAMS));
    if (!params) {
        printf("!!!!!Failed snmp background commit malloc\n");
        return;
    }
    params->pDestComp = pDestComp;
    params->pDestPath = pDestPath;
    params->bSet = bSet;
    AnscCreateTask(commitThread, USER_DEFAULT_TASK_STACK_SIZE, USER_DEFAULT_TASK_PRIORITY, (void*)params, "SNMPWifiCustomCommitThread");
//    AnscSpawnTask(commitThread, (void*)params, "SNMPBackgroundCommitThread");
}
