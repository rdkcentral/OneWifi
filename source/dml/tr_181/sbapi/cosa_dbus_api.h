/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

    module: cosa_api.h

        For CCSP SnmpAgent PA

    ---------------------------------------------------------------

    description:

        This header file defines all the api related to dbus message.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        05/08/2012    initial revision.

**********************************************************************/

#ifndef _COSA_API_H
#define _COSA_API_H

#include "ansc_platform.h"
#include "ccsp_message_bus.h"
#include "ccsp_base_api.h"

/* Init and Exit functions for SnmpAgent PA */
BOOL Cosa_Init ();
BOOL Cosa_Shutdown();

/* retrieve the CCSP Component name and path who supports specified name space */
BOOL 
Cosa_FindDestComp
	(
		char*						pNamespace,
		char**						ppDestComponentName, 
		char**						ppDestPath
	);

/* GetParameterValues */
BOOL
Cosa_GetParamValues
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*						paramArray[], 
		int 						uParamSize,
		int* 						puValueSize,
		parameterValStruct_t***  	pppValueArray
	);

/* SetParameterValues */
BOOL 
Cosa_SetParamValuesNoCommit
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		parameterValStruct_t		*val,
		int							size
	);

/* SetCommit */
BOOL 
Cosa_SetCommit
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		BOOL						bSet
	);

/* GetInstanceNums */
BOOL 
Cosa_GetInstanceNums
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*						pObjName,
		unsigned int**              insNumList,
		unsigned int*				insNum
    );

/* add entry in a table */
int 
Cosa_AddEntry
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*					    pTableObj
	);

/* delete an entry */
BOOL 
Cosa_DelEntry
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		char*					    pEntryName
	);


/* Free Parameter Values */
BOOL 
Cosa_FreeParamValues
	(
		int 						uSize,
		parameterValStruct_t**  	ppValueArray
	);

void 
Cosa_BackgroundCommit
	(
		char*	   				    pDestComp,
		char*						pDestPath,
		BOOL						bSet
	);

#endif	/* COSA_API_h */

