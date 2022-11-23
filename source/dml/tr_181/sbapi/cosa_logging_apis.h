/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

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

/**************************************************************************

    module: cosa_logging_apis.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/


#ifndef  _COSA_LOGGING_APIS_H
#define  _COSA_LOGGING_APIS_H

#include "cosa_apis.h"

/*
 *  Dynamic portion of Logging Configuration
 */
struct
_COSA_DML_LOGGING_CONFIG
{
	BOOLEAN 	bFlushAllLogs;
}_struct_pack_;

typedef  struct _COSA_DML_LOGGING_CONFIG COSA_DML_LOGGING_CONFIG,  *PCOSA_DML_LOGGING_CONFIG;

/**********************************************************************
                FUNCTION PROTOTYPES
**********************************************************************/

ANSC_STATUS    
CosaDmlLogging_GetConfiguration(PCOSA_DML_LOGGING_CONFIG pLoggingConfig);

ANSC_STATUS    
CosaDmlLogging_FlushAllLogs();
#endif
