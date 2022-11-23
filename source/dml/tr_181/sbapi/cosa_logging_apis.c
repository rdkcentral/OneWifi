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

    module: cosa_led_apis.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/
#include "cosa_apis.h"
#include "plugin_main_apis.h"
#include "cosa_logging_apis.h"
#include "secure_wrapper.h"
#include <ctype.h>

ANSC_STATUS    
CosaDmlLogging_GetConfiguration(PCOSA_DML_LOGGING_CONFIG pLoggingConfig)
{
    /* Validate received param */
    if( NULL == pLoggingConfig )
    {
        return ANSC_STATUS_FAILURE;
    }

    /* Now Hardcoded */
    pLoggingConfig->bFlushAllLogs = 0;

	printf("<%s> Entry %d\n",__FUNCTION__,pLoggingConfig->bFlushAllLogs);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS    
CosaDmlLogging_FlushAllLogs()
{
    /* Do the FlushLogs Operation */
//	fprintf(stderr,"<%s> Entry\n",__FUNCTION__);
    v_secure_system("/rdklogger/flush_logs.sh &");
    return ANSC_STATUS_SUCCESS;
}
