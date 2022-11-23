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

#ifndef  _COSA_LOGGING_INTERNAL_H
#define  _COSA_LOGGING_INTERNAL_H
#include "cosa_logging_apis.h"
#include "poam_irepfo_interface.h"
#include "sys_definitions.h"

/* Collection */
typedef  struct
_COSA_DML_LOGGING
{
	PCOSA_DML_LOGGING_CONFIG 		pLoggingConfig;
}
COSA_DML_LOGGING, *PCOSA_DML_LOGGING;

#define  COSA_DATAMODEL_LOGGING_CLASS_CONTENT                                                  \
    /* duplication of the base object class content */                                      \
    COSA_BASE_CONTENT                                                                       \
    /* start of Logging object class content */                                                \
	PCOSA_DML_LOGGING				pLogging;

typedef  struct
_COSA_DATAMODEL_LOGGING                                               
{
	COSA_DATAMODEL_LOGGING_CLASS_CONTENT
}
COSA_DATAMODEL_LOGGING,  *PCOSA_DATAMODEL_LOGGING;

/*
    Standard function declaration 
*/
ANSC_HANDLE
CosaLoggingCreate
    (
        VOID
    );

ANSC_STATUS
CosaLoggingInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaLoggingRemove
    (
        ANSC_HANDLE                 hThisObject
    );
#endif 
