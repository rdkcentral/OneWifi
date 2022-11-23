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

    module: cosa_logging_internal.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

        *  CosaLoggingCreate
        *  CosaLoggingInitialize
        *  CosaLoggingRemove
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

     -------------------------------------------------------------------

    revision:

        29/07/2016    initial revision.

**************************************************************************/

#include "cosa_apis.h"
#include "cosa_logging_internal.h"
#include "plugin_main_apis.h"

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaLoggingCreate
            (
            );

    description:

        This function constructs cosa wifi object and return handle.

    argument:  

    return:     newly created wifi object.

**********************************************************************/

ANSC_HANDLE
CosaLoggingCreate
    (
        VOID
    )
{
    PCOSA_DATAMODEL_LOGGING		   pMyObject    = (PCOSA_DATAMODEL_LOGGING)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_LOGGING)AnscAllocateMemory(sizeof(COSA_DATAMODEL_LOGGING));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = COSA_DATAMODEL_LOGGING_OID;
    pMyObject->Create            = CosaLoggingCreate;
    pMyObject->Remove            = CosaLoggingRemove;
    pMyObject->Initialize        = CosaLoggingInitialize;

    pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaLoggingInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa wifi object and return handle.

    argument:    ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaLoggingInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus   = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_LOGGING         pMyObject      = (PCOSA_DATAMODEL_LOGGING)hThisObject;
    PCOSA_DML_LOGGING				pLogging       = (PCOSA_DML_LOGGING 	    )NULL;
    PCOSA_DML_LOGGING_CONFIG		pLoggingConfig = (PCOSA_DML_LOGGING_CONFIG  )NULL;	

	printf("<%s> Entry\n",__FUNCTION__);

    /* Logging DML - Allocate Memory */
    pLogging = (PCOSA_DML_LOGGING)AnscAllocateMemory( sizeof( COSA_DML_LOGGING ) );

    /* Return fail when allocation fail case */
    if ( NULL == pLogging )
    {
        return ANSC_STATUS_RESOURCES;
    }

    /* Getting Logging Object Configuration */
    memset( pLogging, 0, sizeof( COSA_DML_LOGGING ) );

    /* Logging Configuration - Allocate Memory */
    pLoggingConfig = (PCOSA_DML_LOGGING_CONFIG)AnscAllocateMemory( sizeof( COSA_DML_LOGGING_CONFIG ) );

    /* Return fail when allocation fail case */
    if ( NULL == pLoggingConfig )
    {
		AnscFreeMemory( pLogging );
		return ANSC_STATUS_RESOURCES;
    }

    /* Getting Logging Object Configuration */
    memset( pLoggingConfig, 0, sizeof( COSA_DML_LOGGING_CONFIG ) );

    CosaDmlLogging_GetConfiguration( pLoggingConfig );

    /* Assign allocated address to base configuration */
    pLogging->pLoggingConfig  = pLoggingConfig;
    pMyObject->pLogging 	  = pLogging;

	printf("<%s> Exit\n",__FUNCTION__);

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaLoggingRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa wifi object and return handle.

    argument:    ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/
ANSC_STATUS
CosaLoggingRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_LOGGING         pMyObject      = (PCOSA_DATAMODEL_LOGGING)hThisObject;
    PCOSA_DML_LOGGING				pLogging       = (PCOSA_DML_LOGGING 	    )NULL;

    /* Free Allocated Memory for Logging object */
    pLogging = pMyObject->pLogging;

    if( NULL != pLogging )
    {
        AnscFreeMemory((ANSC_HANDLE)pLogging->pLoggingConfig);
        AnscFreeMemory((ANSC_HANDLE)pLogging);
    }

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}
