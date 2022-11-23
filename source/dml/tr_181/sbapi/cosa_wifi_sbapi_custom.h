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

    module: cosa_wifi_sbapi_custom.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        Following structured customization method, main code remains
        shared across platforms. This custom file defines platform
        specific feature flags or definitions, to tailor the bevahiors
        of the shared code. 

    -------------------------------------------------------------------


    author:

        Ding Hua

    -------------------------------------------------------------------

    revision:

        09/14/2015    initial revision.

**************************************************************************/


#ifndef  _COSA_WIFI_SBAPI_CUSTOM_H
#define  _COSA_WIFI_SBAPI_CUSTOM_H

/**************************************************************************
                            FEATURE FLAGS
**************************************************************************/

#ifdef CISCO_XB3_PLATFORM_CHANGES
#ifdef WIFI_HAL_VERSION_3
#define COSA_DML_WIFI_FEATURE_ResetSsid             0
#endif
#define COSA_DML_WIFI_FEATURE_ResetSsid1            0
#define COSA_DML_WIFI_FEATURE_ResetSsid2            0
#define COSA_DML_WIFI_FEATURE_LoadPsmDefaults       1
            
#else

#ifdef WIFI_HAL_VERSION_3
#define COSA_DML_WIFI_FEATURE_ResetSsid             1
#endif
#define COSA_DML_WIFI_FEATURE_ResetSsid1            1
#define COSA_DML_WIFI_FEATURE_ResetSsid2            1
#define COSA_DML_WIFI_FEATURE_LoadPsmDefaults       0
            
#endif

#endif

