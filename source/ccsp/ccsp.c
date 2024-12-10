/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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

#include <syslog.h>
#include <stdint.h>
#include <stdio.h>
#include "ccsp.h"

/*For RDKB platforms invoking direct CcspCommonLibrary APIs */
#ifdef ONEWIFI_RDKB_CCSP_SUPPORT
extern void init_ccsp();
extern void CcspTraceEmergencyRdkb(char *format, ...);
extern void CcspTraceAlertRdkb(char *format, ...);
extern void CcspTraceCriticalRdkb(char *format, ...);
extern void CcspTraceErrorRdkb(char *format, ...);
extern void CcspTraceWarningRdkb(char *format, ...);
extern void CcspTraceNoticeRdkb(char *format, ...);
extern void CcspTraceInfoRdkb(char *format, ...);
extern void CcspTraceDebugRdkb(char *format, ...);
#else
void init_ccsp()
{

}

void CcspTraceEmergencyRdkb(char *format, ...)
{

}

void CcspTraceAlertRdkb(char *format, ...)
{

}

void CcspTraceCriticalRdkb(char *format, ...)
{

}

void CcspTraceErrorRdkb(char *format, ...)
{

}

void CcspTraceWarningRdkb(char *format, ...)
{

}

void CcspTraceNoticeRdkb(char *format, ...)
{

}

void CcspTraceInfoRdkb(char *format, ...)
{

}

void CcspTraceDebugRdkb(char *format, ...)
{

}

char *psm_get_value_Rdkb(char *recName, char *strValue)
{
    return NULL;
}

int psm_set_value_Rdkb(char *recName, char *strValue)
{
    return 0;
}

int get_partner_id_Rdkb(char *partner_id)
{
    return get_partner_id(partner_id);
}
#endif

void wifi_ccsp_rdkb_init(wifi_ccsp_t *ccsp)
{
    ccsp->desc.init_fn = init_ccsp;
    ccsp->desc.CcspTraceWarningRdkb_fn = CcspTraceWarningRdkb;
    ccsp->desc.CcspTraceEmergencyRdkb_fn = CcspTraceEmergencyRdkb;
    ccsp->desc.CcspTraceCriticalRdkb_fn = CcspTraceCriticalRdkb;
    ccsp->desc.CcspTraceErrorRdkb_fn = CcspTraceErrorRdkb;
    ccsp->desc.CcspTraceAlertRdkb_fn = CcspTraceAlertRdkb;
    ccsp->desc.CcspTraceNoticeRdkb_fn = CcspTraceNoticeRdkb;
    ccsp->desc.CcspTraceInfoRdkb_fn = CcspTraceInfoRdkb;
    ccsp->desc.CcspTraceDebugRdkb_fn = CcspTraceDebugRdkb;
    ccsp->desc.psm_get_value_fn = psm_get_value_Rdkb;
    ccsp->desc.psm_set_value_fn = psm_set_value_Rdkb;
    ccsp->desc.get_partner_id_fn = get_partner_id_Rdkb;
}
