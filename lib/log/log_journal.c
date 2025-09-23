/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2025 RDK Management
  
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

#include "log.h"

static logger_fn_t logger_journal_log;

void logger_journal_new(logger_t *self)
{
    memset(self, 0, sizeof(*self));

    self->logger_fn = logger_journal_log;
}

static void logger_journal_log(logger_t *self, logger_msg_t *msg)
{
    int syslog_sev = LOG_DEBUG;

    /* Journal uses syslog severity. Translate logger severity to syslog severity */
    switch (msg->lm_severity)
    {
        case LOG_SEVERITY_EMERG:
            syslog_sev = LOG_EMERG;
            break;

        case LOG_SEVERITY_ALERT:
            syslog_sev = LOG_ALERT;
            break;

        case LOG_SEVERITY_CRIT:
            syslog_sev = LOG_CRIT;
            break;

        case LOG_SEVERITY_ERR:
            syslog_sev = LOG_ERR;
            break;

        case LOG_SEVERITY_WARNING:
            syslog_sev = LOG_WARNING;
            break;

        case LOG_SEVERITY_NOTICE:
            syslog_sev = LOG_NOTICE;
            break;

        case LOG_SEVERITY_INFO:
            syslog_sev = LOG_INFO;
            break;

        default:
            break;
    }

#if defined(CONFIG_LOG_USE_PREFIX)
    sd_journal_print(syslog_sev, "%s %s: %s", CONFIG_LOG_PREFIX, msg->lm_tag, msg->lm_text);
#else
    sd_journal_print(syslog_sev, "%s: %s", msg->lm_tag, msg->lm_text);
#endif
}
