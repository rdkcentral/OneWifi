/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdbool.h>
#include <syslog.h>

#include "log.h"

static logger_fn_t logger_syslog_log;

bool logger_syslog_new(logger_t *self)
{
    /* Open syslog facilities */
    openlog(log_get_name(), LOG_NDELAY|LOG_PID, LOG_USER);

    memset(self, 0, sizeof(*self));

    self->logger_fn = logger_syslog_log;

    return true;
}

void logger_syslog_log(logger_t *self, logger_msg_t *msg)
{
    UNREFERENCED_PARAMETER(self);
    int syslog_sev = LOG_DEBUG;

    /* Translate logger severity to syslog severity */
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
    syslog(syslog_sev, "%s %s: %s", CONFIG_LOG_PREFIX, msg->lm_tag, msg->lm_text);
#else
    syslog(syslog_sev, "%s: %s", msg->lm_tag, msg->lm_text);
#endif
}
