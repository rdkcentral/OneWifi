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
