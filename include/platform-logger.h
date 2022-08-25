#if CCSP_COMMON
#include <ccsp_trace.h>
#else
#include "wifi_util.h"
#endif //CCSP_COMMON

#if CCSP_COMMON
#define platform_trace_error(module, format, ...)    CcspTraceError((format, ##__VA_ARGS__))
#define platform_trace_warning(module, format, ...)  CcspTraceWarning((format, ##__VA_ARGS__))
#else
#define platform_trace_error(module, format, ...)    wifi_util_dbg_print(module, format, ##__VA_ARGS__)
#define platform_trace_warning(module, format, ...)  wifi_util_dbg_print(module, format, ##__VA_ARGS__)
#endif //CCSP_COMMON
