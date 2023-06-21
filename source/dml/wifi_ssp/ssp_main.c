/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

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

#ifdef __GNUC__
#if (!defined _BUILD_ANDROID) && (!defined _NO_EXECINFO_H_)
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "ccsp_WifiLog_wrapper.h"
#include "syscfg/syscfg.h"
#include "telemetry_busmessage_sender.h"
#include "secure_wrapper.h"

#if defined (FEATURE_SUPPORT_WEBCONFIG)
#include "webconfig_framework.h"
#endif

#ifdef _ANSC_LINUX
#include <semaphore.h>
#include <fcntl.h>
#endif

#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#include "print_uptime.h"
#include <sys/sysinfo.h>
#include "ssp_main.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#define DEBUG_INI_NAME  "/etc/debug.ini"
#include "syscfg/syscfg.h"
#include "cap.h"
static cap_user appcaps;

PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController      = NULL;
PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm  = NULL;
char                            g_Subsystem[32]         = {0};
PCCSP_COMPONENT_CFG             gpWifiStartCfg           = NULL;
PCCSP_FC_CONTEXT                pWifiFcContext           = (PCCSP_FC_CONTEXT           )NULL;
PCCSP_CCD_INTERFACE             pWifiCcdIf               = (PCCSP_CCD_INTERFACE        )NULL;
PCCC_MBI_INTERFACE              pWifiMbiIf               = (PCCC_MBI_INTERFACE         )NULL;
BOOL                            g_bActive               = FALSE;
int gChannelSwitchingCount = 0;

#ifdef _ANSC_LINUX
    extern sem_t *sem;
#endif

void* getSyscfgLogLevel( void *arg );

#if defined(_COSA_INTEL_USG_ATOM_)
void _get_shell_output(char * cmd, char * out, int len)
{
    FILE * fp;
    char   buf[256] = {0};
    fp = popen(cmd, "r");
    if (fp)
    {
        while( fgets(buf, sizeof(buf), fp) )
        {
            buf[strcspn(buf, "\r\n")] = 0; 
            if( buf[0] != '\0' ) 
            {
                strncpy(out, buf, len-1);
                break;
            }
        }
        pclose(fp);        
    }
}
#endif

void* getSyscfgLogLevel( void *arg )
{

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    pthread_detach(pthread_self());
	UNREFERENCED_PARAMETER(arg);
#if defined(_COSA_INTEL_USG_ATOM_) && !defined (_XB6_PRODUCT_REQ_)
    #define DATA_SIZE 1024
    FILE *fp1;
    char buf[DATA_SIZE] = {0};
    char *urlPtr = NULL;
    fp1 = fopen("/etc/device.properties", "r");
    if (fp1 == NULL) {
        CcspTraceError(("Error opening properties file! \n"));
        return FALSE;
    }

    CcspTraceInfo(("Searching for ARM ARP IP\n"));

    while (fgets(buf, DATA_SIZE, fp1) != NULL) {
           if (strstr(buf, "ARM_ARPING_IP") != NULL) {
            buf[strcspn(buf, "\r\n")] = 0; // Strip off any carriage returns

            // grab URL from string
            urlPtr = strstr(buf, "=");
            urlPtr++;
            break;
        }
    }
    if (fclose(fp1) != 0) {
        CcspTraceError(("Error closing properties file! \n"));
    }

    if (urlPtr != NULL && urlPtr[0] != 0 && strlen(urlPtr) > 0)
    {
        CcspTraceInfo(("Reported an ARM IP of %s \n", urlPtr));
/*
        char rpcCmd[128];
        char out[8];
        memset(out, 0, sizeof(out));
        sprintf(rpcCmd, "/usr/bin/rpcclient %s \"syscfg get X_RDKCENTRAL-COM_LoggerEnable\" | grep -v \"RPC\"", urlPtr);
        _get_shell_output(rpcCmd, out, sizeof(out));
        if( NULL != out )
        {
            RDKLogEnable = (BOOL)atoi(out);
        }
        memset(out, 0, sizeof(out));
        sprintf(rpcCmd, "/usr/bin/rpcclient %s \"syscfg get X_RDKCENTRAL-COM_LogLevel\" | grep -v \"RPC\"", urlPtr);
        _get_shell_output(rpcCmd, out, sizeof(out));
        if( NULL != out )
        {
            RDKLogLevel = (ULONG )atoi(out);
        }
        memset(out, 0, sizeof(out));
        sprintf(rpcCmd, "/usr/bin/rpcclient %s \"syscfg get X_RDKCENTRAL-COM_WiFi_LogLevel\" | grep -v \"RPC\"", urlPtr);
        _get_shell_output(rpcCmd, out, sizeof(out));
        if( NULL != out )
        {
            WiFi_RDKLogLevel = (ULONG)atoi(out);
        }
        memset(out, 0, sizeof(out));
        sprintf(rpcCmd, "/usr/bin/rpcclient %s \"syscfg get X_RDKCENTRAL-COM_WiFi_LoggerEnable\" | grep -v \"RPC\"", urlPtr);
        _get_shell_output(rpcCmd, out, sizeof(out));
        if( NULL != out )
        {
            WiFi_RDKLogEnable = (BOOL)atoi(out);
        }
        CcspTraceInfo(("WIFI_DBG:-------Log Info values from arm RDKLogEnable:%d,RDKLogLevel:%u,WiFi_RDKLogLevel:%u,WiFi_RDKLogEnable:%d\n",RDKLogEnable,RDKLogLevel,WiFi_RDKLogLevel, WiFi_RDKLogEnable ));
*/
    } 
#else
    syscfg_init();
/*
    CcspTraceInfo(("WIFI_DBG:-------Read Log Info\n"));
    char buffer[5] = {0};
    if( 0 == syscfg_get( NULL, "X_RDKCENTRAL-COM_LoggerEnable" , buffer, sizeof( buffer ) ) &&  ( buffer[0] != '\0' ) )
    {
        RDKLogEnable = (BOOL)atoi(buffer);
    }
    memset(buffer, 0, sizeof(buffer));
    if( 0 == syscfg_get( NULL, "X_RDKCENTRAL-COM_LogLevel" , buffer, sizeof( buffer ) ) &&  ( buffer[0] != '\0' ) )
    {
        RDKLogLevel = (ULONG )atoi(buffer);
    }
    memset(buffer, 0, sizeof(buffer));
    if( 0 == syscfg_get( NULL, "X_RDKCENTRAL-COM_WiFi_LogLevel" , buffer, sizeof( buffer ) ) &&  ( buffer[0] != '\0' ) )
    {
        WiFi_RDKLogLevel = (ULONG)atoi(buffer);
    }
    memset(buffer, 0, sizeof(buffer));
    if( 0 == syscfg_get( NULL, "X_RDKCENTRAL-COM_WiFi_LoggerEnable" , buffer, sizeof( buffer ) ) &&  ( buffer[0] != '\0' ) )
    {
        WiFi_RDKLogEnable = (BOOL)atoi(buffer);
    }
    CcspTraceInfo(("WIFI_DBG:-------Log Info values RDKLogEnable:%d,RDKLogLevel:%u,WiFi_RDKLogLevel:%u,WiFi_RDKLogEnable:%d\n",RDKLogEnable,RDKLogLevel,WiFi_RDKLogLevel, WiFi_RDKLogEnable ));
*/
#endif
    return NULL;
}
int  cmd_dispatch(int  command)
{
    char*                           pParamNames[]      = {"Device.X_CISCO_COM_DDNS."};
    parameterValStruct_t**          ppReturnVal        = NULL;
    int                             ulReturnValCount   = 0;
    int                             i                  = 0;

    switch ( command )
    {
            case	'e' :

#ifdef _ANSC_LINUX
                CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];

                if ( g_Subsystem[0] != 0 )
                {
                    _ansc_sprintf(CName, "%s%s", g_Subsystem, gpWifiStartCfg->ComponentId);
                }
                else
                {
                    _ansc_sprintf(CName, "%s", gpWifiStartCfg->ComponentId);
                }

                ssp_WifiMbi_MessageBusEngage
                    ( 
                        CName,
                        CCSP_MSG_BUS_CFG,
                        gpWifiStartCfg->DbusPath
                    );
            }

#endif

                ssp_create_wifi(gpWifiStartCfg);
                ssp_engage_wifi(gpWifiStartCfg);

                g_bActive = TRUE;

                CcspTraceInfo(("Wifi Agent loaded successfully...\n"));

            break;

            case    'r' :

            CcspCcMbi_GetParameterValues
                (
                    DSLH_MPA_ACCESS_CONTROL_ACS,
                    pParamNames,
                    1,
                    &ulReturnValCount,
                    &ppReturnVal,
                    NULL
                );



            for ( i = 0; i < ulReturnValCount; i++ )
            {
                CcspTraceWarning(("Parameter %d name: %s value: %s \n", i+1, ppReturnVal[i]->parameterName, ppReturnVal[i]->parameterValue));
            }

			break;

        case    'm':
                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':
                AnscTraceMemoryTable();

                break;

        case    'c':
                ssp_cancel_wifi(gpWifiStartCfg);

                break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#if (!defined _BUILD_ANDROID) && (!defined _NO_EXECINFO_H_)
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, 2 );

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
		wifi_util_dbg_print(WIFI_MGR,"%s\n", funcNames[i] );

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}

#if defined(_ANSC_LINUX)
void sig_handler(int sig)
{

    if ( sig == SIGINT ) {
    	signal(SIGINT, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 ) {
    	signal(SIGUSR1, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGUSR1 received!\n"));
	#ifndef DISABLE_LOGAGENT
/*
	RDKLogEnable = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LoggerEnable");
	RDKLogLevel = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LogLevel");
	WiFi_RDKLogLevel = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_WiFi_LogLevel");
	WiFi_RDKLogEnable = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_WiFi_LoggerEnable");
*/
	#endif
    }
    else if ( sig == SIGUSR2 ) {
    	CcspTraceInfo(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) {
    	signal(SIGCHLD, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) {
    	signal(SIGPIPE, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGPIPE received!\n"));
    }
	else if ( sig == SIGALRM ) {

    	signal(SIGALRM, sig_handler); /* reset it to this function */
    	CcspTraceInfo(("SIGALRM received!\n"));
		gChannelSwitchingCount = 0;
    }
    else if ( sig == SIGTERM )
    {
        CcspTraceInfo(("SIGTERM received!\n"));
        exit(0);
    }
    else if ( sig == SIGKILL )
    {
        CcspTraceInfo(("SIGKILL received!\n"));
        exit(0);
    }
    else {
    	/* get stack trace first */
    	_print_stack_backtrace();
    	CcspTraceInfo(("Signal %d received, exiting!\n", sig));
    	exit(0);
    }
}

#ifndef INCLUDE_BREAKPAD
static int is_core_dump_opened(void)
{
    FILE *fp;
    char path[256];
    char line[1024];
    char *start, *tok, *sp;
#define TITLE   "Max core file size"

    snprintf(path, sizeof(path), "/proc/%d/limits", getpid());
    if ((fp = fopen(path, "rb")) == NULL)
        return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if ((start = strstr(line, TITLE)) == NULL)
            continue;

        start += strlen(TITLE);
        if ((tok = strtok_r(start, " \t\r\n", &sp)) == NULL)
            break;

        fclose(fp);

        if (strcmp(tok, "0") == 0)
            return 0;
        else
            return 1;
    }

    fclose(fp);
    return 0;
}
#endif

#endif

bool drop_root()
{
  char buf[8] = {'\0'};
  appcaps.caps = NULL;
  appcaps.user_name = NULL;
  bool retval = false;
  syscfg_init();
  syscfg_get( NULL, "NonRootSupport", buf, sizeof(buf));
  if(buf != NULL) {
     if(strncmp(buf, "true", strlen("true")) == 0) {
        if(init_capability() != NULL) {
           if(drop_root_caps(&appcaps) != -1) {
              if(update_process_caps(&appcaps) != -1) {
                 read_capability(&appcaps);
                 retval = true;
              }
           }
        }
     }
  }
  return retval;
}
void lnf_ssid_updateBootLogTime()
{
    BOOL apIsUp = FALSE;
    wifi_vap_info_t *vapInfo = NULL;
    int count = 0;
    UINT apIndex;
    UINT total_vap_index = getTotalNumberVAPs();
    wifi_mgr_t *mgr = get_wifimgr_obj();

    do {
        count++;
        for (UINT index = 0; index < total_vap_index; index++) {
            apIndex = VAP_INDEX(mgr->hal_cap, index);
            if(isVapLnf(apIndex)) {
                vapInfo =  get_wifidb_vap_parameters(apIndex);
                CcspTraceWarning(("%s-%d LnF SSID %d   \n",__FUNCTION__, __LINE__, apIndex));
                if(vapInfo != NULL) {
                    if( vapInfo->u.bss_info.enabled == TRUE ) {
                        apIsUp = TRUE;
                        break;
                    }
                }
            }
        }
        if (apIsUp) {
            struct sysinfo l_sSysInfo;
            sysinfo(&l_sSysInfo);
            char uptime[16] = {0};
            snprintf(uptime, sizeof(uptime), "%ld", l_sSysInfo.uptime);
            print_uptime("boot_to_LnF_SSID_uptime", NULL, uptime);
            break;
        }
    } while (count <= 10);
}
int ssp_main(int argc, char* argv[])
{
    int                             cmdChar            = 0;
    BOOL                            bRunAsDaemon       = TRUE;
    int                             idx                = 0;
    FILE                           *fd                 = NULL;
    DmErr_t                         err;
    char                            *subSys            = NULL;
    extern ANSC_HANDLE bus_handle;

wifi_util_dbg_print(WIFI_MGR,"%s:%d: Inside ssp_main\n", __func__, __LINE__);
    /*
     *  Load the start configuration
     */
#if defined(FEATURE_SUPPORT_RDKLOG)
        RDK_LOGGER_INIT();
wifi_util_dbg_print(WIFI_MGR,"%s:%d: RDK_LOGGER_INIT done!\n", __func__, __LINE__);
#endif

 wifi_util_dbg_print(WIFI_MGR,"%s:%d: Allocating resources for start configuration!\n", __func__, __LINE__);

    gpWifiStartCfg = (PCCSP_COMPONENT_CFG)AnscAllocateMemory(sizeof(CCSP_COMPONENT_CFG));
    
    if ( gpWifiStartCfg )
    {
 wifi_util_dbg_print(WIFI_MGR,"%s:%d: Loading configuration!\n", __func__, __LINE__);
        CcspComponentLoadCfg(CCSP_WIFI_START_CFG_FILE, gpWifiStartCfg);
 wifi_util_dbg_print(WIFI_MGR,"%s:%d: Loaded configuration!\n", __func__, __LINE__);
    }
    else
    {
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: Insufficient resources for start configuration, quit!\n", __func__, __LINE__);
        return -1;
    }
    wifi_util_dbg_print(WIFI_MGR,"%s:%d: Allocated resources for start configuration!\n", __func__, __LINE__);
    
    /* Set the global pComponentName */
    pComponentName = gpWifiStartCfg->ComponentName;

#if defined(_DEBUG) && defined(_COSA_SIM_)
    AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);
    wifi_util_dbg_print(WIFI_MGR,"%s:%d: AnscSetTraceLevel done!\n", __func__, __LINE__);
#endif

    wifi_util_dbg_print(WIFI_MGR,"%s:%d: Argc is %d\n", __func__, __LINE__, argc);
    for (idx = 0; idx < argc; idx++)
    {
        if ( (strcmp(argv[idx], "-subsys") == 0) )
        {
            /* Coverity Fix */
            if ((idx+1) < argc)
            {
                AnscCopyString(g_Subsystem, argv[idx+1]);
                CcspTraceWarning(("\nSubsystem is %s\n", g_Subsystem));
                wifi_util_dbg_print(WIFI_MGR,"%s:%d: Subsystem is %s\n", __func__, __LINE__, g_Subsystem);
            }
        }
        else if ( strcmp(argv[idx], "-c" ) == 0 )
        {
            bRunAsDaemon = FALSE;
        }
    }

#if  defined(_ANSC_WINDOWSNT)

    AnscStartupSocketWrapper(NULL);

    display_info();

    cmd_dispatch('e');

    while ( cmdChar != 'q' )
    {
        cmdChar = getchar();

        cmd_dispatch(cmdChar);
    }
#elif defined(_ANSC_LINUX)
#if 0
  #if defined (_CBR_PRODUCT_REQ_) || (defined (_XB6_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_)) //Applicable only for TCHCBR, TCHXB6 & TCHXB7
    if(!drop_root())
    {
        CcspTraceError(("drop_root function failed!\n"));
        gain_root_privilege();
    }
  #endif
#endif//ONE_WIFI

/* Legacy Devices Like XB3 have systemd on the side with WiFi Agent, but don't use Service Files */
#if defined(ENABLE_SD_NOTIFY) && (defined(_XB6_PRODUCT_REQ_) || defined(_COSA_BCM_MIPS_)|| defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_))
    char cmd[1024]          = {0};
    /*This is used for systemd */
    fd = fopen("/var/tmp/OneWifi.pid", "w+");
    if ( !fd )
    {
        CcspTraceWarning(("Create /var/tmp/OneWifi.pid error. \n"));
        return 1;
    }
    else
    {
        sprintf(cmd, "%d", getpid());
        fputs(cmd, fd);
        fclose(fd);
    }
#endif

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
    signal(SIGUSR1, sig_handler);
#else

    if (is_core_dump_opened())
    {
        signal(SIGUSR1, sig_handler);
        CcspTraceWarning(("Core dump is opened, do not catch signal\n"));
    }
    else
    {
        CcspTraceWarning(("Core dump is NOT opened, backtrace if possible\n"));
    	signal(SIGTERM, sig_handler);
    	signal(SIGINT, sig_handler);
    	signal(SIGUSR1, sig_handler);
    	signal(SIGUSR2, sig_handler);

    	signal(SIGSEGV, sig_handler);
    	signal(SIGBUS, sig_handler);
    	signal(SIGKILL, sig_handler);
    	signal(SIGFPE, sig_handler);
    	signal(SIGILL, sig_handler);
    	signal(SIGQUIT, sig_handler);
    	signal(SIGHUP, sig_handler);
	signal(SIGALRM, sig_handler);
    }

#endif
  
    t2_init("ccsp-wifi-agent");
  
    /* Default handling of SIGCHLD signals */
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
    {
        CcspTraceError(("ERROR: Couldn't set SIGCHLD handler!\n"));
    }
    cmd_dispatch('e');
    // printf("Calling Docsis\n");

    // ICC_init();
    // DocsisIf_StartDocsisManager();
    /* For XB3, there are  4 rpc calls to arm to get loglevel values from syscfg
     * this takes around 7 to 10 seconds, so we are moving this to a thread */
    pthread_t updateSyscfgLogLevel;
    pthread_create(&updateSyscfgLogLevel, NULL, &getSyscfgLogLevel, NULL);

#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif
    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);
    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));
        exit(1);
    }

#if defined (FEATURE_SUPPORT_WEBCONFIG)
    /* Inform Webconfig framework if component is coming after crash */
    check_component_crash("/tmp/wifi_initialized");
#endif

    /* For some reason, touching the file via system command was not working consistently.
     * We'll fopen the file and dump in a value */
    if ((fd = fopen ("/tmp/wifi_initialized", "w+")) != NULL) {
        fprintf(fd,"1");
        fclose(fd);
    }

    printf("Entering Wifi loop\n");
    struct sysinfo l_sSysInfo;
    sysinfo(&l_sSysInfo);
    char uptime[16] = {0};
    snprintf(uptime, sizeof(uptime), "%ld", l_sSysInfo.uptime);
    print_uptime("boot_to_WIFI_uptime",NULL, uptime);
    lnf_ssid_updateBootLogTime();
    CcspTraceWarning(("RDKB_SYSTEM_BOOT_UP_LOG : Entering Wifi loop \n"));
    if ( bRunAsDaemon )
    {
        sem_post (sem);
        sem_close(sem);
        ssp_loop();
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            cmd_dispatch(cmdChar);
        }
    }
#endif

    err = Cdm_Term();
    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
        exit(1);
    }

    if ( g_bActive )
    {
        ssp_cancel_wifi(gpWifiStartCfg);

        g_bActive = FALSE;
    }

    if ( gpWifiStartCfg )
    {
       AnscFreeMemory(gpWifiStartCfg);
    }

    return 0;
}

void *ssp_func(void *arg)
{
	int ret;
        char *args[] = {"-subsys", "eRT."};
//	wifi_ssp_t *ssp = (wifi_ssp_t *)arg;
        wifi_util_dbg_print(WIFI_MGR,"%s:%d: Calling ssp_main\n", __func__, __LINE__);

	prctl(PR_SET_NAME,  __func__, 0, 0, 0);

	ret = ssp_main(2, args);
        wifi_util_dbg_print(WIFI_MGR,"%s:%d:ssp_main returned %d\n", __func__, __LINE__,ret);
	return NULL;
}

int start_dml_main(wifi_ssp_t *ssp)
{

    if (pthread_create(&ssp->tid, NULL, ssp_func, ssp) != 0) {
        wifi_util_error_print(WIFI_MGR,"%s:%d:ssp_main create failed\n", __func__, __LINE__);
        return -1;
    }

    wifi_util_info_print(WIFI_MGR,"%s:%d:ssp_main thread started\n", __func__, __LINE__);

    return 0;
}

