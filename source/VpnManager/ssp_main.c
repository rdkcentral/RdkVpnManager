/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 Deutsche Telekom AG
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

#include "ssp_internal.h"
#include "ssp_global.h"
#include "ssp_messagebus_interface.h"
#include "syscfg/syscfg.h"
#include "breakpad_wrapper.h"
#include "ccsp_dm_api.h"
#include "execinfo.h"

#define DEBUG_INI_NAME  "/etc/debug.ini"

char                                        g_Subsystem[32]         = {0};
extern char*                                pComponentName;
extern ANSC_HANDLE                          bus_handle;

volatile unsigned int                       VPNMANAGER_RDKLogLevel  = (unsigned int)CCSP_TRACE_LEVEL_INFO;
volatile BOOL                               VPNMANAGER_RDKLogEnable = TRUE;

/*
 * Reads a LogAgent parameter over the CCSP message bus.
 * Returns the parameter value, or -1 when it could not be retrieved.
 */
int GetLogInfo(ANSC_HANDLE bus_handle, char *Subsystem, char *pParameterName)
{
    char                        dst_pathname_cr[64] = {0};
    componentStruct_t**         ppComponents        = NULL;
    parameterValStruct_t**      ppParameterVal      = NULL;
    char*                       pParamNames[1];
    int                         compSize            = 0;
    int                         valSize             = 0;
    int                         value               = -1;
    int                         ret                 = 0;

    if ((Subsystem == NULL) || (pParameterName == NULL))
    {
        return -1;
    }

    snprintf(dst_pathname_cr, sizeof(dst_pathname_cr), "%s%s", Subsystem, CCSP_DBUS_INTERFACE_CR);

    ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle,
                                                      dst_pathname_cr,
                                                      pParameterName,
                                                      Subsystem,
                                                      &ppComponents,
                                                      &compSize);
    if ((ret != CCSP_SUCCESS) || (compSize < 1))
    {
        return -1;
    }

    pParamNames[0] = pParameterName;

    ret = CcspBaseIf_getParameterValues(bus_handle,
                                        ppComponents[0]->componentName,
                                        ppComponents[0]->dbusPath,
                                        pParamNames,
                                        1,
                                        &valSize,
                                        &ppParameterVal);

    if ((ret == CCSP_SUCCESS) && (valSize >= 1) && (ppParameterVal[0]->parameterValue != NULL))
    {
        if (strcmp(ppParameterVal[0]->parameterValue, "true") == 0)
        {
            value = 1;
        }
        else if (strcmp(ppParameterVal[0]->parameterValue, "false") == 0)
        {
            value = 0;
        }
        else
        {
            value = atoi(ppParameterVal[0]->parameterValue);
        }
    }

    if (ppParameterVal != NULL)
    {
        free_parameterValStruct_t(bus_handle, valSize, ppParameterVal);
    }

    free_componentStruct_t(bus_handle, compSize, ppComponents);

    return value;
}

#if defined(_ANSC_LINUX)
static void daemonize(void) 
{
    switch (fork())
    {
        case 0:
            break;
        case -1:{
            // Error
            CcspTraceInfo(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
                            errno)));
		
            exit(0);
            break;}
        default:
            _exit(0);
    }

    if (setsid() < 0) 
    {
        CcspTraceInfo(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
        exit(0);
    }

#ifndef  _DEBUG
    int fd;

    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
#endif
}

static int  cmd_dispatch(int  command)
{
    switch ( command )
    {
        case    'e' :

#ifdef _ANSC_LINUX
            CcspTraceInfo(("Connect to bus daemon...\n"));
            {
                char                            CName[256];

                if ( g_Subsystem[0] != 0 )
                {
                    sprintf(CName, "%s%s", g_Subsystem, RDK_COMPONENT_ID_VPN_MANAGER);
                }
                else
                {
                    sprintf(CName, "%s", RDK_COMPONENT_ID_VPN_MANAGER);
                }

                ssp_Mbi_MessageBusEngage
                    ( 
                     CName,
                     CCSP_MSG_BUS_CFG,
                     RDK_COMPONENT_PATH_VPN_MANAGER
                    );
            }
#endif

            ssp_create();
            ssp_engage();

            break;

        case    'm':

            AnscPrintComponentMemoryTable(pComponentName);

            break;

        case    't':

            AnscTraceMemoryTable();

            break;

        case    'c':

            ssp_cancel();

            break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
    void* tracePtrs[100];
    char** funcNames = NULL;
    int i, count = 0;

    count = backtrace( tracePtrs, 100 );
    backtrace_symbols_fd( tracePtrs, count, 2 );

    funcNames = backtrace_symbols( tracePtrs, count );

    if ( funcNames )
    {
        // Print the stack trace
        for( i = 0; i < count; i++ )
            printf("%s\n", funcNames[i] );

        // Free the string pointers
        free( funcNames );
    }
#endif
#endif
}

void sig_handler(int sig)
{
  
    if ( sig == SIGINT )
    {
        signal(SIGINT, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 ) 
    {
        signal(SIGUSR1, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGUSR1 received!\n"));

    }
    else if ( sig == SIGUSR2 ) 
    {
       signal(SIGUSR2, sig_handler); /* reset it to this function */ 
       CcspTraceInfo(("SIGUSR2 received!\n"));

    }
    else if ( sig == SIGCHLD ) 
    {
        signal(SIGCHLD, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGCHLD received!\n"));

    }
    else if ( sig == SIGPIPE ) 
    {
        signal(SIGPIPE, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGPIPE received!\n"));
    }
    else if ( sig == SIGALRM ) 
    {
        int logInfo;

        signal(SIGALRM, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGALRM received!\n"));

        logInfo = GetLogInfo(bus_handle, "eRT.", "Device.LogAgent.X_RDKCENTRAL-COM_VpnManager_LoggerEnable");
        if (logInfo >= 0)
        {
            VPNMANAGER_RDKLogEnable = (logInfo != 0) ? TRUE : FALSE;
        }

        logInfo = GetLogInfo(bus_handle, "eRT.", "Device.LogAgent.X_RDKCENTRAL-COM_VpnManager_LogLevel");
        if (logInfo >= 0)
        {
            VPNMANAGER_RDKLogLevel = (unsigned int)logInfo;
        }
    }
    else 
    {
        /* get stack trace first */
        _print_stack_backtrace();
        CcspTraceInfo(("Signal %d received, exiting!\n", sig));

        exit(0);
    }

}
#endif

int main(int argc, char* argv[])
{
    BOOL                bRunAsDaemon = TRUE;
    int                 idx = 0;
    int                 ind = -1;
    int                 cmdChar = 0;
    int                 err;
    char                *subSys = NULL;

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif
    rdk_logger_init("/etc/debug.ini");
    syscfg_init();

    for(idx = 1; idx < argc; idx++)
    {
        if((strcmp(argv[idx], "-subsys") == 0))
        {
            if((idx + 1) < argc) 
            {
                AnscCopyString(g_Subsystem, argv[idx+1]);
            }
            else
            {
                CcspTraceError(("parameter after -subsys is missing"));

            }
        }
        else if ( strcmp(argv[idx], "-c") == 0 )
        {
            bRunAsDaemon = FALSE;
        }
    }

    pComponentName          = RDK_COMPONENT_NAME_VPN_MANAGER;

#if defined(_ANSC_LINUX)
    if ( bRunAsDaemon ) 
        daemonize();


#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#else
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
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
#endif

    cmd_dispatch('e');
    syscfg_init();

#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif

    system("touch /tmp/vpnmanager_initialized");

    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
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

    ssp_cancel();
    return 0;

}
