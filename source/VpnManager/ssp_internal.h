/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

#ifndef  _SSP_INTERNAL_H_
#define  _SSP_INTERNAL_H_

#include "plugin_main_apis.h"

#define  RDK_COMPONENT_ID_VPN_MANAGER                      "com.cisco.spvtg.ccsp.vpnmanager"
#define  RDK_COMPONENT_NAME_VPN_MANAGER                    "com.cisco.spvtg.ccsp.vpnmanager"
#define  RDK_COMPONENT_VERSION_VPN_MANAGER                 1
#define  RDK_COMPONENT_PATH_VPN_MANAGER                    "/com/cisco/spvtg/ccsp/vpnmanager"

#define  RDK_COMMON_COMPONENT_HEALTH_Red                   1
#define  RDK_COMMON_COMPONENT_HEALTH_Yellow                2
#define  RDK_COMMON_COMPONENT_HEALTH_Green                 3

#define  RDK_COMMON_COMPONENT_STATE_Initializing           1
#define  RDK_COMMON_COMPONENT_STATE_Running                2
#define  RDK_COMMON_COMPONENT_STATE_Blocked                3
#define  RDK_COMMON_COMPONENT_STATE_Paused                 3

typedef  struct
_COMPONENT_COMMON_VPN_MANAGER 
{
    char*                           Name;
    ULONG                           Version;
    char*                           Author;
    ULONG                           Health;
    ULONG                           State;

    BOOL                            LogEnable;
    ULONG                           LogLevel;

    ULONG                           MemMaxUsage;
    ULONG                           MemMinUsage;
    ULONG                           MemConsumed;

}
COMPONENT_COMMON_VPN_MANAGER, *PCOMPONENT_COMMON_VPN_MANAGER;

#define ComponentCommonDmInit(component_com_vpnmanager)                                          \
        {                                                                                        \
            AnscZeroMemory(component_com_vpnmanager, sizeof(COMPONENT_COMMON_VPN_MANAGER));      \
            component_com_vpnmanager->Name        = NULL;                                        \
            component_com_vpnmanager->Version     = 1;                                           \
            component_com_vpnmanager->Author      = NULL;                                        \
            component_com_vpnmanager->Health      = RDK_COMMON_COMPONENT_HEALTH_Red;             \
            component_com_vpnmanager->State       = RDK_COMMON_COMPONENT_STATE_Running;          \
            if(g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                                      \
                component_com_vpnmanager->LogLevel = (ULONG) g_iTraceLevel;                      \
            component_com_vpnmanager->LogEnable   = TRUE;                                        \
            component_com_vpnmanager->MemMaxUsage = 0;                                           \
            component_com_vpnmanager->MemMinUsage = 0;                                           \
            component_com_vpnmanager->MemConsumed = 0;                                           \
        }

ANSC_STATUS ssp_create();
ANSC_STATUS ssp_engage();
ANSC_STATUS ssp_cancel();

char*
ssp_CcdIfGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    );

char*
ssp_CcdIfGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    );

BOOL
ssp_CcdIfGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    );

ULONG
ssp_CcdIfGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    );

ULONG
ssp_CcdIfGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    );

int 
VpnDmlInit
(
    ULONG                       uMaxVersionSupported,
    void*                       hCosaPlugInfo
);

#endif
