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

#ifndef  _PLUGIN_MAIN_APIS_H
#define  _PLUGIN_MAIN_APIS_H

#include <stdio.h>
#include "ansc_debug_wrapper_base.h"
#include "ansc_common_structures.h"
#include "ansc_status.h"
#include "cosa_plugin_api.h" 
#include "ssp_global.h"

typedef  ANSC_HANDLE
(*PFN_DM_CREATE)
    (
        VOID
    );

typedef  ANSC_STATUS
(*PFN_DM_REMOVE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DM_INITIALIZE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef enum
_COSA_DML_WIREGUARD_TUNNEL_STATUS
{
    COSA_DML_WIREGUARD_TUNNEL_STATUS_DISABLED   = 0,
    COSA_DML_WIREGUARD_TUNNEL_STATUS_ENABLED    = 1,
    COSA_DML_WIREGUARD_TUNNEL_STATUS_ERROR      = 2,
}
COSA_DML_WIREGUARD_TUNNEL_STATUS;

typedef enum
_DML_VPN_IF_CFG_STATUS
{
    DML_VPN_IF_CFG_STATUS_DISABLED   = 0,
    DML_VPN_IF_CFG_STATUS_ENABLED    = 1,
    DML_VPN_IF_CFG_STATUS_ERROR      = 2,
}
DML_VPN_IF_CFG_STATUS;

typedef  struct _DML_VPN_IF_CFG
{
    BOOLEAN                         Enable;
    DML_VPN_IF_CFG_STATUS           Status;
    char                            LocalIP[45];
    char                            PublicKey[64];
    char                            Subnet[64];
}
DML_VPN_IF_CFG,  *PDML_VPN_IF_CFG;

#define MAX_WIREGUARD_TU              5

typedef enum
_COSA_DML_WIREGUARD_TUNNEL_CHANGE_FLAG
{
    WIREGUARDTU_CF_ENABLE         = 0x01<<0,
    WIREGUARDTU_CF_PSKENABLE      = 0x01<<1,
    WIREGUARDTU_CF_PRESHAREDKEY   = 0x01<<2,
    WIREGUARDTU_CF_PEERPUBKEY     = 0x01<<3,
    WIREGUARDTU_CF_REMEP          = 0x01<<4,
    WIREGUARDTU_CF_REMOTEIP       = 0x01<<5,
    WIREGUARDTU_CF_REMPORT        = 0x01<6,
}
COSA_DML_WIREGUARD_TUNNEL_CHANGE_FLAG;

typedef struct
_COSA_DML_WIREGUARD_TUNNEL
{
    ULONG                                 InstanceNumber;
    COSA_DML_WIREGUARD_TUNNEL_CHANGE_FLAG ChangeFlag;
    COSA_DML_WIREGUARD_TUNNEL_STATUS      Status;
    BOOL                                  Enable;
    BOOL                                  PSKEnable;
    char                                  PreSharedKey[64];
    char                                  PeerPublicKey[64];
    char                                  RemoteEndPoint[64];
    char                                  RemoteIP[64];
    ULONG                                 RemotePort;
}
COSA_DML_WIREGUARD_TUNNEL, *PDML_VPN_TUN_CFG;

#define  BASE_CONTENT                                                                       \
    /* start of object class content */                                                     \
    ULONG                           Oid;                                                    \
    ANSC_HANDLE                     hSbContext;                                             \
    PFN_DM_CREATE                   Create;                                                 \
    PFN_DM_REMOVE                   Remove;                                                 \
    PFN_DM_INITIALIZE               Initialize;                                             \


#define BACKEND_MANAGER_CLASS_CONTENT                                                      \
        PDML_VPN_IF_CFG            pVpnConfig;                                             \
        ANSC_HANDLE                  hTWIREGUARD;                                          \
        PCOSA_PLUGIN_INFO hCosaPluginInfo;

typedef  struct
_BACKEND_MANAGER_OBJECT
{
    BASE_CONTENT
    BACKEND_MANAGER_CLASS_CONTENT
}
BACKEND_MANAGER_OBJECT, *PBACKEND_MANAGER_OBJECT;

/* The OID for all objects s*/
#define DATAMODEL_BASE_OID                                 0
#define COSA_DATAMODEL_WIREGUARD_OID                       5

extern COSAGetParamValueByPathNameProc       g_GetParamValueByPathNameProc;
extern COSASetParamValueByPathNameProc       g_SetParamValueByPathNameProc;
extern COSAGetParamValueStringProc           g_GetParamValueString;
extern COSAGetParamValueUlongProc            g_GetParamValueUlong;
extern COSAGetParamValueIntProc              g_GetParamValueInt;
extern COSAGetParamValueBoolProc             g_GetParamValueBool;
extern COSASetParamValueStringProc           g_SetParamValueString;
extern COSASetParamValueUlongProc            g_SetParamValueUlong;
extern COSASetParamValueIntProc              g_SetParamValueInt;
extern COSASetParamValueBoolProc             g_SetParamValueBool;
extern COSAGetInstanceNumbersProc            g_GetInstanceNumbers;

extern COSAValidateHierarchyInterfaceProc    g_ValidateInterface;
extern COSAGetHandleProc                     g_GetRegistryRootFolder;
extern COSAGetInstanceNumberByIndexProc      g_GetInstanceNumberByIndex;
extern COSAGetHandleProc                     g_GetMessageBusHandle;
extern COSAGetSubsystemPrefixProc            g_GetSubsystemPrefix;
extern COSAGetInterfaceByNameProc            g_GetInterfaceByName;
extern PCCSP_CCD_INTERFACE                   g_pPnmCcdIf;
extern ANSC_HANDLE                           g_MessageBusHandle;
extern char*                                 g_SubsystemPrefix;
extern COSARegisterCallBackAfterInitDmlProc  g_RegisterCallBackAfterInitDml;

ANSC_HANDLE
BackEndManagerCreate
    (
        VOID
    );

ANSC_STATUS
BackEndManagerInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BackEndManagerRemove
    (
        ANSC_HANDLE                 hThisObject
    );

#endif
