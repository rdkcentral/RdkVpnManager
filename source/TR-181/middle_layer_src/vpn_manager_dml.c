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

#include "plugin_main_apis.h"
#include "ssp_global.h"
#include "vpn_manager_dml_apis.h"
#include "vpn_manager_dml.h"
#include "vpn_manager_internal.h"
#include "syscfg/syscfg.h"
#include "secure_wrapper.h"

extern PBACKEND_MANAGER_OBJECT           g_pBEManager;

/**********************************************************************
    function: WireGuard_GetParamBoolValue
    description:
        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.
**********************************************************************/
BOOL
WireGuard_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL != pMyObject)
    {
        if (AnscEqualString(ParamName, "Enable", TRUE))
        {
            *pBool = pMyObject->Enable;
            return TRUE;
        }
    }

    return FALSE;
}

/**********************************************************************
    function: WireGuard_SetParamBoolValue
    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.
**********************************************************************/
BOOL
WireGuard_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL != pMyObject)
    {
        if (AnscEqualString(ParamName, "Enable", TRUE))
        {
             pMyObject->Enable = bValue;
             return TRUE;
        }
    }

    return FALSE;
}


/**********************************************************************  
    function: WireGuard_GetParamStringValue
    description:
        This function is called to retrieve string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;
    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/
ULONG
WireGuard_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;
    
    if (NULL != pMyObject)
    {
        if (AnscEqualString(ParamName, "LocalIP", TRUE))
        {
            snprintf(pValue, *pUlSize, "%s", pMyObject->LocalIP);
            return 0;
        }

        if (AnscEqualString(ParamName, "PublicKey", TRUE))
        {
            WireGuard_GetPublicKey(pMyObject->PublicKey); 
            snprintf(pValue, *pUlSize, "%s", pMyObject->PublicKey);
            return 0;
        }

        if (AnscEqualString(ParamName, "Subnet", TRUE))
        {
            snprintf(pValue, *pUlSize, "%s", pMyObject->Subnet);
            return 0;
        }
    }

    return -1;
}

/**********************************************************************  
    function: WireGuard_SetParamStringValue
    description:
        This function is called to set string parameter value; 
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pString
                The updated string value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL
WireGuard_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL != pMyObject)
    {
        if (AnscEqualString(ParamName, "LocalIP", TRUE))
        {
            snprintf(pMyObject->LocalIP, sizeof(pMyObject->LocalIP), "%s", pString);
            syscfg_set(NULL, "wireguard_localip", pString);
            syscfg_commit();
            return TRUE;
        }
       
        if (AnscEqualString(ParamName, "Subnet", TRUE))
        {
            snprintf(pMyObject->Subnet, sizeof(pMyObject->Subnet), "%s", pString);
            syscfg_set(NULL, "wireguard_subnet", pString);
            syscfg_commit();
            return TRUE;
        }
    }

   return FALSE;
}

/**********************************************************************
    function: WireGuard_GetParamUlongValue
    description:
        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.
**********************************************************************/
BOOL
WireGuard_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )
{
    if (AnscEqualString(ParamName, "Status", TRUE))
    {
        if (CosaDml_WireGuardGetStatus((DML_VPN_IF_CFG_STATUS *)pUlong) != ANSC_STATUS_SUCCESS)
            return FALSE;
	return TRUE;
    }

    return FALSE;
}

BOOL
WireGuard_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL == pMyObject)
    {
        CcspTraceError(("%s %d- Invalid handle, pMyObject is NULL\n", __FUNCTION__, __LINE__));
	return FALSE;
    }

    if (!pMyObject->Enable)
       return TRUE;

    if (strlen(pMyObject->LocalIP) == 0)
    {
        AnscCopyString(pReturnParamName, "LocalIP");
        *puLength = AnscSizeOfString("LocalIP");
        CcspTraceError(("%s- LocalIP is not having valid input!\n",__FUNCTION__));
        return FALSE;
    }

    if (strlen(pMyObject->Subnet) == 0)
    {
        AnscCopyString(pReturnParamName, "Subnet");
        *puLength = AnscSizeOfString("Subnet");
        CcspTraceError(("%s-Subnet is not having valid input!\n",__FUNCTION__));
        return FALSE;
    }

    CcspTraceInfo(("%s -Validate for Enable returning TRUE\n",__FUNCTION__));
    return TRUE;
}


ULONG
WireGuard_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL == pMyObject)
    {
	CcspTraceError(("%s %d- Invalid handle, pMyObject is NULL\n", __FUNCTION__, __LINE__));
        return -1;
    }

    if (!pMyObject->Enable)
    {
        v_secure_system(VPN_CONFIG_SCRIPT " DOWN");
        CcspTraceInfo(("%s-wg0 interface is down\n",__FUNCTION__));
    }
    else
    {
        create_config_file();
        v_secure_system(VPN_CONFIG_SCRIPT " UP");
        CcspTraceInfo(("%s-wg0 interface is up\n",__FUNCTION__));
    }

    return 0;
}

ULONG
WireGuard_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL == pMyObject)
    {
        CcspTraceError(("%s %d- Invalid handle, pMyObject is NULL\n", __FUNCTION__, __LINE__));
        return -1;
    }

    if (pMyObject->Enable)
        pMyObject->Enable = FALSE;

    CcspTraceInfo(("%s-DMs are not set with valid values. Resetting Enable\n",__FUNCTION__));
    return 0;
}

ULONG 
WireGuardTunnel_GetEntryCount 
    (  
        ANSC_HANDLE hInsContext  
    ) 
{
    UNREFERENCED_PARAMETER(hInsContext);
    return CosaDml_WireGuardTunnelGetNumberOfEntries();
}

ANSC_HANDLE 
WireGuardTunnel_GetEntry
    ( 
        ANSC_HANDLE        hInsContext, 
        ULONG              nIndex, 
        ULONG*             pInsNumber 
    ) 
{
    UNREFERENCED_PARAMETER(hInsContext);
    COSA_DATAMODEL_WIREGUARD2           *pMyObject   = (COSA_DATAMODEL_WIREGUARD2 *)g_pBEManager->hTWIREGUARD;

    if (NULL == pMyObject || nIndex >= MAX_WIREGUARD_TU)
        return NULL;

    *pInsNumber = pMyObject->WireGuardTu[nIndex].InstanceNumber;

    return (ANSC_HANDLE)&pMyObject->WireGuardTu[nIndex];
}

BOOL 
WireGuardTunnel_GetParamBoolValue 
    ( 
        ANSC_HANDLE        hInsContext, 
        char*              ParamName, 
        BOOL*              pBool
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL                 *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL != pWireGuardTu)
    {
        if (AnscEqualString(ParamName, "Enable", TRUE))
        {
            *pBool = pWireGuardTu->Enable;
            return TRUE;
        }
   
        if (AnscEqualString(ParamName, "PSKEnable", TRUE))
        {
            *pBool = pWireGuardTu->PSKEnable;
            return TRUE;
        }
    }
     
    return FALSE;
}

BOOL 
WireGuardTunnel_GetParamUlongValue 
    ( 
        ANSC_HANDLE           hInsContext, 
        char*                 ParamName, 
        ULONG*                pUlong
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL != pWireGuardTu)
    {
	ULONG ins = pWireGuardTu->InstanceNumber;

        if (AnscEqualString(ParamName, "Status", TRUE))
        {
            if (CosaDml_WireGuardTunnelGetStatus(ins, (COSA_DML_WIREGUARD_TUNNEL_STATUS *)pUlong) != ANSC_STATUS_SUCCESS)
                return FALSE;
            return TRUE;
        }
   
        if (AnscEqualString(ParamName, "RemotePort", TRUE))
        {
            *pUlong = pWireGuardTu->RemotePort;
            return TRUE;
        }
    }

    return FALSE;
}

ULONG 
WireGuardTunnel_GetParamStringValue 
    ( 
        ANSC_HANDLE            hInsContext, 
        char*                  ParamName, 
        char*                  pValue, 
        ULONG*                 pUlSize 
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL != pWireGuardTu)
    {
        ULONG ins = pWireGuardTu->InstanceNumber;

        if (AnscEqualString(ParamName, "RemoteEndPoint", TRUE))
        {
            snprintf(pValue, *pUlSize, "%s", pWireGuardTu->RemoteEndPoint);
            return 0;
        }

        if (AnscEqualString(ParamName, "RemoteIP", TRUE))
        {
            snprintf(pValue, *pUlSize, "%s", pWireGuardTu->RemoteIP);
            return 0;
        }
  
        if (AnscEqualString(ParamName, "PreSharedKey", TRUE))
        {
            snprintf(pValue, *pUlSize, "%s", pWireGuardTu->PreSharedKey);
            return 0;
        }

        if (AnscEqualString(ParamName, "PeerPublicKey", TRUE))
        {
            snprintf(pValue, *pUlSize, "%s", pWireGuardTu->PeerPublicKey);
            return 0;
        }
    }

    return -1;
}

BOOL 
WireGuardTunnel_SetParamBoolValue 
    (    ANSC_HANDLE         hInsContext, 
         char*               ParamName, 
         BOOL                bValue
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL      *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL != pWireGuardTu)
    {
        if (AnscEqualString(ParamName, "Enable", TRUE))
        {
            pWireGuardTu->Enable = bValue;
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_ENABLE;
            return TRUE;
        }
  
        if (AnscEqualString(ParamName, "PSKEnable", TRUE))
        {
            pWireGuardTu->PSKEnable = bValue;
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_PSKENABLE;
            return TRUE;
        }
    }

    return FALSE;
}

BOOL 
WireGuardTunnel_SetParamStringValue 
    ( 
        ANSC_HANDLE            hInsContext, 
        char*                  ParamName, 
        char*                  strValue 
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL != pWireGuardTu)
    {
        if (AnscEqualString(ParamName, "RemoteEndPoint", TRUE))
        {
            snprintf(pWireGuardTu->RemoteEndPoint, sizeof(pWireGuardTu->RemoteEndPoint), "%s", strValue);
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_REMEP;
            return TRUE;
        }

        if (AnscEqualString(ParamName, "RemoteIP", TRUE))
        {
            snprintf(pWireGuardTu->RemoteIP, sizeof(pWireGuardTu->RemoteIP), "%s", strValue);
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_REMOTEIP;
            return TRUE;
        }

        if (AnscEqualString(ParamName, "PreSharedKey", TRUE))
        {
            snprintf(pWireGuardTu->PreSharedKey, sizeof(pWireGuardTu->PreSharedKey), "%s", strValue);
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_PRESHAREDKEY;
            return TRUE;
        }

        if (AnscEqualString(ParamName, "PeerPublicKey", TRUE))
        {
            snprintf(pWireGuardTu->PeerPublicKey, sizeof(pWireGuardTu->PeerPublicKey), "%s", strValue);
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_PEERPUBKEY;
            return TRUE;
        }
    }

   return FALSE;
}

BOOL 
WireGuardTunnel_SetParamUlongValue 
    ( 
        ANSC_HANDLE           hInsContext, 
        char*                 ParamName, 
        ULONG                 uValue
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL != pWireGuardTu)
    {
        if (AnscEqualString(ParamName, "RemotePort", TRUE))
        {
            pWireGuardTu->RemotePort = uValue;
            pWireGuardTu->ChangeFlag |= WIREGUARDTU_CF_REMPORT;
            return TRUE;
        }
    }

    return FALSE;
}

BOOL 
WireGuardTunnel_Validate 
    ( 
        ANSC_HANDLE          hInsContext, 
        char*                pReturnParamName, 
        ULONG*               puLength 
    )
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL == pWireGuardTu)
    {
        CcspTraceError(("%s %d- Invalid handle, pWireGuardTu is NULL\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    ULONG ins = pWireGuardTu->InstanceNumber;

    if (!pWireGuardTu->Enable)
       return TRUE;

    if (strlen(pWireGuardTu->PeerPublicKey) == 0)
    {
        AnscCopyString(pReturnParamName, "PeerPublicKey");
        *puLength = AnscSizeOfString("PeerPublicKey");
        CcspTraceError(("%s- PeerPublicKey is not valid for tunnel instance:%d \n",__FUNCTION__,ins));
        return FALSE;
    }

    if (strlen(pWireGuardTu->RemoteEndPoint) == 0)
    {
        AnscCopyString(pReturnParamName, "RemoteEndPoint");
        *puLength = AnscSizeOfString("RemoteEndPoint");
        CcspTraceError(("%s-RemoteEndPoint is not valid for tunnel instance:%d \n",__FUNCTION__,ins));
        return FALSE;
    }

    if (strlen(pWireGuardTu->RemoteIP) == 0)
    {
        AnscCopyString(pReturnParamName, "RemoteIP");
        *puLength = AnscSizeOfString("RemoteIP");
        CcspTraceError(("%s-RemoteIP is not valid for tunnel instance:%d \n",__FUNCTION__,ins));
        return FALSE;
    }

    if (pWireGuardTu->RemotePort == 0)
    {
        AnscCopyString(pReturnParamName, "RemotePort");
        *puLength = AnscSizeOfString("RemotePort");
        CcspTraceError(("%s-RemotePort is not valid for tunnel instance:%d \n",__FUNCTION__,ins));
        return FALSE;
    }

    if ((pWireGuardTu->PSKEnable) && (strlen(pWireGuardTu->PreSharedKey) == 0))
    {
        AnscCopyString(pReturnParamName, "PreSharedKey");
        *puLength = AnscSizeOfString("PreSharedKey");
        CcspTraceError(("%s-PreSharedKey is not valid for tunnel instance:%d \n",__FUNCTION__,ins));
        return FALSE;
    }

    return TRUE;
}

ULONG 
WireGuardTunnel_Commit 
    ( 
         ANSC_HANDLE       hInsContext 
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL == pWireGuardTu)
    {
        CcspTraceError(("%s %d- Invalid handle, pWireGuardTu is NULL\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ULONG ins = pWireGuardTu->InstanceNumber;

    if (pWireGuardTu->ChangeFlag == 0)
    return ANSC_STATUS_SUCCESS;

    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_ENABLE)
    {
        if (CosaDml_WireGuardTunnelSetEnable(ins, pWireGuardTu->Enable) != ANSC_STATUS_SUCCESS)
            goto rollback;
    }
   
    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_PSKENABLE)
    {
        if (CosaDml_WireGuardTunnelSetPSKEnable(ins, pWireGuardTu->PSKEnable) != ANSC_STATUS_SUCCESS)
            goto rollback;
    }

    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_REMEP)
    {
        if (CosaDml_WireGuardTunnelSetRemoteEndPoint(ins, pWireGuardTu->RemoteEndPoint) != ANSC_STATUS_SUCCESS)
            goto rollback;
    }
 
    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_REMOTEIP)
    {
        if (CosaDml_WireGuardTunnelSetRemoteIP(ins, pWireGuardTu->RemoteIP) != ANSC_STATUS_SUCCESS)
            goto rollback;
    }

    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_PRESHAREDKEY)
    {
        if (CosaDml_WireGuardTunnelSetPreSharedKey(ins, pWireGuardTu->PreSharedKey) != ANSC_STATUS_SUCCESS)
            goto rollback;
    }

    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_PEERPUBKEY)
    {
         if (CosaDml_WireGuardTunnelSetPeerPublicKey(ins, pWireGuardTu->PeerPublicKey) != ANSC_STATUS_SUCCESS)
           goto rollback;
    }
   
    if (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_REMPORT)
    {
         if (CosaDml_WireGuardTunnelSetRemotePort(ins, pWireGuardTu->RemotePort) != ANSC_STATUS_SUCCESS)
           goto rollback;
    }

    if (pWireGuardTu->Enable || (pWireGuardTu->ChangeFlag & WIREGUARDTU_CF_ENABLE))
    {
	create_config_file();
	v_secure_system(VPN_CONFIG_SCRIPT " SYNC");
        CcspTraceInfo(("%s-applying changes for tunnel instance:%d \n",__FUNCTION__,ins));
    }

    return ANSC_STATUS_SUCCESS;
  
rollback:
    pWireGuardTu->ChangeFlag = 0;
    WireGuardTunnel_Rollback((ANSC_HANDLE)pWireGuardTu);
    return ANSC_STATUS_FAILURE;
}

ULONG 
WireGuardTunnel_Rollback
    ( 
         ANSC_HANDLE           hInsContext
    ) 
{
    COSA_DML_WIREGUARD_TUNNEL       *pWireGuardTu      = (COSA_DML_WIREGUARD_TUNNEL *)hInsContext;

    if (NULL == pWireGuardTu)
    {
        CcspTraceError(("%s %d- Invalid handle, pWireGuardTu is NULL\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    ULONG ins = pWireGuardTu->InstanceNumber;

    pWireGuardTu->Enable = FALSE;

    return ANSC_STATUS_SUCCESS;
}
