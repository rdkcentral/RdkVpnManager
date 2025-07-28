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
#include "syscfg/syscfg.h"
#include "vpn_manager_internal.h"
#include "secure_wrapper.h"

#define WIREGUARD_OBJ_TU                  "wireguard_tunnel_"
#define WIREGUARDTU_PARAM_ENABLE          WIREGUARD_OBJ_TU "%lu_Enable"
#define WIREGUARDTU_PARAM_PSKENABLE       WIREGUARD_OBJ_TU "%lu_PSKEnable"
#define WIREGUARDTU_PARAM_REMEP           WIREGUARD_OBJ_TU "%lu_RemoteEndPoint"
#define WIREGUARDTU_PARAM_REMOTEIP        WIREGUARD_OBJ_TU "%lu_RemoteIP"
#define WIREGUARDTU_PARAM_PRESHAREDKEY    WIREGUARD_OBJ_TU "%lu_PreSharedKey"
#define WIREGUARDTU_PARAM_PEERPUBKEY      WIREGUARD_OBJ_TU "%lu_PeerPublicKey"
#define WIREGUARDTU_PARAM_REMPORT         WIREGUARD_OBJ_TU "%lu_RemotePort"
#define MAX_SIZE                          127
#define MAX_ENTRY                         5
#define SUBNET_MAX_LEN			  16
#define STRING_MAX_LEN                    64
#define VALUE_MAX_LEN                     8
#define FILE_BUF_SIZE                     1026
#define BUF_SIZE                          16

extern PBACKEND_MANAGER_OBJECT           g_pBEManager;

static BOOL g_Wireguard_Enabled;

ANSC_STATUS VpnDmlInitialize()
{
    PDML_VPN_IF_CFG pMyObject = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;

    if (NULL != pMyObject)
    {
        syscfg_init();
        CcspTraceInfo(("syscfg_init done !\n"));

        char value[VALUE_MAX_LEN], string[STRING_MAX_LEN] = {0};
        bzero(value, sizeof(value));

        if (0 == syscfg_get(NULL, "wireguard_enabled", value, sizeof(value)))
        {
            if (1 == atoi(value))
            {
                pMyObject->Enable = TRUE;
            }
            else
            {
                pMyObject->Enable = FALSE;
            }
        }
   
        if (0 == syscfg_get(NULL, "wireguard_localip", string,sizeof(string)))
        {
            strncpy(pMyObject->LocalIP,string,sizeof(pMyObject->LocalIP));
        }
       
        if (0 == syscfg_get(NULL, "wireguard_subnet", string,sizeof(string)))
        {
            strncpy(pMyObject->Subnet,string,sizeof(pMyObject->Subnet));
        }
    }
}

ANSC_STATUS
CosaDml_WireGuardGetStatus(DML_VPN_IF_CFG_STATUS *st)
{
    char buf[FILE_BUF_SIZE] = {0};
    FILE *fp = NULL;

    if (!st)
        return ANSC_STATUS_FAILURE;

    if (!g_pBEManager->pVpnConfig->Enable)
    {
        *st = DML_VPN_IF_CFG_STATUS_DISABLED;
        return ANSC_STATUS_SUCCESS;
    }

    if (fp = popen("wg show", "r"))
    {
        while ( fgets(buf, sizeof(buf), fp)!= NULL )
	{
	    if(strstr(buf,"interface: wg0"))
            {
                *st = DML_VPN_IF_CFG_STATUS_ENABLED;
                pclose(fp);
		CcspTraceInfo(("%s %d - WireGuard status is enabled. \n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_SUCCESS;
	    }
	}
        pclose(fp);
    }

    *st = DML_VPN_IF_CFG_STATUS_ERROR;
    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
CosaDml_WireGuardTunnelGetStatus(ULONG tuIns, COSA_DML_WIREGUARD_TUNNEL_STATUS *st)
{
    char buf[FILE_BUF_SIZE] = {0};
    FILE *fp = NULL;
    ULONG tuIdx = tuIns-1;

    COSA_DATAMODEL_WIREGUARD2 *wireGuard = g_pBEManager->hTWIREGUARD;

    if (!st || !wireGuard)
    {
        CcspTraceError(("%s %d- Invalid handle, Null pointer\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (!g_pBEManager->pVpnConfig->Enable)
    {
        *st = DML_VPN_IF_CFG_STATUS_DISABLED;
        return ANSC_STATUS_SUCCESS;
    }

    if (!wireGuard->WireGuardTu[tuIdx].Enable)
    {
        *st = DML_VPN_IF_CFG_STATUS_DISABLED;
        return ANSC_STATUS_SUCCESS;
    }

    if (0 == strlen(wireGuard->WireGuardTu[tuIdx].PeerPublicKey))
    {
        *st = DML_VPN_IF_CFG_STATUS_ERROR;
        return ANSC_STATUS_SUCCESS;
    }

    if (fp = popen("wg show", "r"))
    {
        while ( fgets(buf, sizeof(buf), fp)!= NULL )
        {
            if(strstr(buf,wireGuard->WireGuardTu[tuIdx].PeerPublicKey))
            {
                *st = DML_VPN_IF_CFG_STATUS_ENABLED;
                pclose(fp);
		CcspTraceInfo(("%s %d - WireGuard Tunnel status is enabled. \n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_SUCCESS;
            }
        }
        pclose(fp);
    }

    *st = DML_VPN_IF_CFG_STATUS_ERROR;
    return ANSC_STATUS_SUCCESS;
}

static int netMastToCIDR(const char *subnet)
{
    uint32_t nmask=0;
    int cidr_suffix=0;

    inet_pton(AF_INET, subnet, &nmask);

    while (nmask)
    {
        cidr_suffix += (nmask & 0x1);
        nmask >>= 1;
    }

    return cidr_suffix;
}

void create_config_file()
{
    PDML_VPN_IF_CFG           pMyObject  = (PDML_VPN_IF_CFG) g_pBEManager->pVpnConfig;
    COSA_DATAMODEL_WIREGUARD2 *wireGuard = g_pBEManager->hTWIREGUARD;

    int i = 0;

    if (NULL == pMyObject || NULL == wireGuard)
    {
        CcspTraceError(("%s %d- Invalid handle, NULL pointer\n", __FUNCTION__, __LINE__));
	return;
    }

    if (!pMyObject->Enable)
    {
	//v_secure_system(VPN_CONFIG_SCRIPT " disable2");
        return;
    }
    else
    {
        CcspTraceInfo(("%s %d - Enabling the WireGuard through the script. \n", __FUNCTION__, __LINE__));
	v_secure_system(VPN_CONFIG_SCRIPT " enable %s %d", pMyObject->LocalIP, netMastToCIDR(pMyObject->Subnet));
	for (i = 0; i < 5; i++)
        {
            PDML_VPN_TUN_CFG pTunnel = &(wireGuard->WireGuardTu[i]);

            if (!pTunnel->Enable)
                continue;

	    CcspTraceInfo(("%s %d - Creating Tunnel through the script. \n", __FUNCTION__, __LINE__));
	    v_secure_system(VPN_CONFIG_SCRIPT " create_tun %s %s %ld %s %s",
                        pTunnel->PeerPublicKey, pTunnel->RemoteEndPoint,
                        pTunnel->RemotePort,pTunnel->RemoteIP, 
			pTunnel->PSKEnable ? pTunnel->PreSharedKey:"\0");
        }
    }
}

ULONG
CosaDml_WireGuardTunnelGetNumberOfEntries(void)
{
    return 5;
}

ANSC_STATUS
CosaDml_WireGuardTunnelFinalize(void)
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelInit(void)
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetEntryByIndex(ULONG ins, COSA_DML_WIREGUARD_TUNNEL *wireguardTu)
{
    if (!wireguardTu)
        return ANSC_STATUS_FAILURE;

    memset(wireguardTu, 0, sizeof(COSA_DML_WIREGUARD_TUNNEL));

    wireguardTu->InstanceNumber = ins;
    //wireguardTu->Enable = TRUE;

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetEnable(ULONG tuIns, BOOL enable)
{
    char syscfg_var[MAX_SIZE +1]={0};
    char value[VALUE_MAX_LEN]= {0};

    snprintf(value, sizeof(value), "%d", enable ? 1 : 0);
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_ENABLE, tuIns);

    syscfg_set(NULL,syscfg_var,value);
    syscfg_commit();   
     
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetPSKEnable(ULONG tuIns, BOOL pskenable)
{
    char syscfg_var[MAX_SIZE +1]={0};
    char value[VALUE_MAX_LEN]= {0};

    snprintf(value, sizeof(value), "%d", pskenable ? 1 : 0);
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PSKENABLE, tuIns);

    syscfg_set(NULL,syscfg_var,value);
    syscfg_commit();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetRemoteEndPoint(ULONG tuIns, const char *endpoint)
{
    char syscfg_var[MAX_SIZE +1]={0};

    if (!endpoint)
        return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMEP, tuIns);

    syscfg_set(NULL,syscfg_var,endpoint);
    syscfg_commit();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetRemoteIP(ULONG tuIns, const char *remoteip)
{
    char syscfg_var[MAX_SIZE +1]={0};

    if (!remoteip)
        return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMOTEIP, tuIns);

    syscfg_set(NULL,syscfg_var,remoteip);
    syscfg_commit();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetPreSharedKey(ULONG tuIns, const char *presharedkey)
{
    char syscfg_var[MAX_SIZE +1]={0};

    if (!presharedkey)
        return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PRESHAREDKEY, tuIns);

    syscfg_set(NULL,syscfg_var,presharedkey);
    syscfg_commit();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetPeerPublicKey(ULONG tuIns, const char *peerpublickey)
{
    char syscfg_var[MAX_SIZE +1]={0};

    if (!peerpublickey)
        return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PEERPUBKEY, tuIns);

    syscfg_set(NULL,syscfg_var,peerpublickey);
    syscfg_commit();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelSetRemotePort(ULONG tuIns, ULONG val)
{
    char syscfg_var[MAX_SIZE +1]={0};
    char buf[BUF_SIZE]={0};

    sprintf(buf, "%d", val);
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMPORT, tuIns);

    syscfg_set(NULL,syscfg_var,buf);
    syscfg_commit();

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WireGuardTunnelDmlInitialize()
{
  
    COSA_DATAMODEL_WIREGUARD2        *pMyObject   = (COSA_DATAMODEL_WIREGUARD2 *)g_pBEManager->hTWIREGUARD;

    ULONG i, tuIns = 0;
    char syscfg_var[MAX_SIZE +1]={0};
    char value[VALUE_MAX_LEN]={0};
    bzero(value, sizeof(value));

    if (NULL == pMyObject)
    {
        CcspTraceError(("%s %d- Invalid handle, pMyObject is NULL\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    for (i = 0; i < MAX_ENTRY; i++)
    {
        tuIns=i+1;
        CosaDml_WireGuardTunnelGetEnable(tuIns, &(pMyObject->WireGuardTu[i].Enable));
        CosaDml_WireGuardTunnelGetPSKEnable(tuIns, &(pMyObject->WireGuardTu[i].PSKEnable));
        CosaDml_WireGuardTunnelGetRemoteEndPoint(tuIns, pMyObject->WireGuardTu[i].RemoteEndPoint, sizeof(pMyObject->WireGuardTu[i].RemoteEndPoint));
        CosaDml_WireGuardTunnelGetRemoteIP(tuIns, pMyObject->WireGuardTu[i].RemoteIP, sizeof(pMyObject->WireGuardTu[i].RemoteIP));
        CosaDml_WireGuardTunnelGetPreSharedKey(tuIns, pMyObject->WireGuardTu[i].PreSharedKey, sizeof(pMyObject->WireGuardTu[i].PreSharedKey));
        CosaDml_WireGuardTunnelGetPeerPublicKey(tuIns, pMyObject->WireGuardTu[i].PeerPublicKey, sizeof(pMyObject->WireGuardTu[i].PeerPublicKey));
        CosaDml_WireGuardTunnelGetRemotePort(tuIns, &(pMyObject->WireGuardTu[i].RemotePort));
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetEnable(ULONG tuIns, BOOL *enable)
{
    if (!enable)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1]={0};
    char value[VALUE_MAX_LEN]={0};

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_ENABLE, tuIns);
    bzero(value, sizeof(value));
    
    if (0 == syscfg_get(NULL,syscfg_var, value, sizeof(value)))
        *enable = (atoi(value) == 1) ? TRUE : FALSE;
      
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetPSKEnable(ULONG tuIns, BOOL *pskenable)
{
   if (!pskenable)
       return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1]={0};
    char value[VALUE_MAX_LEN]={0};

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PSKENABLE, tuIns);
    bzero(value, sizeof(value));

    if (0 == syscfg_get(NULL,syscfg_var, value, sizeof(value)))
        *pskenable = (atoi(value) == 1) ? TRUE : FALSE;

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetRemoteEndPoint(ULONG tuIns, char *eps, ULONG size)
{
    if (!eps)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1], string[STRING_MAX_LEN] = {0};

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMEP, tuIns);
    
    if (0 == syscfg_get(NULL,syscfg_var, string, sizeof(string)))
        strncpy(eps,string,sizeof(string));

    if ((unsigned int)size > strlen(string))
        snprintf(eps, size, "%s", string);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetRemoteIP(ULONG tuIns, char *ip, ULONG size)
{
    if (!ip)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1],string[STRING_MAX_LEN] = {0};
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMOTEIP, tuIns);
    
    if (0 == syscfg_get(NULL,syscfg_var, string, sizeof(string)))
        strncpy(ip,string,sizeof(string)); 

    if ((unsigned int)size > strlen(string))
        snprintf(ip, size, "%s", string);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetPreSharedKey(ULONG tuIns, char *key, ULONG size)
{
    if (!key)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1],string[STRING_MAX_LEN] = {0};
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PRESHAREDKEY, tuIns);
    
    if (0 == syscfg_get(NULL,syscfg_var, string, sizeof(string)))
        strncpy(key,string,sizeof(string));

    if ((unsigned int)size > strlen(string))
        snprintf(key, size, "%s", string);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetPeerPublicKey(ULONG tuIns, char *key, ULONG size)
{
    if (!key)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1],string[STRING_MAX_LEN] = {0};
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PEERPUBKEY, tuIns);
    
    if (0 == syscfg_get(NULL,syscfg_var, string, sizeof(string)))
        strncpy(key,string,sizeof(string));

    if ((unsigned int)size > strlen(string))
        snprintf(key, size, "%s", string);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDml_WireGuardTunnelGetRemotePort(ULONG tuIns, ULONG *val)
{
    if (!val)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1];
    char buf[64];

    memset(buf, 0, sizeof(buf));
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMPORT, tuIns);
      
    if (0 == syscfg_get(NULL,syscfg_var, buf, sizeof(buf)))
        *val = atoi(buf);
      
    return ANSC_STATUS_SUCCESS;
}
