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

#include <ctype.h>
#include "plugin_main_apis.h"
#include "ssp_global.h"
#include "vpn_manager_dml_apis.h"
#include "syscfg/syscfg.h"
#include "vpn_manager_internal.h"
#include "secure_wrapper.h"

#define WIREGUARD_OBJ_TU                  "wireguard_tunnel_"
#define WIREGUARDTU_PARAM_ENABLE          WIREGUARD_OBJ_TU "%lu_Enable"
#define WIREGUARDTU_PARAM_TUNNELNAME      WIREGUARD_OBJ_TU "%lu_TunnelName"
#define WIREGUARDTU_PARAM_PSKENABLE       WIREGUARD_OBJ_TU "%lu_PSKEnable"
#define WIREGUARDTU_PARAM_REMEP           WIREGUARD_OBJ_TU "%lu_RemoteEndPoint"
#define WIREGUARDTU_PARAM_REMOTEIP        WIREGUARD_OBJ_TU "%lu_RemoteIPv4"
#define WIREGUARDTU_PARAM_REMOTEIPV6      WIREGUARD_OBJ_TU "%lu_RemoteIPv6"
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

#define MAX_KEY_LEN   128
#define MAX_EP_LEN    128
#define MAX_LINE_LEN  256
#define SERV_PORT     53280

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
   
        if (0 == syscfg_get(NULL, "wireguard_local_ipv4", string, sizeof(string)))
        {
            strncpy(pMyObject->LocalIP,string,sizeof(pMyObject->LocalIP));
        }
        
	if (0 == syscfg_get(NULL, "wireguard_local_ipv6", string, sizeof(string)))
        {
            strncpy(pMyObject->LocalIPv6,string,sizeof(pMyObject->LocalIPv6));
        }
       
        if (0 == syscfg_get(NULL, "wireguard_subnet", string, sizeof(string)))
        {
            strncpy(pMyObject->Subnet,string,sizeof(pMyObject->Subnet));
        }
       
        if (0 == syscfg_get(NULL, "Wireguard_Port", string, sizeof(string)))
        {
             pMyObject->WireguardPort = atoi(string);
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
    ULONG tuIdx = tuIns-1;
    ULONG remote_port = 0;

    char endpoint[MAX_EP_LEN] = {0};
    char remote_endpoint[MAX_EP_LEN] = {0};
    char port[BUF_SIZE] = {0};
    char syscfg_endpoint[MAX_SIZE +1] = {0};
    char syscfg_remport[MAX_SIZE +1] = {0};
    char line[MAX_LINE_LEN] = {0};
    int  found_peer = 0;
    char key[MAX_KEY_LEN] = {0};
    char cmd[MAX_LINE_LEN] = {0};
   
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
        snprintf(wireGuard->WireGuardTu[tuIdx].RemoteEndPoint, sizeof(wireGuard->WireGuardTu[tuIdx].RemoteEndPoint), "0.0.0.0");
        wireGuard->WireGuardTu[tuIdx].RemotePort = SERV_PORT;
        return ANSC_STATUS_SUCCESS;
    }

    if (0 == strlen(wireGuard->WireGuardTu[tuIdx].PeerPublicKey))
    {
        *st = DML_VPN_IF_CFG_STATUS_ERROR;
        return ANSC_STATUS_SUCCESS;
    }

    snprintf(cmd, sizeof(cmd), "wg show wg0");

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        return ANSC_STATUS_FAILURE;
    }

    while (fgets(line, sizeof(line), fp) != NULL) 
    {
        while (isspace((unsigned char)*line)) memmove(line, line + 1, strlen(line));

        if (strncmp(line, "peer:", 5) == 0) {
            sscanf(line, "peer: %127s", key);

            if (strcmp(key, wireGuard->WireGuardTu[tuIdx].PeerPublicKey) == 0) 
	    {
                found_peer = 1; 
                *st = DML_VPN_IF_CFG_STATUS_ENABLED;
            } 
	    else 
	    {
                found_peer = 0;
            }
        }

        if (found_peer && strncmp(line, "endpoint:", 9) == 0) {
            sscanf(line, "endpoint: %127s", endpoint);
            break ;
	}
    }

    pclose(fp);

    if (endpoint[0] == '\0') {
        CcspTraceInfo(("Peer with public key not found or no endpoint set.\n"));
	return ANSC_STATUS_SUCCESS;
    }

    if (endpoint[0] == '[')
    {
        if (sscanf(endpoint, "[%127[^]]]:%15s", remote_endpoint, port) == 2)
        {
            snprintf(wireGuard->WireGuardTu[tuIdx].RemoteEndPoint, sizeof(wireGuard->WireGuardTu[tuIdx].RemoteEndPoint), "%s", remote_endpoint);
            remote_port = atoi(port);
            wireGuard->WireGuardTu[tuIdx].RemotePort = remote_port;
        }
        else
        {
            CcspTraceWarning(("Invalid IPv6 endpoint format\n"));
        }
    }
    else if (sscanf(endpoint, "%127[^:]:%15s", remote_endpoint, port) == 2)
    {
        snprintf(wireGuard->WireGuardTu[tuIdx].RemoteEndPoint, sizeof(wireGuard->WireGuardTu[tuIdx].RemoteEndPoint), "%s", remote_endpoint);
        remote_port = atoi(port);
        wireGuard->WireGuardTu[tuIdx].RemotePort = remote_port;
    }
    else
    {
        CcspTraceWarning(("Invalid IPv4 endpoint format\n"));
    }

    snprintf(syscfg_endpoint, sizeof(syscfg_endpoint), WIREGUARDTU_PARAM_REMEP, tuIns);
    syscfg_set(NULL,syscfg_endpoint,remote_endpoint);
    snprintf(syscfg_remport, sizeof(syscfg_remport), WIREGUARDTU_PARAM_REMPORT, tuIns);
    syscfg_set(NULL, syscfg_remport, port);
    syscfg_commit();

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
	v_secure_system(VPN_CONFIG_SCRIPT " enable %s %d %s %ld", pMyObject->LocalIP, netMastToCIDR(pMyObject->Subnet), pMyObject->LocalIPv6, pMyObject->WireguardPort);
	for (i = 0; i < 5; i++)
        {
            PDML_VPN_TUN_CFG pTunnel = &(wireGuard->WireGuardTu[i]);

            if (!pTunnel->Enable)
                continue;

	    CcspTraceInfo(("%s %d - Creating Tunnel through the script. \n", __FUNCTION__, __LINE__));
	    v_secure_system(VPN_CONFIG_SCRIPT " create_tun %s %s %ld %s %s %s",
                        pTunnel->PeerPublicKey, pTunnel->RemoteEndPoint,
			pTunnel->RemotePort,pTunnel->RemoteIP,pTunnel->RemoteIPv6,
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
CosaDml_WireGuardTunnelSetRemoteIPv6(ULONG tuIns, const char *remoteipv6)
{
    char syscfg_var[MAX_SIZE +1]={0};

    if (!remoteipv6)
        return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMOTEIPV6, tuIns);

    syscfg_set(NULL,syscfg_var,remoteipv6);
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

ANSC_STATUS
CosaDml_WireGuardTunnelSetTunnelName(ULONG tuIns, const char *tunnelname)
{
    char syscfg_var[MAX_SIZE +1]={0};

    if (!tunnelname)
        return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_TUNNELNAME, tuIns);

    syscfg_set(NULL,syscfg_var,tunnelname);
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
        CosaDml_WireGuardTunnelGetTunnelName(tuIns, pMyObject->WireGuardTu[i].TunnelName, sizeof(pMyObject->WireGuardTu[i].TunnelName));
        CosaDml_WireGuardTunnelGetPSKEnable(tuIns, &(pMyObject->WireGuardTu[i].PSKEnable));
        CosaDml_WireGuardTunnelGetRemoteEndPoint(tuIns, pMyObject->WireGuardTu[i].RemoteEndPoint, sizeof(pMyObject->WireGuardTu[i].RemoteEndPoint));
        CosaDml_WireGuardTunnelGetRemoteIP(tuIns, pMyObject->WireGuardTu[i].RemoteIP, sizeof(pMyObject->WireGuardTu[i].RemoteIP));
        CosaDml_WireGuardTunnelGetRemoteIPv6(tuIns, pMyObject->WireGuardTu[i].RemoteIPv6, sizeof(pMyObject->WireGuardTu[i].RemoteIPv6));
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
CosaDml_WireGuardTunnelGetTunnelName(ULONG tuIns, char *tunnelname, ULONG size)
{
    if (!tunnelname)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1],string[STRING_MAX_LEN] = {0};
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_TUNNELNAME, tuIns);

    if (0 == syscfg_get(NULL,syscfg_var, string, sizeof(string)))
        strncpy(tunnelname,string,sizeof(string));

    if ((unsigned int)size > strlen(string))
        snprintf(tunnelname, size, "%s", string);

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
CosaDml_WireGuardTunnelGetRemoteIPv6(ULONG tuIns, char *ip6, ULONG size)
{
    if (!ip6)
        return ANSC_STATUS_FAILURE;

    char syscfg_var[MAX_SIZE +1],string[STRING_MAX_LEN] = {0};
    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_REMOTEIPV6, tuIns);

    if (0 == syscfg_get(NULL,syscfg_var, string, sizeof(string)))
        strncpy(ip6,string,sizeof(string));

    if ((unsigned int)size > strlen(string))
        snprintf(ip6, size, "%s", string);

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

ANSC_STATUS
WireGuard_TunnelGeneratePskKey(ULONG tuIns, char *pskKey, ULONG size)
{ 
    FILE *fd = NULL;
    char presharedKey [STRING_MAX_LEN] = {0};
    char syscfg_var[MAX_SIZE +1]={0};

    if(!pskKey)
	    return ANSC_STATUS_FAILURE;

    snprintf(syscfg_var, sizeof(syscfg_var),WIREGUARDTU_PARAM_PRESHAREDKEY, tuIns);
   
    syscfg_get(NULL,syscfg_var, presharedKey, sizeof(presharedKey));

    if(strlen(presharedKey) == 0)
    {
	    snprintf(presharedKey,sizeof(presharedKey),"wg genpsk"); 
	    fd = popen(presharedKey, "r");
	    if (fd)
	    {
		    fgets(presharedKey,sizeof(presharedKey),fd);
		    pclose(fd);
	    }
	    size_t len = strlen(presharedKey);
	    if(len > 0 && presharedKey [len -1] == '\n')
	    {
                presharedKey[len -1] = '\0';
	    }
	    syscfg_set(NULL,syscfg_var,presharedKey);
	    syscfg_commit();
    }

    strncpy(pskKey,presharedKey,sizeof(presharedKey));

    if ((unsigned int)size > strlen(presharedKey))
        snprintf(pskKey, size, "%s", presharedKey);

    return ANSC_STATUS_SUCCESS;
}
