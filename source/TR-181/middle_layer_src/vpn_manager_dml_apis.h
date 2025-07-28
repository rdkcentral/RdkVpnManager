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

#ifndef _VPN_MANAGER_DML_APIS_H
#define _VPN_MANAGER_DML_APIS_H

#define VPN_CONFIG_SCRIPT "/usr/rdk/vpnmanager/vpn_config.sh"

ANSC_STATUS VpnDmlInitialize();

ANSC_STATUS
CosaDml_WireGuardGetStatus(DML_VPN_IF_CFG_STATUS *st);

ULONG
CosaDml_WireGuardTunnelGetNumberOfEntries(void);

ANSC_STATUS
CosaDml_WireGuardGetStatus(DML_VPN_IF_CFG_STATUS *st);

ANSC_STATUS
CosaDml_WireGuardTunnelGetStatus(ULONG tuIns, COSA_DML_WIREGUARD_TUNNEL_STATUS *st);

ANSC_STATUS
CosaDml_WireGuardTunnelGetEntryByIndex(ULONG ins, COSA_DML_WIREGUARD_TUNNEL *wireguardTu);

ANSC_STATUS
CosaDml_WireGuardTunnelSetEnable(ULONG tuIns, BOOL enable);

ANSC_STATUS
CosaDml_WireGuardTunnelSetPSKEnable(ULONG tuIns, BOOL pskenable);

ANSC_STATUS
CosaDml_WireGuardTunnelSetRemoteEndPoint(ULONG tuIns, const char *endpoint);

ANSC_STATUS
CosaDml_WireGuardTunnelSetRemoteIP(ULONG tuIns, const char *remoteip);

ANSC_STATUS
CosaDml_WireGuardTunnelSetPreSharedKey(ULONG tuIns, const char *presharedkey);

ANSC_STATUS
CosaDml_WireGuardTunnelSetPeerPublicKey(ULONG tuIns, const char *peerpublickey);

ANSC_STATUS
CosaDml_WireGuardTunnelSetRemotePort(ULONG tuIns, ULONG val);

ANSC_STATUS WireGuardTunnelDmlInitialize();

ANSC_STATUS
CosaDml_WireGuardTunnelGetEnable(ULONG ins, BOOL *enable);

ANSC_STATUS
CosaDml_WireGuardTunnelGetPSKEnable(ULONG ins, BOOL *pskenable);  

ANSC_STATUS
CosaDml_WireGuardTunnelGetRemoteEndPoint(ULONG tuIns, char *eps, ULONG size);

ANSC_STATUS
CosaDml_WireGuardTunnelGetRemoteIP(ULONG tuIns, char *ip, ULONG size);

ANSC_STATUS
CosaDml_WireGuardTunnelGetPreSharedKey(ULONG tuIns, char *key, ULONG size);

ANSC_STATUS
CosaDml_WireGuardTunnelGetPeerPublicKey(ULONG tuIns, char *key, ULONG size);

ANSC_STATUS
CosaDml_WireGuardTunnelGetRemotePort(ULONG tuIns, ULONG *val);

void create_config_file();

ANSC_STATUS CosaDml_WireGuardTunnelInit(void);

ANSC_STATUS CosaDml_WireGuardTunnelFinalize(void);

#endif
