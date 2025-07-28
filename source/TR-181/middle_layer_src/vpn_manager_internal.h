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

#include "vpn_manager_dml_apis.h"
#include <time.h>

#define LOG_FILE "/tmp/vpnDebug.txt"

#define APPLY_PRINT(fmt ...) {\
FILE *logfp = fopen(LOG_FILE , "a+");\
if (logfp){\
time_t s = time(NULL);\
struct tm* current_time = localtime(&s);\
fprintf(logfp, "[%02d:%02d:%02d] ",\
current_time->tm_hour,\
current_time->tm_min,\
current_time->tm_sec);\
fprintf(logfp, fmt);\
fclose(logfp);\
}\
}\

#define WG_PUB_KEY_FILE "/nvram/publickey_wg"

typedef  struct
_COSA_DATAMODEL_WIREGUARD2
{
  BASE_CONTENT
        COSA_DML_WIREGUARD_TUNNEL  WireGuardTu[MAX_WIREGUARD_TU];
} COSA_DATAMODEL_WIREGUARD2;


ANSC_HANDLE CosaWireGuardTunnelCreate ();

ANSC_STATUS CosaWireGuardTunnelInitialize  ( ANSC_HANDLE  hThisObject );

ANSC_STATUS CosaWireGuardTunnelRemove ( ANSC_HANDLE hThisObject );

ANSC_STATUS WireGuard_GetPublicKey(char *pubKey);

