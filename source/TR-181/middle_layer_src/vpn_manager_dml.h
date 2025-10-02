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

#ifndef  _VPN_MGR_DML_H
#define _VPN_MGR_DML_H

BOOL
WireGuard_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

ULONG
WireGuard_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
WireGuard_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

BOOL
WireGuard_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
WireGuard_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
WireGuard_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLength
    );

ULONG
WireGuard_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
WireGuard_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
WireGuardTunnel_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE 
WireGuardTunnel_GetEntry
    (
        ANSC_HANDLE                 hInsContext, 
        ULONG                       nIndex, 
        ULONG*                      pInsNumber 
    );

BOOL 
WireGuardTunnel_GetParamBoolValue 
    (
        ANSC_HANDLE                hInsContext, 
        char*                      ParamName, 
        BOOL*                      pBool
    );

BOOL 
WireGuardTunnel_GetParamUlongValue 
    (
        ANSC_HANDLE                hInsContext, 
        char*                      ParamName, 
        ULONG*                     pUlong
    );

ULONG 
WireGuardTunnel_GetParamStringValue 
    (
        ANSC_HANDLE                hInsContext, 
        char*                      ParamName, 
        char*                      pValue, 
        ULONG*                     pUlSize
    );

BOOL 
WireGuardTunnel_SetParamBoolValue 
    (
        ANSC_HANDLE               hInsContext, 
        char*                     ParamName, 
        BOOL                      bValue
    );

BOOL 
WireGuardTunnel_SetParamStringValue 
    (
        ANSC_HANDLE               hInsContext, 
        char*                     ParamName, 
        char*  strValue 
    );

BOOL 
WireGuardTunnel_SetParamUlongValue 
    (
        ANSC_HANDLE               hInsContext, 
        char*                     ParamName, 
        ULONG                     uValuepUlong
    );

BOOL 
WireGuardTunnel_Validate 
    (
        ANSC_HANDLE              hInsContext, 
        char*                    pReturnParamName, 
        ULONG*                   puLength 
    );

ULONG
WireGuardTunnel_Commit 
    (
        ANSC_HANDLE              hInsContext
    );

ULONG 
WireGuardTunnel_Rollback
    (
        ANSC_HANDLE hInsContext
    );
#endif
