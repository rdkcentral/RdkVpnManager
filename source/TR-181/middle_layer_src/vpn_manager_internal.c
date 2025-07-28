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
#include "vpn_manager_internal.h"
#include "vpn_manager_dml_apis.h"

extern void* g_pDslhDmlAgent;

ANSC_STATUS
WireGuard_GetPublicKey
    (
       char *pubKey
    )
{
    size_t keylen = 0;
    FILE *fPtr = fopen(WG_PUB_KEY_FILE,"r");

    if (NULL == fPtr)
        return ANSC_STATUS_FAILURE;

    fgets(pubKey,64,fPtr);
    keylen = strlen(pubKey);

    if(pubKey[keylen-1] == '\n')
        pubKey[keylen-1] = '\0';

    fclose(fPtr);

    CcspTraceInfo(("%s %d-Got the public key from publickey_wg.\n",__FUNCTION__, __LINE__));
}

ANSC_HANDLE
CosaWireGuardTunnelCreate
    (
        VOID
    )
{
    COSA_DATAMODEL_WIREGUARD2          *pMyObject   = NULL;

    pMyObject = AnscAllocateMemory(sizeof(COSA_DATAMODEL_WIREGUARD2));

    if (!pMyObject)
    {
        return NULL;
    }

    pMyObject->Oid               = COSA_DATAMODEL_WIREGUARD_OID; // TODO: COSA_DATAMODEL_WIREGUARD2_OID;
    pMyObject->Create            = CosaWireGuardTunnelCreate;
    pMyObject->Remove            = CosaWireGuardTunnelRemove;
    pMyObject->Initialize        = CosaWireGuardTunnelInitialize;
        printf("-- %s CosaWireGuardTunnelInitialize >>\n", __func__);
    pMyObject->Initialize((ANSC_HANDLE)pMyObject);
        printf("-- %s CosaWireGuardTunnelInitialize <<\n", __func__);

    return (ANSC_HANDLE)pMyObject;
}

ANSC_STATUS
CosaWireGuardTunnelInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    COSA_DATAMODEL_WIREGUARD2       *wireguard          = (COSA_DATAMODEL_WIREGUARD2 *)hThisObject;

    ULONG                           tuCnt, i, tuIns;//,  nextIns;


    if (NULL == wireguard)
    {
        CcspTraceError(("%s %d- Invalid handle, wireguard is NULL\n", __FUNCTION__, __LINE__));
	return ANSC_STATUS_FAILURE;
    }

    if (CosaDml_WireGuardTunnelInit() != ANSC_STATUS_SUCCESS)         //only init tunnel
        return ANSC_STATUS_FAILURE;

    memset(wireguard->WireGuardTu, 0, sizeof(COSA_DML_WIREGUARD_TUNNEL) * MAX_WIREGUARD_TU);
    tuCnt = CosaDml_WireGuardTunnelGetNumberOfEntries();
    //nextIns = 1;

    for (i = 0, tuIns=1; i < tuCnt; i++, tuIns++)
    {
        if (CosaDml_WireGuardTunnelGetEntryByIndex(tuIns, &wireguard->WireGuardTu[i]) != ANSC_STATUS_SUCCESS)
            return ANSC_STATUS_FAILURE;
    }

EXIT:
    return returnStatus;
}

ANSC_STATUS
CosaWireGuardTunnelRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    COSA_DATAMODEL_WIREGUARD2       *wireguard = (COSA_DATAMODEL_WIREGUARD2 *)hThisObject;

    if (NULL == wireguard)
    {
        CcspTraceError(("%s %d- Invalid handle, wireguard is NULL\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (CosaDml_WireGuardTunnelFinalize() != ANSC_STATUS_SUCCESS)
        return ANSC_STATUS_FAILURE;

    if (wireguard)
        AnscFreeMemory(wireguard);

    return ANSC_STATUS_SUCCESS;
}

