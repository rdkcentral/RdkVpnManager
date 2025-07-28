#! /bin/sh

#########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2025 Deutsche Telekom AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

###################################################################################
#
# This file will configure wg0 interface and bringup tunnels from the inputs 
# pased from vpn_manager
#
####################################################################################

WG_CONFIG_FILE=/etc/wireguard/wg0.conf
WG_DEBUG_FILE=/tmp/vpnDebug.txt
WG_PRIV_KEY_FILE=/nvram/privatekey_wg
WG_PUB_KEY_FILE=/nvram/publickey_wg

COMMAND=$1

if [ "$COMMAND" = "enable" ]; then
    echo "Enabling wireguard and configuring the wg0.conf file" >> $WG_DEBUG_FILE
    echo "[Interface]" > $WG_CONFIG_FILE 
    echo "Address = $2/$3" >> $WG_CONFIG_FILE
    WG_PORT=`syscfg get Wireguard_Port`
    if [ "" != "$WG_PORT" ] && [ "0" != "$WG_PORT" ]; then
	echo "ListenPort = $WG_PORT" >> $WG_CONFIG_FILE
	echo "ListenPort value set." >> $WG_DEBUG_FILE
    else
	echo "Error: ListenPort value not set." >> $WG_DEBUG_FILE
    fi
    if [ -f $WG_PRIV_KEY_FILE ]; then
        echo "Key file found" >> $WG_DEBUG_FILE
    else
        wg genkey | tee $WG_PRIV_KEY_FILE | wg pubkey | tee $WG_PUB_KEY_FILE
       echo "Key file not found....Generating it." >> $WG_DEBUG_FILE
    fi
    PrivKey=$(<$WG_PRIV_KEY_FILE)
    echo "PrivateKey = $PrivKey" >> $WG_CONFIG_FILE 
    echo "" >> $WG_CONFIG_FILE
    echo "Interface configuration done." >> $WG_DEBUG_FILE
elif [ "$COMMAND" = "UP" ]; then
    echo "*********************************" >> $WG_DEBUG_FILE 
    cat WG_CONFIG_FILE >> $WG_DEBUG_FILE
    echo "*********************************" >> $WG_DEBUG_FILE
    echo "wg-quick up wg0" >> $WG_DEBUG_FILE
    syscfg set wireguard_enabled 1
    syscfg commit
    sysevent set firewall-restart
    wg-quick up wg0
    echo "enable done" >> $WG_DEBUG_FILE
elif [ "$COMMAND" = "DOWN" ]; then
    echo "wg-quick down wg0" >> $WG_DEBUG_FILE
    wg-quick down wg0
    syscfg set wireguard_enabled 0
    syscfg commit
    sysevent set firewall-restart
    rm $WG_CONFIG_FILE
    echo "Removed wg0.conf file" >> $WG_DEBUG_FILE
    echo "*********************************" >> $WG_DEBUG_FILE
    echo "*********************************" >> $WG_DEBUG_FILE
elif [ "$COMMAND" = "create_tun" ]; then
    echo "[Peer]" >> $WG_CONFIG_FILE
    echo "PublicKey = $2" >> $WG_CONFIG_FILE
    echo "AllowedIPs = $5/32" >> $WG_CONFIG_FILE
    echo "Endpoint = $3:$4" >> $WG_CONFIG_FILE
    if [ -n "$6" ]; then
	echo "PresharedKey = $6" >> $WG_CONFIG_FILE
        echo "PSK $6" >> $WG_DEBUG_FILE
    else
        echo "NO PSK $6" >> $WG_DEBUG_FILE
    fi
    echo "" >> $WG_CONFIG_FILE
    echo "Peer configurations added to wg0.conf file" >> $WG_DEBUG_FILE
elif [ "$COMMAND" = "SYNC" ]; then
    echo "*********************************" >> $WG_DEBUG_FILE
    cat WG_CONFIG_FILE >> $WG_DEBUG_FILE
    echo "*********************************" >> $WG_DEBUG_FILE
    echo "wg syncconf wg0 $WG_CONFIG_FILE" >> $WG_DEBUG_FILE
    wg-quick strip wg0 > /tmp/wg0.conf ; wg syncconf wg0 /tmp/wg0.conf ; rm /tmp/wg0.conf
fi
