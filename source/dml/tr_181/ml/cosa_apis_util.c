/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


/**********************************************************************

    module:	cosa_apis_util.h

        This is base file for all parameters H files.

    ---------------------------------------------------------------

    description:

        This file contains all utility functions for COSA DML API development.

    ---------------------------------------------------------------

    environment:

        COSA independent

    ---------------------------------------------------------------

    author:

        Roger Hu

    ---------------------------------------------------------------

    revision:

        01/30/2011    initial revision.

**********************************************************************/



#include "cosa_apis.h"
#include "plugin_main_apis.h"
#include <strings.h>
#ifdef _ANSC_LINUX
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include "secure_wrapper.h"

#endif
#include "ansc_platform.h"
#ifdef WIFI_HAL_VERSION_3
#include "wifi_hal.h"
#endif

ANSC_STATUS
CosaUtilStringToHex
    (
        char          *str,
        unsigned char *hex_str,
        int           hex_sz 
    )
{
    INT   i= 0, index = 0, val = 0; /*RDKB-6904, CID-33101, CID-33055,  initialize before use */
    CHAR  byte[3]       = {'\0'};

    while(str[i] != '\0')
    {
        byte[0] = str[i];
        byte[1] = str[i+1];
        byte[2] = '\0';
        if(_ansc_sscanf(byte, "%x", &val) != 1)
            break;
        hex_str[index] = val;
        i += 2;
        index++;
        if (str[i] == ':' || str[i] == '-'  || str[i] == '_')
            i++;
    }
    if(index != hex_sz)
        return ANSC_STATUS_FAILURE;

    return ANSC_STATUS_SUCCESS;
}

ULONG
CosaUtilGetIfAddr
    (
        char*       netdev
    )
{
    ANSC_IPV4_ADDRESS       ip4_addr = {{0}};

#ifdef _ANSC_LINUX

    struct ifreq            ifr;
    int                     fd = 0;

    strcpy(ifr.ifr_name, netdev);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        if (!ioctl(fd, SIOCGIFADDR, &ifr))
           memcpy(&ip4_addr.Value, ifr.ifr_ifru.ifru_addr.sa_data + 2,4);
        else
           perror("CosaUtilGetIfAddr IOCTL failure.");

        close(fd);
    }
    else
        perror("CosaUtilGetIfAddr failed to open socket.");

#else

    AnscGetLocalHostAddress(ip4_addr.Dot);

#endif

    return ip4_addr.Value;

}

ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContext->InstanceNumber < pCosaContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pCosaContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        return NULL;
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContextEntry->InstanceNumber == InstanceNumber )
            {
                return pCosaContextEntry;
            }
        }
    }

    return NULL;
}

PUCHAR
CosaUtilGetLowerLayers
    (
        PUCHAR                      pTableName,
        PUCHAR                      pKeyword
    )
{

    ULONG                           ulNumOfEntries              = 0;
    ULONG                           i                           = 0;
    ULONG                           j                           = 0;
    ULONG                           ulEntryNameLen;
    CHAR                            ucEntryParamName[256]       = {0};
    CHAR                            ucEntryNameValue[256]       = {0};
    CHAR                            ucEntryFullPath[256]        = {0};
    CHAR                            ucLowerEntryPath[256]       = {0};
    CHAR                            ucLowerEntryName[256]       = {0};
    ULONG                           ulEntryInstanceNum          = 0;
    ULONG                           ulEntryPortNum              = 0;
    PUCHAR                          pMatchedLowerLayer          = NULL;
    PANSC_TOKEN_CHAIN               pTableListTokenChain        = (PANSC_TOKEN_CHAIN)NULL;
    PANSC_STRING_TOKEN              pTableStringToken           = (PANSC_STRING_TOKEN)NULL;

    if ( !pTableName || AnscSizeOfString((char*)pTableName) == 0 ||
         !pKeyword   || AnscSizeOfString((char*)pKeyword) == 0
       )
    {
        return NULL;
    }

    pTableListTokenChain = AnscTcAllocate((char*)pTableName, ",");

    if ( !pTableListTokenChain )
    {
        return NULL;
    }

    while ((pTableStringToken = AnscTcUnlinkToken(pTableListTokenChain)))
    {
        if ( pTableStringToken->Name )
        {
            if ( AnscEqualString(pTableStringToken->Name, "Device.Ethernet.Interface.", TRUE ) )
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.Ethernet.InterfaceNumberOfEntries");

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.Ethernet.Interface.", i);

                    if ( ulEntryInstanceNum )
                    {
                        _ansc_sprintf(ucEntryFullPath, "%s%lu", "Device.Ethernet.Interface.", ulEntryInstanceNum);

                        _ansc_sprintf(ucEntryParamName, "%s%s", ucEntryFullPath, ".Name");
               
                        ulEntryNameLen = sizeof(ucEntryNameValue);

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             AnscEqualString(ucEntryNameValue, (char*)pKeyword, TRUE ) )
                        {
                            pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.IP.Interface.", TRUE ) )
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.IP.InterfaceNumberOfEntries");
                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.IP.Interface.", i);

                    if ( ulEntryInstanceNum )
                    {
                        _ansc_sprintf(ucEntryFullPath, "%s%lu", "Device.IP.Interface.", ulEntryInstanceNum);

                        _ansc_sprintf(ucEntryParamName, "%s%s", ucEntryFullPath, ".Name");

                        ulEntryNameLen = sizeof(ucEntryNameValue);

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             AnscEqualString(ucEntryNameValue, (char*)pKeyword, TRUE ) )
                        {
                            pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.USB.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.HPNA.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.DSL.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.WiFi.Radio.", TRUE ) )
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.WiFi.RadioNumberOfEntries");

                for (i = 0; i < ulNumOfEntries; i++)
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.WiFi.Radio.", i);
                    
                    if (ulEntryInstanceNum)
                    {
                        _ansc_sprintf(ucEntryFullPath, "%s%lu.", "Device.WiFi.Radio.", ulEntryInstanceNum);
                        
                        _ansc_sprintf(ucEntryParamName, "%s%s", ucEntryFullPath, "Name");
                        
                        ulEntryNameLen = sizeof(ucEntryNameValue);

                        if (( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                            AnscEqualString(ucEntryNameValue, (char*)pKeyword, TRUE) )
                        {
                            pMatchedLowerLayer = (PUCHAR)AnscCloneString(ucEntryFullPath);
                            
                            break;
                        }
                    }
                }
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.HomePlug.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.MoCA.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.UPA.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.ATM.Link.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.PTM.Link.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.Ethernet.Link.", TRUE ) )
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.Ethernet.LinkNumberOfEntries");

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.Ethernet.Link.", i);

                    if ( ulEntryInstanceNum )
                    {
                        _ansc_sprintf(ucEntryFullPath, "%s%lu", "Device.Ethernet.Link.", ulEntryInstanceNum);

                        _ansc_sprintf(ucEntryParamName, "%s%s", ucEntryFullPath, ".Name");
               
                        ulEntryNameLen = sizeof(ucEntryNameValue);

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             AnscEqualString(ucEntryNameValue, (char*)pKeyword, TRUE ) )
                        {
                            pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.Ethernet.VLANTermination.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.WiFi.SSID.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.Bridging.Bridge.", TRUE ) )
            {
                ulNumOfEntries =  CosaGetParamValueUlong("Device.Bridging.BridgeNumberOfEntries");
                CcspTraceInfo(("----------CosaUtilGetLowerLayers, bridgenum:%ld\n", ulNumOfEntries));
                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.Bridging.Bridge.", i);
                    CcspTraceInfo(("----------CosaUtilGetLowerLayers, instance num:%ld\n", ulEntryInstanceNum));

                    if ( ulEntryInstanceNum )
                    {
                        _ansc_sprintf(ucEntryFullPath, "%s%lu", "Device.Bridging.Bridge.", ulEntryInstanceNum);
                        _ansc_sprintf(ucLowerEntryPath, "%s%s", ucEntryFullPath, ".PortNumberOfEntries"); 
                        
                        ulEntryPortNum = CosaGetParamValueUlong(ucLowerEntryPath);  
                        CcspTraceInfo(("----------CosaUtilGetLowerLayers, Param:%s,port num:%ld\n",ucLowerEntryPath, ulEntryPortNum));

                        for ( j = 1; j<= ulEntryPortNum; j++) {
                            _ansc_sprintf(ucLowerEntryName, "%s%s%lu", ucEntryFullPath, ".Port.", j);
                            _ansc_sprintf(ucEntryParamName, "%s%s%lu%s", ucEntryFullPath, ".Port.", j, ".Name");
                            CcspTraceInfo(("----------CosaUtilGetLowerLayers, Param:%s,Param2:%s\n", ucLowerEntryName, ucEntryParamName));
                        
                            ulEntryNameLen = sizeof(ucEntryNameValue);

                            if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                                 AnscEqualString(ucEntryNameValue, (char*)pKeyword , TRUE ) )
                            {
                                pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucLowerEntryName);
                                CcspTraceInfo(("----------CosaUtilGetLowerLayers, J:%ld, LowerLayer:%s\n", j, pMatchedLowerLayer));
                                break;
                            }
                        }
                    }
                }
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.PPP.Interface.", TRUE ) )
            {
            }
            else if ( AnscEqualString(pTableStringToken->Name, "Device.DSL.Channel.", TRUE ) )
            {
            }
            
            if ( pMatchedLowerLayer )
            {
                break;
            }
        }

        AnscFreeMemory(pTableStringToken);
    }

    if ( pTableListTokenChain )
    {
        AnscTcFree((ANSC_HANDLE)pTableListTokenChain);
    }

    CcspTraceWarning
        ((
            "CosaUtilGetLowerLayers: %s matched LowerLayer(%s) with keyword %s in the table %s\n",
            pMatchedLowerLayer ? "Found a":"Not find any",
            pMatchedLowerLayer ? (char *)pMatchedLowerLayer : "",
            pKeyword,
            pTableName
        ));

    return pMatchedLowerLayer;
}

/*
    CosaUtilGetFullPathNameByKeyword
    
   Description:
        This funcation serves for searching other pathname  except lowerlayer.
        
    PUCHAR                      pTableName
        This is the Table names divided by ",". For example 
        "Device.Ethernet.Interface., Device.Dhcpv4." 
        
    PUCHAR                      pParameterName
        This is the parameter name which hold the keyword. eg: "name"
        
    PUCHAR                      pKeyword
        This is keyword. eg: "wan0".

    return value
        return result string which need be free by the caller.
*/
PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword
    )
{

    ULONG                           ulNumOfEntries              = 0;
    ULONG                           i                           = 0;
    ULONG                           ulEntryNameLen;
    CHAR                            ucEntryParamName[256]       = {0};
    CHAR                            ucEntryNameValue[256]       = {0};
    CHAR                            ucTmp[128]                  = {0};
    CHAR                            ucTmp2[128]                 = {0};
    CHAR                            ucEntryFullPath[256]        = {0};
    PUCHAR                          pMatchedLowerLayer          = NULL;
    ULONG                           ulEntryInstanceNum          = 0;
    PANSC_TOKEN_CHAIN               pTableListTokenChain        = (PANSC_TOKEN_CHAIN)NULL;
    PANSC_STRING_TOKEN              pTableStringToken           = (PANSC_STRING_TOKEN)NULL;
    PUCHAR                          pString                     = NULL;
    PUCHAR                          pString2                    = NULL;

    if ( !pTableName || AnscSizeOfString((char*)pTableName) == 0 ||
         !pKeyword   || AnscSizeOfString((char*)pKeyword) == 0   ||
         !pParameterName   || AnscSizeOfString((char*)pParameterName) == 0
       )
    {
        return NULL;
    }

    pTableListTokenChain = AnscTcAllocate((char*)pTableName, ",");

    if ( !pTableListTokenChain )
    {
        return NULL;
    }

    while ((pTableStringToken = AnscTcUnlinkToken(pTableListTokenChain)))
    {
        if ( pTableStringToken->Name )
        {
            /* Get the string XXXNumberOfEntries */
            pString2 = (PUCHAR)&pTableStringToken->Name[0];
            pString  = pString2;
            for (i = 0;pTableStringToken->Name[i]; i++)
            {
                if ( pTableStringToken->Name[i] == '.' )
                {
                    pString2 = pString;
                    pString  = (PUCHAR)&pTableStringToken->Name[i+1];
                }
            }

            pString--;
            pString[0] = '\0';
            _ansc_sprintf(ucTmp2, "%s%s", pString2, "NumberOfEntries");                
            pString[0] = '.';

            /* Enumerate the entry in this table */
            if ( TRUE )
            {
                pString2--;
                pString2[0]='\0';
                _ansc_sprintf(ucTmp, "%s.%s", pTableStringToken->Name, ucTmp2);                
                pString2[0]='.';
                ulNumOfEntries =       CosaGetParamValueUlong(ucTmp);

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex(pTableStringToken->Name, i);

                    if ( ulEntryInstanceNum )
                    {
                        _ansc_sprintf(ucEntryFullPath, "%s%lu%s", pTableStringToken->Name, ulEntryInstanceNum, ".");

                        _ansc_sprintf(ucEntryParamName, "%s%s", ucEntryFullPath, pParameterName);
               
                        ulEntryNameLen = sizeof(ucEntryNameValue);

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             AnscEqualString(ucEntryNameValue, (char*)pKeyword, TRUE ) )
                        {
                            pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }

            if ( pMatchedLowerLayer )
            {
                break;
            }
        }

        AnscFreeMemory(pTableStringToken);
    }

    if ( pTableListTokenChain )
    {
        AnscTcFree((ANSC_HANDLE)pTableListTokenChain);
    }

    CcspTraceWarning
        ((
            "CosaUtilGetFullPathNameByKeyword: %s matched parameters(%s) with keyword %s in the table %s(%s)\n",
            pMatchedLowerLayer ? "Found a":"Not find any",
            pMatchedLowerLayer ? (char *)pMatchedLowerLayer : "",
            pKeyword,
            pTableName,
            pParameterName
        ));

    return pMatchedLowerLayer;
}

ULONG
CosaUtilChannelValidate
    (
        UINT                       uiRadio,
        ULONG                      Channel,
        char                       *channelList
    )
{

#if defined CONFIG_DFS
    BOOLEAN dfsEnable;
    wifi_getRadioDfsEnable(uiRadio-1, &dfsEnable);
    unsigned long channelList_5G_dfs [] = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144};
#endif
#ifndef WIFI_HAL_VERSION_3
    // This should be updated to use the possible channels list  Device.WiFi.Radio.1.PossibleChannels instead of a static list.
    unsigned long channelList_5G [] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
    int i;
#endif

    // Channel maybe 0 if radio is disabled or auto channel was set
    if (Channel == 0) {
        return 1;
    }

#if defined CONFIG_DFS
    int k;
#endif
    // If channelList is provided use it.
    if (channelList != NULL) {
        char chan[4];
        sprintf(chan,"%lu",Channel);
        
        //channel list is comma seperated values, so for comparing split them individually
        char PossibleChannels[512] = {0};
        strncpy(PossibleChannels, channelList, sizeof(PossibleChannels)-1);
        PossibleChannels[sizeof(PossibleChannels)-1]='\0';
        const char delimiter[2] = ",";
        char *saveptr = NULL;
        char *token = strtok_r(PossibleChannels, delimiter, &saveptr);
        
        //Check whether channel value to set is from the specified channel list only
        while( token != NULL ) {
            if (strcmp(token,chan) == 0) {
#if defined CONFIG_DFS
                if(uiRadio == 2 && !dfsEnable) {
                    for (k=0; k<15; k++)
                    {
                        if(Channel == channelList_5G_dfs[k]) {
                            CcspTraceInfo(("RDK_LOG_INFO,%s DFS is disabled, invalid channel\n",__FUNCTION__));
                            return 0;
                        }
                    }
                }
#endif
                return 1;
            }
            token = strtok_r(NULL, delimiter, &saveptr);
        }
    }
#ifdef WIFI_HAL_VERSION_3
    if(wifiRadioChannelIsValid(uiRadio - 1, Channel) == ANSC_STATUS_SUCCESS)
    {
        return 1;
    }
    return 0;
#else
    switch(uiRadio)
    {
        case 1:
             if(((int)Channel < RADIO_2G_MIN_CHANNEL) || (Channel > RADIO_2G_MAX_CHANNEL))
                return 0;
             return 1;
        case 2:
             for(i=0; i<24; i++)
             {
                if(Channel == channelList_5G[i])
                  return 1;
             }
             return 0;
             break;
        default:
             break;
     }
     return 0;
#endif
}

#if  defined(_COSA_DRG_CNS_) || defined(_COSA_DRG_TPG_)
ULONG CosaUtilIoctlXXX(char * if_name, char * method, void * input)
{
    ULONG ret = 0;
    struct ifreq ifr;
	int sock;

    if (!if_name || !method)
    {
        return 0;
    }
    
	sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0 ) 
    {
        return 0;
    }

    strncpy(ifr.ifr_name, if_name, IF_NAMESIZE);

    if (!strcmp(method, "mtu"))
    {
        if (ioctl(sock, SIOCGIFMTU, &ifr) == 0)
        {
            ret = ifr.ifr_mtu;
            goto _EXIT;
        }
        else 
        {
            goto _EXIT;
        }
    }
    if (!strcmp(method, "setmtu"))
    {
        ULONG mtu = *(ULONG *)input;
        ifr.ifr_mtu = mtu;

        ret = ioctl(sock, SIOCSIFMTU, &ifr);
        goto _EXIT;
    }
    else if (!strcmp(method, "status"))
    {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
        {
            ret = ifr.ifr_flags;
            goto _EXIT;

        }
        else 
        {
            goto _EXIT;
        }        
    }
    else if (!strcmp(method, "netmask"))
    {
        if (ioctl(sock, SIOCGIFNETMASK, &ifr) == 0)
        {
            memcpy(&ret, ifr.ifr_netmask.sa_data + 2,4);
            goto _EXIT;

        }
        else 
        {
            goto _EXIT;
        }        
    }
    else if (!strcmp(method, "set_netmask"))
    {
        ULONG mask = *(ULONG *)input;

        /*first get netmask then modify it*/
        if (ioctl(sock, SIOCGIFNETMASK, &ifr) == 0)
        {
            memcpy(ifr.ifr_netmask.sa_data + 2, &mask, sizeof(mask));
            ret = ioctl(sock, SIOCSIFNETMASK, &ifr);
            
            goto _EXIT;
        }
        else 
        {
            ret = -1;
            goto _EXIT;
        }        
    }
_EXIT:
    close(sock);
    return ret;
}

#define NET_STATS_FILE "/proc/net/dev"
int CosaUtilGetIfStats(char * ifname, PCOSA_DML_IF_STATS pStats)
{
    int    i;
    FILE * fp;
    char buf[1024] = {0} ;
    char * p;
    int    ret = 0;

    fp = fopen(NET_STATS_FILE, "r");
    
    if (fp)
    {
        i = 0;
        while (fgets(buf, sizeof(buf), fp))
        {
            if (++i <= 2) continue;
            
            if (p = strchr(buf, ':'))
            {
                if (strstr(buf, ifname))
                {
                    memset(pStats, 0, sizeof(*pStats));
                    if (sscanf(p+1, "%d %d %d %d %*d %*d %*d %*d %d %d %d %d %*d %*d %*d %*d", 
                               &pStats->BytesReceived, &pStats->PacketsReceived, &pStats->ErrorsReceived, &pStats->DiscardPacketsReceived,
                               &pStats->BytesSent, &pStats->PacketsSent, &pStats->ErrorsSent, &pStats->DiscardPacketsSent
                            ) == 8)
                    {
                        /*found*/
                        ret = TRUE;
                        goto _EXIT;
                    }
                }
                else continue;
            }
            else continue;
        }
        
    }   

_EXIT:
    fclose(fp);
    return ret;
}
#endif

ULONG NetmaskToNumber(char *netmask)
{
    char * pch;
    ULONG val;
    ULONG i;
    ULONG count = 0;

    pch = strtok(netmask, ".");
    while (pch != NULL)
    {
        val = atoi(pch);
        for (i=0;i<8;i++)
        {
            if (val&0x01)
            {
                count++;
            }
            val = val >> 1;
        }
        pch = strtok(NULL,".");
    }
    return count;
}

ANSC_STATUS
CosaUtilGetStaticRouteTable
    (
        UINT                        *count,
        StaticRoute                 **out_sroute
    )
{
#if ( defined(_COSA_DRG_CNS_) || defined(_COSA_DRG_TPG_))
    int i;
    int j;
    StaticRoute *sroute;
    char line_buf[512];
    int line_count;
    char *pch = NULL;

    if (NULL == count || NULL == out_sroute) {
        return ANSC_STATUS_FAILURE;
    }
    
    *count = 0;
    
    get_stubs_descriptor()->v_secure_system_fn("route -n | grep -v '^127.0.0' > /tmp/.rout_table_tmp");

    FILE *fp = fopen("/tmp/.route_table_tmp", "r");
    FILE *fp2 = NULL;
    
    if (!fp) {
        return ANSC_STATUS_FAILURE;
    }
    
    line_count = 0;
    while (NULL != fgets(line_buf, sizeof(line_buf), fp)) {
        line_count++;
    }
    
    *count = line_count - 2; // Skip the first two lines
    if (*count <= 0) {
        fclose(fp);
        return ANSC_STATUS_SUCCESS;
    }

    sroute = (StaticRoute *) malloc(sizeof(StaticRoute) * (*count));
    if (NULL == sroute) {
        return ANSC_STATUS_FAILURE;
    }
    bzero(sroute, sizeof(StaticRoute) * (*count));
    
    // Seek to beginning of file
    fseek(fp, 0, SEEK_SET);
    
    // Read past the first two lines
    for (i = 0; i < 2; i++) {
        if (NULL == fgets(line_buf, sizeof(line_buf), fp)) {
    	    break;
        }
    }
    
    for (i = 0; i < *count && fgets(line_buf, sizeof(line_buf), fp) != NULL; i++) {
        char *start;
        int len;
        
        // Set the destination LAN IP
        start = line_buf;
        len = strcspn(start, " ");
        if (len >= 16) {
            len = 16 - 1;
        }
        strncpy(sroute[i].dest_lan_ip, start, len);
        sroute[i].dest_lan_ip[len] = 0;
        
        // Set the gateway
        start += len;
        start += strspn(start, " ");
        len = strcspn(start, " ");
        if (len >= 16) {
            len = 16 - 1;
        }
        strncpy(sroute[i].gateway, start, len);
        sroute[i].gateway[len] = 0;
        
        // Set the netmask
        start += len;
        start += strspn(start, " ");
        len = strcspn(start, " ");
        if (len >= 16) {
            len = 16 - 1;
        }
        strncpy(sroute[i].netmask, start, len);
        sroute[i].netmask[len] = 0;
        
        // Skip the next one columns
        for (j = 0; j < 1; j++) {
            start += len;
	        start += strspn(start, " ");
	        len = strcspn(start, " ");
        }
        
        // set metric
        start += len;
        start += strspn(start, " ");
        sroute[i].metric = atoi(start);

        // Skip the next two columns
        for (j = 0; j < 2; j++) {
            start += len;
	        start += strspn(start, " ");
	        len = strcspn(start, " ");
        }

        // Lookup the interface
        start += len;
        start += strspn(start, " ");
        
        // Set the route's interface
        strncpy(sroute[i].dest_intf, start, 9);

        len = strlen(sroute[i].dest_intf);
        if (sroute[i].dest_intf[len-1] == '\n')
            sroute[i].dest_intf[len-1] = '\0';

        if (TRUE)
        {

            if (((fp2 = v_secure_popen("r", "/sbin/ip route show %s/%d", sroute[i].dest_lan_ip, NetmaskToNumber(sroute[i].netmask))) != NULL) &&
               (fgets(line_buf, sizeof(line_buf), fp2)))
            {
                pch = strtok(line_buf, " ");

                while(pch != NULL)
                {
                    if (!strcmp(pch, "proto"))
                    {
                        pch = strtok(NULL, " ");
                        strcpy(sroute[i].origin, pch);
                        break;
                    }
                    pch = strtok(NULL, " ");
                }
            }
        }

    }

    if (fp2)
    {
        v_secure_pclose(fp2);
    }
    fclose(fp);
    
    *out_sroute = sroute;

    return ANSC_STATUS_SUCCESS;
#else
// These function parameters are unused in the else case .
    UNREFERENCED_PARAMETER(count);
    UNREFERENCED_PARAMETER(out_sroute);
    return ANSC_STATUS_SUCCESS;
#endif

}

#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U
#define IPV6_ADDR_COMPATv4      0x0080U
#define IPV6_ADDR_SCOPE_MASK    0x00f0U

#if  defined(_COSA_DRG_CNS_) || defined(_COSA_DRG_TPG_)

/*caller must free(*pp_info)*/
#define _PROCNET_IFINET6  "/proc/net/if_inet6"
#define MAX_INET6_PROC_CHARS 200


int getIpv6Scope(int scope_v6)
{
    int scopeToReturn = scope_v6 & IPV6_ADDR_SCOPE_MASK;

    if(scopeToReturn == 0)
       return IPV6_ADDR_SCOPE_GLOBAL;
    else if( scopeToReturn == IPV6_ADDR_LINKLOCAL)
       return IPV6_ADDR_LINKLOCAL;
    else if( scopeToReturn == IPV6_ADDR_SCOPE_LINKLOCAL)
       return IPV6_ADDR_SCOPE_LINKLOCAL;
    else if( scopeToReturn == IPV6_ADDR_SITELOCAL)
       return IPV6_ADDR_SITELOCAL;
    else if(scopeToReturn == IPV6_ADDR_SCOPE_SITELOCAL)
        return IPV6_ADDR_SCOPE_SITELOCAL;
    else if( scopeToReturn == IPV6_ADDR_COMPATv4)
        return IPV6_ADDR_COMPATv4;
    else if( scopeToReturn == IPV6_ADDR_SCOPE_COMPATv4)
        return  IPV6_ADDR_SCOPE_COMPATv4;
    else if( scopeToReturn == IPV6_ADDR_LOOPBACK)
        return IPV6_ADDR_LOOPBACK;
    else if( scopeToReturn == IPV6_ADDR_SCOPE_LOOPBACK)
        return IPV6_ADDR_SCOPE_LOOPBACK;
    else
        return IPV6_ADDR_SCOPE_UNKNOWN;
}

int parseProcfileParams(char* lineToParse,ifv6Details *detailsToParse,char* interface)
{

    struct sockaddr_in6 sAddr6;
    char splitv6[8][5];
    CcspTraceInfo(("%s, Parse the line read from file\n",__FUNCTION__));

    if (lineToParse == NULL)
           return 0;

    if(sscanf(lineToParse, "%s %x %x %x %x %s", detailsToParse->ipv6_addr,&detailsToParse->devIndex,
              &detailsToParse->bitsToMask,&detailsToParse->scopeofipv6,&detailsToParse->flags,detailsToParse->intrName) == 6)
    {

       CcspTraceInfo(("%s, Check if interface matches\n",__FUNCTION__));
       if (!strcmp(interface, detailsToParse->intrName))
       {
           CcspTraceInfo(("%s,Interface matched\n",__FUNCTION__));
           //Convert the raw interface ip to IPv6 format
           int position,placeholder=0;
           for (position=0; position<strlen(detailsToParse->ipv6_addr); position++)
           {
               detailsToParse->address6[placeholder] = detailsToParse->ipv6_addr[position];
               placeholder++;
               // Positions at which ":" should be put.
               if((position==3)||(position==7)||(position==11)||(position==15)||
                   (position==19)||(position==23)||(position==27))
               {
                   detailsToParse->address6[placeholder] = ':';
                   placeholder++;
               }
           }
           CcspTraceInfo(("%s,Interface IPv6 address calculation\n",__FUNCTION__));
           inet_pton(AF_INET6, detailsToParse->address6,(struct sockaddr *) &sAddr6.sin6_addr);
           sAddr6.sin6_family = AF_INET6;
           inet_ntop(AF_INET6, (struct sockaddr *) &sAddr6.sin6_addr, detailsToParse->address6, sizeof(detailsToParse->address6));
           CcspTraceInfo(("%s,Interface IPv6 address is: %s\n",__FUNCTION__,detailsToParse->address6));

           if(sscanf(lineToParse, "%4s%4s%4s%4s%4s%4s%4s%4s", splitv6[0], splitv6[1], splitv6[2],
                                                              splitv6[3], splitv6[4],splitv6[5], splitv6[6], splitv6[7])==8)
           {
               memset(detailsToParse->prefix_v6,0,sizeof(detailsToParse->prefix_v6));
               int iCount =0;
               for (iCount=0; (iCount< ( detailsToParse->bitsToMask%16 ? (detailsToParse->bitsToMask/16+1):detailsToParse->bitsToMask/16)) && iCount<8; iCount++)
               {
                  sprintf(detailsToParse->prefix_v6+strlen(detailsToParse->prefix_v6), "%s:",splitv6[iCount]);
               }
               CcspTraceInfo(("%s,Interface IPv6 prefix calculation done\n",__FUNCTION__));
            }
            return 1;
      }
      else
      {
         CcspTraceInfo(("%s,Interface not found\n",__FUNCTION__));
         return 0;
      }
    }
    else
    {
      CcspTraceInfo(("%s,Interface line read failed\n",__FUNCTION__));
      return 0;
    }
}


int CosaUtilGetIpv6AddrInfo (char * ifname, ipv6_addr_info_t ** pp_info, int * p_num)
{
    FILE * fp = NULL;
    ipv6_addr_info_t * p_ai = NULL;
    char procLine[MAX_INET6_PROC_CHARS];
    ifv6Details v6Details;
    int parsingResult;

    if (!ifname || !pp_info || !p_num)
        return -1;

    *p_num = 0;

    fp = fopen(_PROCNET_IFINET6, "r");
    if (!fp)
        return -1;

    while(fgets(procLine, MAX_INET6_PROC_CHARS, fp))
    {

        parsingResult=parseProcfileParams(procLine, &v6Details,ifname);
        if (parsingResult == 1)
        {
            (*p_num)++;
            *pp_info = realloc(*pp_info,  *p_num * sizeof(ipv6_addr_info_t));
            if (!*pp_info)
                return -1;
            p_ai = &(*pp_info)[*p_num-1];
            strncpy(p_ai->v6addr, v6Details.address6, sizeof(p_ai->v6addr));

            // Get the scope of IPv6
            p_ai->scope = getIpv6Scope(v6Details.scopeofipv6);
            CcspTraceInfo(("%s,Interface scope is : %d\n",__FUNCTION__,v6Details.scopeofipv6));

            memset(p_ai->v6pre, 0, sizeof(p_ai->v6pre));
            if(v6Details.prefix_v6)
                 strcpy(p_ai->v6pre,v6Details.prefix_v6);
            else
                CcspTraceInfo(("%s,Interface ipv6 prefix is NULL\n",__FUNCTION__));

            sprintf(p_ai->v6pre+strlen(p_ai->v6pre), ":/%d", v6Details.bitsToMask);

        }
    }

    return 0;
}

#endif

int safe_strcpy(char * dst, char * src, int dst_size)
{
    if (!dst || !src) return -1;

    memset(dst, 0, dst_size);
    _ansc_strncpy(dst, src, _ansc_strlen(src) <= (ULONG)(dst_size-1) ? _ansc_strlen(src): (ULONG)(dst_size-1) );

    return 0;
}

int  __v6addr_mismatch(char * addr1, char * addr2, int pref_len)
{
    int i = 0;
    int num = 0;
    int mask = 0;
    char addr1_buf[128] = {0};
    char addr2_buf[128] = {0};
    struct in6_addr in6_addr1;
    struct in6_addr in6_addr2;

    if (!addr1 || !addr2)
        return -1;
    
    safe_strcpy(addr1_buf, addr1, sizeof(addr1_buf));
    safe_strcpy(addr2_buf, addr2, sizeof(addr2_buf));

    if ( inet_pton(AF_INET6, addr1_buf, &in6_addr1) != 1)
        return -8;
    if ( inet_pton(AF_INET6, addr2_buf, &in6_addr2) != 1)
        return -9;

    num = (pref_len%8)? (pref_len/8+1) : pref_len/8;
    if (pref_len%8)
    {
        for (i=0; i<num-1; i++)
            if (in6_addr1.s6_addr[i] != in6_addr2.s6_addr[i])
                return -3;

        for (i=0; i<pref_len%8; i++)
            mask += 1<<(7-i);
        
        if ( (in6_addr1.s6_addr[num-1] &  mask) == (in6_addr2.s6_addr[num-1] & mask))
            return 0;
        else
            return -4;
    }
    else 
    {
        for (i=0; i<num; i++)
            if (in6_addr1.s6_addr[i] != in6_addr2.s6_addr[i])
                return -5;
    }

    return 0;
}

int  __v6addr_mismatches_v6pre(char * v6addr,char * v6pre)
{
    int pref_len = 0;
    char addr_buf[128] = {0};
    char pref_buf[128] = {0};
    char * p = NULL;

    if (!v6addr || !v6pre)
        return -1;
    
    safe_strcpy(addr_buf, v6addr, sizeof(addr_buf));
    safe_strcpy(pref_buf, v6pre, sizeof(pref_buf));

    if (!(p = strchr(pref_buf, '/')))
        return -1;

    if (sscanf(p, "/%d", &pref_len) != 1)
        return -2;
    *p = 0;

    return __v6addr_mismatch(addr_buf, pref_buf, pref_len);
}

int  __v6pref_mismatches(char * v6pref1,char * v6pref2)
{
    int pref1_len = 0;
    int pref2_len = 0;
    char pref1_buf[128] = {0};
    char pref2_buf[128] = {0};
    char * p = NULL;

    if (!v6pref1 || !v6pref2)
        return -1;
    
    safe_strcpy(pref1_buf, v6pref1, sizeof(pref1_buf));
    safe_strcpy(pref2_buf, v6pref2, sizeof(pref2_buf));

    if (!(p = strchr(pref1_buf, '/')))
        return -1;

    if (sscanf(p, "/%d", &pref1_len) != 1)
        return -2;
    *p = 0;

    if (!(p = strchr(pref2_buf, '/')))
        return -1;

    if (sscanf(p, "/%d", &pref2_len) != 1)
        return -2;
    *p = 0;

    if (pref1_len != pref2_len)
        return -7;

    return __v6addr_mismatch(pref1_buf, pref2_buf, pref1_len);
}

int CosaDmlV6AddrIsEqual(char * p_addr1, char * p_addr2)
{
    if (!p_addr1 || !p_addr2)
        return 0;

    return !__v6addr_mismatch(p_addr1, p_addr2, 128);
}

int CosaDmlV6PrefIsEqual(char * p_pref1, char * p_pref2)
{
    if (!p_pref1 || !p_pref2)
        return 0;

    return !__v6pref_mismatches(p_pref1, p_pref2);
}

int _write_sysctl_file(char * fn, int val)
{
    FILE * fp = fopen(fn, "w+");

    if (fp)
    {
        fprintf(fp, "%d", val);
        fclose(fp);
    }
    
    return 0;
}
