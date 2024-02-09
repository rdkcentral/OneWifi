/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
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

#ifndef _HARVESTER_H_
#define _HARVESTER_H_

#define HARVESTER_COMPONENT_NAME		"com.cisco.spvtg.ccsp.harvester"

#if (defined SIMULATION)
#define NEIGHBORHOOD_SCAN_AVRO_FILENAME		"GatewayAccessPointNeighborScanReport.avsc"
#define INTERFACE_DEVICES_WIFI_AVRO_FILENAME		"InterfaceDevicesWifi.avsc"
#define WIFI_SINGLE_CLIENT_AVRO_FILENAME	"/usr/ccsp/wifi/WifiSingleClient.avsc"
#define RADIO_INTERFACE_STATS_AVRO_FILENAME		"RadioInterfacesStatistics.avsc"
#else
#define NEIGHBORHOOD_SCAN_AVRO_FILENAME		"/usr/ccsp/harvester/GatewayAccessPointNeighborScanReport.avsc"
#define INTERFACE_DEVICES_WIFI_AVRO_FILENAME		"/usr/ccsp/harvester/InterfaceDevicesWifi.avsc"
#define WIFI_SINGLE_CLIENT_AVRO_FILENAME	"/usr/ccsp/wifi/WifiSingleClient.avsc"
#define RADIO_INTERFACE_STATS_AVRO_FILENAME		"/usr/ccsp/harvester/RadioInterfacesStatistics.avsc"
#define WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME        "/usr/ccsp/wifi/WifiSingleClientActiveMeasurement.avsc"
#endif
#define CHK_AVRO_ERR (strlen(avro_strerror()) > 0)

/**
 * @brief Initializes the Message Bus and registers component with the stack.
 *
 * @param[in] name Component Name.
 * @return status 0 for success and 1 for failure
 */
int msgBusInit(const char *name);

/**
 * @brief To send message to webpa and further upstream
 *
 * @param[in] serviceName Name of component/service trying to send message upstream, sending entity
 * @param[in] dest Destination to identify the type of upstream message or receiving entity
 * @param[in] trans_id Transaction UUID unique identifier for the message/transaction
 * @param[in] payload The actual message data
 * @param[in] contentType content type of message "application/json", "avro/binary"
 * @param[in] payload_len length of payload or message length
 */
void sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *traceParent, char *traceState, char *contentType, char *payload, unsigned int payload_len);

/**
 * @brief To get device CM MAC by querying stack
 * @return deviceMAC
*/
char * getDeviceMac();
int initparodusTask();

#endif /* _HARVESTER_H_ */
