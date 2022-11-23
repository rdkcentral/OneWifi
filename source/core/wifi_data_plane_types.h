 /****************************************************************************
  If not stated otherwise in this file or this component's LICENSE     
  file the following copyright and licenses apply:                          
                                                                            
  Copyright 2020 RDK Management                                             
                                                                            
  Licensed under the Apache License, Version 2.0 (the "License");           
  you may not use this file except in compliance with the License.          
  You may obtain a copy of the License at                                   
                                                                            
      http://www.apache.org/licenses/LICENSE-2.0                            
                                                                            
  Unless required by applicable law or agreed to in writing, software       
  distributed under the License is distributed on an "AS IS" BASIS,         
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
  See the License for the specific language governing permissions and       
  limitations under the License.                                            
                                                                            
 ****************************************************************************/

#ifndef WIFI_DATA_PLANE_TYPE_H
#define WIFI_DATA_PLANE_TYPE_H

typedef enum {
    wifi_data_plane_packet_type_8021x,
    wifi_data_plane_packet_type_auth,
    wifi_data_plane_packet_type_assoc_req,
    wifi_data_plane_packet_type_assoc_rsp,
} wifi_data_plane_packet_type_t;

typedef enum {
    wifi_data_plane_event_type_dpp,
    wifi_data_plane_event_type_anqp,
} wifi_data_plane_event_type_t;

typedef enum {
    wifi_data_plane_queue_data_type_packet,
    wifi_data_plane_queue_data_type_event,
} wifi_data_plane_queue_data_type_t;

#endif
