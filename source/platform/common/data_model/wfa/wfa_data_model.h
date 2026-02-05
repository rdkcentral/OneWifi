/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef WFA_DATA_MODEL_H
#define WFA_DATA_MODEL_H

#include <stddef.h>

#define DATAELEMS_NETWORK_OBJ   "Device.WiFi.DataElements.Network"
#define DATAELEMS_NETWORK       DATAELEMS_NETWORK_OBJ "."

#define MAX_INSTANCE_LEN        32
#define MAX_CAPS_STR_LEN        32
#define ARRAY_SIZE(a)           (sizeof(a) / sizeof(a[0]))

/* Device.WiFi.DataElements.Network */
#define DE_NETWORK_ID           DATAELEMS_NETWORK       "ID"
#define DE_NETWORK_CTRLID       DATAELEMS_NETWORK       "ControllerID"
#define DE_NETWORK_COLAGTID     DATAELEMS_NETWORK       "ColocatedAgentID"
// #define DE_NETWORK_DEVNOE       DATAELEMS_NETWORK       "DeviceNumberOfEntries"NumberOfDevices
#define DE_NETWORK_DEVNOE       DATAELEMS_NETWORK       "NumberOfDevices"
#define DE_NETWORK_SETSSID      DATAELEMS_NETWORK       "SetSSID()"
/* Device.WiFi.DataElements.Network.SSID */
#define DE_NETWORK_SSID         DATAELEMS_NETWORK       "SSID.{i}."
#define DE_SSID_TABLE           DATAELEMS_NETWORK       "SSID.{i}"
#define DE_SSID_SSID            DE_NETWORK_SSID         "SSID"
#define DE_SSID_BAND            DE_NETWORK_SSID         "Band"
#define DE_SSID_ENABLE          DE_NETWORK_SSID         "Enable"
#define DE_SSID_AKMALLOWE       DE_NETWORK_SSID         "AKMsAllowed"
#define DE_SSID_SUITESEL        DE_NETWORK_SSID         "SuiteSelector"
#define DE_SSID_ADVENABLED      DE_NETWORK_SSID         "AdvertisementEnabled"
#define DE_SSID_MFPCONFIG       DE_NETWORK_SSID         "MFPConfig"
#define DE_SSID_MOBDOMAIN       DE_NETWORK_SSID         "MobilityDomain"
#define DE_SSID_HAULTYPE        DE_NETWORK_SSID         "HaulType"
/* Device.WiFi.DataElements.Network.Device */
#define DE_NETWORK_DEVICE       DATAELEMS_NETWORK       "Device.{i}."
#define DE_DEVICE_TABLE         DATAELEMS_NETWORK       "Device.{i}"
#define DE_DEVICE_ID            DE_NETWORK_DEVICE       "ID"
#define DE_DEVICE_MAPCAP        DE_NETWORK_DEVICE       "MultiAPCapabilities"
#define DE_DEVICE_NUMRADIO      DE_NETWORK_DEVICE       "NumberOfRadios"
#define DE_DEVICE_COLLINT       DE_NETWORK_DEVICE       "CollectionInterval"
#define DE_DEVICE_RUASSOC       DE_NETWORK_DEVICE       "ReportUnsuccessfulAssociations"
#define DE_DEVICE_MAXRRATE      DE_NETWORK_DEVICE       "MaxReportingRate"
#define DE_DEVICE_MAPPROF       DE_NETWORK_DEVICE       "MultiAPProfile"
#define DE_DEVICE_APMERINT      DE_NETWORK_DEVICE       "APMetricsReportingInterval"
#define DE_DEVICE_MANUFACT      DE_NETWORK_DEVICE       "Manufacturer"
#define DE_DEVICE_SERIALNO      DE_NETWORK_DEVICE       "SerialNumber"
#define DE_DEVICE_MFCMODEL      DE_NETWORK_DEVICE       "ManufacturerModel"
#define DE_DEVICE_SWVERSION     DE_NETWORK_DEVICE       "SoftwareVersion"
#define DE_DEVICE_EXECENV       DE_NETWORK_DEVICE       "ExecutionEnv"
#define DE_DEVICE_LSDSTALIST    DE_NETWORK_DEVICE       "LocalSteeringDisallowedSTAList"
#define DE_DEVICE_BTMSDSTALIST  DE_NETWORK_DEVICE       "BTMSteeringDisallowedSTAList"
#define DE_DEVICE_MAXVIDS       DE_NETWORK_DEVICE       "MaxVIDs"
#define DE_DEVICE_BPRIO         DE_NETWORK_DEVICE       "BasicPrioritization"
#define DE_DEVICE_EPRIO         DE_NETWORK_DEVICE       "EnhancedPrioritization"
#define DE_DEVICE_DE8021QPVID   DE_NETWORK_DEVICE       "Default8021Q.PrimaryVID"
#define DE_DEVICE_DE8021QDPCP   DE_NETWORK_DEVICE       "Default8021Q.DefaultPCP"
#define DE_DEVICE_TSEPPOLI      DE_NETWORK_DEVICE       "TrafficSeparationPolicy"
#define DE_DEVICE_STVMAP        DE_NETWORK_DEVICE       "SSIDtoVIDMapping"
#define DE_DEVICE_DSCPM         DE_NETWORK_DEVICE       "DSCPMap"
#define DE_DEVICE_MAXPRIRULE    DE_NETWORK_DEVICE       "MaxPrioritizationRules"
#define DE_DEVICE_COUNTRCODE    DE_NETWORK_DEVICE       "CountryCode"
#define DE_DEVICE_PRIOSUPP      DE_NETWORK_DEVICE       "PrioritizationSupport"
#define DE_DEVICE_REPINDSCAN    DE_NETWORK_DEVICE       "ReportIndependentScans"
#define DE_DEVICE_TRASEPALW     DE_NETWORK_DEVICE       "TrafficSeparationAllowed"
#define DE_DEVICE_SERPRIOALW    DE_NETWORK_DEVICE       "ServicePrioritizationAllowed"
#define DE_DEVICE_STASDISALW    DE_NETWORK_DEVICE       "STASteeringDisallowed"
#define DE_DEVICE_DFSENABLE     DE_NETWORK_DEVICE       "DFSEnable"
#define DE_DEVICE_MAXUSASSOCREPRATE DE_NETWORK_DEVICE   "MaxUnsuccessfulAssociationReportingRate"
#define DE_DEVICE_STASSTATE     DE_NETWORK_DEVICE       "STASteeringState"
#define DE_DEVICE_COORCACALW    DE_NETWORK_DEVICE       "CoordinatedCACAllowed"
#define DE_DEVICE_CONOPMODE     DE_NETWORK_DEVICE       "ControllerOperationMode"
#define DE_DEVICE_BHMACADDR     DE_NETWORK_DEVICE       "BackhaulMACAddress"
#define DE_DEVICE_BHDMACADDR    DE_NETWORK_DEVICE       "BackhaulDownMACAddress"
#define DE_DEVICE_BHPHYRATE     DE_NETWORK_DEVICE       "BackhaulPHYRate"
#define DE_DEVICE_TRSEPCAP      DE_NETWORK_DEVICE       "TrafficSeparationCapability"
#define DE_DEVICE_EASYCCAP      DE_NETWORK_DEVICE       "EasyConnectCapability"
#define DE_DEVICE_TESTCAP       DE_NETWORK_DEVICE       "TestCapabilities"
#define DE_DEVICE_BSTAMLDMACLINK    DE_NETWORK_DEVICE   "bSTAMLDMaxLinks"
#define DE_DEVICE_MACNUMMLDS    DE_NETWORK_DEVICE       "MaxNumMLDs"
#define DE_DEVICE_BHALID        DE_NETWORK_DEVICE       "BackhaulALID"
#define DE_DEVICE_TIDLMAP       DE_NETWORK_DEVICE       "TIDLinkMapping"
#define DE_DEVICE_ASSOCSTAREPINT    DE_NETWORK_DEVICE   "AssociatedSTAReportingInterval"
#define DE_DEVICE_BHMEDIATYPE   DE_NETWORK_DEVICE       "BackhaulMediaType"
#define DE_DEVICE_RADIONOE      DE_NETWORK_DEVICE       "RadioNumberOfEntries"
#define DE_DEVICE_CACSTATNOE    DE_NETWORK_DEVICE       "CACStatusNumberOfEntries"
#define DE_DEVICE_BHDOWNNOE     DE_NETWORK_DEVICE       "BackhaulDownNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus */
#define DE_DEVICE_CACSTAT       DE_NETWORK_DEVICE       "CACStatus.{i}."
#define DE_CACSTAT_TABLE        DE_NETWORK_DEVICE       "CACStatus.{i}"
#define DE_CACSTAT_NONOCCNOE    DE_DEVICE_CACSTAT       "CACNonOccupancyChannelNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACNonOccupancyChannel */
#define DE_CACSTAT_CACNON       DE_DEVICE_CACSTAT       "CACNonOccupancyChannel.{i}."
#define DE_CACNON_TABLE         DE_DEVICE_CACSTAT       "CACNonOccupancyChannel.{i}"
#define DE_CACNON_OPCLASS       DE_CACSTAT_CACNON       "OpClass"
#define DE_CACNON_CHANNEL       DE_CACSTAT_CACNON       "Channel"
#define DE_CACNON_SECONDS       DE_CACSTAT_CACNON       "Seconds"
/* Device.WiFi.DataElements.Network.Device.BackhaulDown */
#define DE_DEVICE_BHDOWN        DE_NETWORK_DEVICE       "BackhaulDown.{i}."
#define DE_BHDOWN_TABLE         DE_NETWORK_DEVICE       "BackhaulDown.{i}"
#define DE_BHDOWN_ALID          DE_DEVICE_BHDOWN        "BackhaulDownALID"
#define DE_BHDOWN_MACADDR       DE_DEVICE_BHDOWN        "BackhaulDownMACAddress"
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice */
#define DE_DEVICE_MAPDEV        DE_NETWORK_DEVICE       "MultiAPDevice."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul */
#define DE_MAPDEV_BACKHAUL      DE_DEVICE_MAPDEV        "Backhaul."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul.Stats */
#define DE_MAPDEVBH_STATS       DE_MAPDEV_BACKHAUL      "Stats."
#define DE_MDBHSTATS_BYTESSNT   DE_MAPDEVBH_STATS       "BytesSent"
#define DE_MDBHSTATS_BYTESRCV   DE_MAPDEVBH_STATS       "BytesReceived"
#define DE_MDBHSTATS_PCKTSSNT   DE_MAPDEVBH_STATS       "PacketsSent"
#define DE_MDBHSTATS_PCKTSRCV   DE_MAPDEVBH_STATS       "PacketsReceived"
#define DE_MDBHSTATS_ERRSSNT    DE_MAPDEVBH_STATS       "ErrorsSent"
#define DE_MDBHSTATS_ERRSRCV    DE_MAPDEVBH_STATS       "ErrorsReceived"
#define DE_MDBHSTATS_LINKUTIL   DE_MAPDEVBH_STATS       "LinkUtilization"
#define DE_MDBHSTATS_SIGNALSTR  DE_MAPDEVBH_STATS       "SignalStrength"
#define DE_MDBHSTATS_LSTDTADLR  DE_MAPDEVBH_STATS       "LastDataDownlinkRate"
#define DE_MDBHSTATS_LSTDTAULR  DE_MAPDEVBH_STATS       "LastDataUplinkRate"
/* Device.WiFi.DataElements.Network.Device.Radio */
#define DE_DEVICE_RADIO         DE_NETWORK_DEVICE       "Radio.{i}."
#define DE_RADIO_TABLE          DE_NETWORK_DEVICE       "Radio.{i}"
#define DE_RADIO_ID             DE_DEVICE_RADIO         "ID"
#define DE_RADIO_ENABLED        DE_DEVICE_RADIO         "Enabled"
#define DE_RADIO_NUMCUROPCLASS  DE_DEVICE_RADIO         "NumberOfCurrOpClass"
#define DE_RADIO_NOISE          DE_DEVICE_RADIO         "Noise"
#define DE_RADIO_UTILIZATION    DE_DEVICE_RADIO         "Utilization"
#define DE_RADIO_TRANSMIT       DE_DEVICE_RADIO         "Transmit"
#define DE_RADIO_RECEIVESELF    DE_DEVICE_RADIO         "ReceiveSelf"
#define DE_RADIO_RECEIVEOTHER   DE_DEVICE_RADIO         "ReceiveOther"
#define DE_RADIO_CHIPVENDOR     DE_DEVICE_RADIO         "ChipsetVendor"
#define DE_RADIO_CURROPNOE      DE_DEVICE_RADIO         "CurrentOperatingClassProfileNumberOfEntries"
#define DE_RADIO_BSSNOE         DE_DEVICE_RADIO         "NumberOfBSS"
#define DE_RADIO_UNASSCSTALIST  DE_DEVICE_RADIO         "UnassociatedStaList"
#define DE_RADIO_NOUNASSCSTA    DE_DEVICE_RADIO         "NumberOfUnassocSta"
/* Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta */
#define DE_RADIO_BHSTA          DE_DEVICE_RADIO         "BackhaulSta."
#define DE_BHSTA_MACADDR        DE_RADIO_BHSTA          "MACAddress"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities */
#define DE_RADIO_CAPS           DE_DEVICE_RADIO         "Capabilities."
#define DE_RCAPS_HTCAPS         DE_RADIO_CAPS           "HTCapabilities"
#define DE_RCAPS_VHTCAPS        DE_RADIO_CAPS           "VHTCapabilities"
#define DE_RCAPS_MSCS_CAP       DE_RADIO_CAPS           "MSCSCapability"
#define DE_RCAPS_SCS_CAP        DE_RADIO_CAPS           "SCSCapability"
#define DE_RCAPS_QOSMAP_CAP     DE_RADIO_CAPS           "QoSMapCapability"
#define DE_RCAPS_DSCP_POLICY    DE_RADIO_CAPS           "DSCPPolicyCapability"
#define DE_RCAPS_SCSTRAFDESC    DE_RADIO_CAPS           "SCSTrafficDescriptionCapability"
#define DE_RCAPS_CAPOPNOE       DE_RADIO_CAPS           "CapableOperatingClassProfileNumberOfEntries"
#define DE_RCAPS_AKMFHNOE       DE_RADIO_CAPS           "AKMFrontHaulNumberOfEntries"
#define DE_RCAPS_AKMBHNOE       DE_RADIO_CAPS           "AKMBackHaulNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6APRole */
#define DE_CAPS_WF6AP           DE_RADIO_CAPS           "WiFi6APRole."
#define DE_WF6AP_HE160          DE_CAPS_WF6AP           "HE160"
#define DE_WF6AP_HE8080         DE_CAPS_WF6AP           "HE8080"
#define DE_WF6AP_MCSNSS         DE_CAPS_WF6AP           "MCSNSS"
#define DE_WF6AP_SU_BFER        DE_CAPS_WF6AP           "SUBeamformer"
#define DE_WF6AP_SU_BFEE        DE_CAPS_WF6AP           "SUBeamformee"
#define DE_WF6AP_MU_BFER        DE_CAPS_WF6AP           "MUBeamformer"
#define DE_WF6AP_BFEE_80L       DE_CAPS_WF6AP           "Beamformee80orLess"
#define DE_WF6AP_BFEE_80A       DE_CAPS_WF6AP           "BeamformeeAbove80"
#define DE_WF6AP_UL_MUMIMO      DE_CAPS_WF6AP           "ULMUMIMO"
#define DE_WF6AP_UL_OFDMA       DE_CAPS_WF6AP           "ULOFDMA"
#define DE_WF6AP_DL_OFDMA       DE_CAPS_WF6AP           "DLOFDMA"
#define DE_WF6AP_MAX_DL_MUMIMO  DE_CAPS_WF6AP           "MaxDLMUMIMO"
#define DE_WF6AP_MAX_UL_MUMIMO  DE_CAPS_WF6AP           "MaxULMUMIMO"
#define DE_WF6AP_MAX_DL_OF      DE_CAPS_WF6AP           "MaxDLOFDMA"
#define DE_WF6AP_MAX_UL_OF      DE_CAPS_WF6AP           "MaxULOFDMA"
#define DE_WF6AP_RTS            DE_CAPS_WF6AP           "RTS"
#define DE_WF6AP_MU_RTS         DE_CAPS_WF6AP           "MURTS"
#define DE_WF6AP_MULTI_BSS      DE_CAPS_WF6AP           "MultiBSSID"
#define DE_WF6AP_MU_EDCA        DE_CAPS_WF6AP           "MUEDCA"
#define DE_WF6AP_TWT_REQ        DE_CAPS_WF6AP           "TWTRequestor"
#define DE_WF6AP_TWT_RSP        DE_CAPS_WF6AP           "TWTResponder"
#define DE_WF6AP_SPAT_REUSE     DE_CAPS_WF6AP           "SpatialReuse"
#define DE_WF6AP_ANT_CH_USE     DE_CAPS_WF6AP           "AnticipatedChannelUsage"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6bSTARole */
#define DE_CAPS_WF6BSTA         DE_RADIO_CAPS           "WiFi6bSTARole."
#define DE_WF6BSTA_HE160        DE_CAPS_WF6BSTA         "HE160"
#define DE_WF6BSTA_MCSNSS       DE_CAPS_WF6BSTA         "MCSNSS"
#define DE_WF6BSTA_SU_BFER      DE_CAPS_WF6BSTA         "SUBeamformer"
#define DE_WF6BSTA_SU_BFEE      DE_CAPS_WF6BSTA         "SUBeamformee"
#define DE_WF6BSTA_MU_BFER      DE_CAPS_WF6BSTA         "MUBeamformer"
#define DE_WF6BSTA_BFEE_80_LESS DE_CAPS_WF6BSTA         "Beamformee80orLess"
#define DE_WF6BSTA_BFEE_ABV_80  DE_CAPS_WF6BSTA         "BeamformeeAbove80"
#define DE_WF6BSTA_UL_MUMIMO    DE_CAPS_WF6BSTA         "ULMUMIMO"
#define DE_WF6BSTA_UL_OFDMA     DE_CAPS_WF6BSTA         "ULOFDMA"
#define DE_WF6BSTA_DL_OFDMA     DE_CAPS_WF6BSTA         "DLOFDMA"
#define DE_WF6BSTA_MAX_DL_MUMIMO    DE_CAPS_WF6BSTA     "MaxDLMUMIMO"
#define DE_WF6BSTA_MAX_UL_MUMIMO    DE_CAPS_WF6BSTA     "MaxULMUMIMO"
#define DE_WF6BSTA_MAX_DL_OFDMA DE_CAPS_WF6BSTA         "MaxDLOFDMA"
#define DE_WF6BSTA_MAX_UL_OFDMA DE_CAPS_WF6BSTA         "MaxULOFDMA"
#define DE_WF6BSTA_RTS          DE_CAPS_WF6BSTA         "RTS"
#define DE_WF6BSTA_MU_RTS       DE_CAPS_WF6BSTA         "MURTS"
#define DE_WF6BSTA_MULTI_BSSID  DE_CAPS_WF6BSTA         "MultiBSSID"
#define DE_WF6BSTA_MUEDCA       DE_CAPS_WF6BSTA         "MUEDCA"
#define DE_WF6BSTA_TWT_REQ      DE_CAPS_WF6BSTA         "TWTRequestor"
#define DE_WF6BSTA_TWT_RSP      DE_CAPS_WF6BSTA         "TWTResponder"
#define DE_WF6BSTA_SPATIAL_REUSE    DE_CAPS_WF6BSTA     "SpatialReuse"
#define DE_WF6BSTA_ANT_CH_USAGE DE_CAPS_WF6BSTA         "AnticipatedChannelUsage"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.CapableOperatingClassProfile */
#define DE_CAPS_CAPOP           DE_DEVICE_RADIO         "CapableOperatingClassProfile.{i}."
#define DE_CAPOP_TABLE          DE_DEVICE_RADIO         "CapableOperatingClassProfile.{i}"
#define DE_CAPOP_CLASS          DE_CAPS_CAPOP           "Class"
#define DE_CAPOP_MAXTXPOWER     DE_CAPS_CAPOP           "MaxTxPower"
#define DE_CAPOP_NONOPERABLE    DE_CAPS_CAPOP           "NonOperable"
#define DE_CAPOP_NONOPCNT       DE_CAPS_CAPOP           "NumberOfNonOperChan"
/* Device.WiFi.DataElements.Network.Device.Radio.CurrentOperatingClassProfile */
#define DE_RADIO_CUROP          DE_DEVICE_RADIO         "CurrentOperatingClassProfile.{i}."
#define DE_CUROP_TABLE          DE_DEVICE_RADIO         "CurrentOperatingClassProfile.{i}"
#define DE_CUROP_CLASS          DE_RADIO_CUROP          "Class"
#define DE_CUROP_CHANNEL        DE_RADIO_CUROP          "Channel"
#define DE_CUROP_TXPOWER        DE_RADIO_CUROP          "TxPower"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi7APRole */
#define DE_CAPS_WF7AP           DE_RADIO_CAPS           "WiFi7APRole."
#define DE_WF7AP_EMLMR          DE_CAPS_WF7AP           "EMLMRSupport"
#define DE_WF7AP_EMLSR          DE_CAPS_WF7AP           "EMLSRSupport"
#define DE_WF7AP_STR            DE_CAPS_WF7AP           "STRSupport"
#define DE_WF7AP_NSTR           DE_CAPS_WF7AP           "NSTRSupport"
#define DE_WF7AP_TID_MAP        DE_CAPS_WF7AP           "TIDLinkMapNegotiation"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi7bSTARole */
#define DE_CAPS_WF7BSTA         DE_DEVICE_RADIO         "WiFi7bSTARole."
#define DE_WF7BSTA_EMLMR        DE_CAPS_WF7BSTA         "EMLMRSupport"
#define DE_WF7BSTA_EMLSR        DE_CAPS_WF7BSTA         "EMLSRSupport"
#define DE_WF7BSTA_STR          DE_CAPS_WF7BSTA         "STRSupport"
#define DE_WF7BSTA_NSTR         DE_CAPS_WF7BSTA         "NSTRSupport"
#define DE_WF7BSTA_TID_MAP      DE_CAPS_WF7BSTA         "TIDLinkMapNegotiation"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.ScanCapability */
#define DE_CAPS_SCANCAP         DE_DEVICE_RADIO         "ScanCapability."
#define DE_SCANCAP_TIMESTAMP    DE_CAPS_SCANCAP         "TimeStamp"
#define DE_SCANCAP_OPCLSCANSNOE DE_CAPS_SCANCAP         "NumberOfOpClassScans"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS */
#define DE_RADIO_BSS            DE_DEVICE_RADIO         "BSS.{i}."
#define DE_BSS_TABLE            DE_DEVICE_RADIO         "BSS.{i}"
#define DE_BSS_BSSID            DE_RADIO_BSS            "BSSID"
#define DE_BSS_SSID             DE_RADIO_BSS            "SSID"
#define DE_BSS_ENABLED          DE_RADIO_BSS            "Enabled"
#define DE_BSS_LASTCHG          DE_RADIO_BSS            "LastChange"
#define DE_BSS_TS               DE_RADIO_BSS            "TimeStamp"
#define DE_BSS_UCAST_TX         DE_RADIO_BSS            "UnicastBytesSent"
#define DE_BSS_UCAST_RX         DE_RADIO_BSS            "UnicastBytesReceived"
#define DE_BSS_MCAST_TX         DE_RADIO_BSS            "MulticastBytesSent"
#define DE_BSS_MCAST_RX         DE_RADIO_BSS            "MulticastBytesReceived"
#define DE_BSS_BCAST_TX         DE_RADIO_BSS            "BroadcastBytesSent"
#define DE_BSS_BCAST_RX         DE_RADIO_BSS            "BroadcastBytesReceived"
#define DE_BSS_EST_BE           DE_RADIO_BSS            "EstServiceParametersBE"
#define DE_BSS_EST_BK           DE_RADIO_BSS            "EstServiceParametersBK"
#define DE_BSS_EST_VI           DE_RADIO_BSS            "EstServiceParametersVI"
#define DE_BSS_EST_VO           DE_RADIO_BSS            "EstServiceParametersVO"
#define DE_BSS_BYTCNTUNITS      DE_RADIO_BSS            "ByteCounterUnits"
#define DE_BSS_PROF1_DIS        DE_RADIO_BSS            "Profile1bSTAsDisallowed"
#define DE_BSS_PROF2_DIS        DE_RADIO_BSS            "Profile2bSTAsDisallowed"
#define DE_BSS_ASSOC_STAT       DE_RADIO_BSS            "AssociationAllowanceStatus"
#define DE_BSS_BHAULUSE         DE_RADIO_BSS            "BackhaulUse"
#define DE_BSS_FHAULUSE         DE_RADIO_BSS            "FronthaulUse"
#define DE_BSS_R1_DIS           DE_RADIO_BSS            "R1disallowed"
#define DE_BSS_R2_DIS           DE_RADIO_BSS            "R2disallowed"
#define DE_BSS_MULTI_BSSID      DE_RADIO_BSS            "MultiBSSID"
#define DE_BSS_TX_BSSID         DE_RADIO_BSS            "TransmittedBSSID"
#define DE_BSS_FHAULAKMS        DE_RADIO_BSS            "FronthaulAKMsAllowed"
#define DE_BSS_BHAULAKMS        DE_RADIO_BSS            "BackhaulAKMsAllowed"
#define DE_BSS_QM_DESC          DE_RADIO_BSS            "QMDescriptor"
#define DE_BSS_NUM_STA          DE_RADIO_BSS            "NumberOfSTA"
#define DE_BSS_LINK_IMM         DE_RADIO_BSS            "LinkRemovalImminent"
#define DE_BSS_FH_SUITE         DE_RADIO_BSS            "FronthaulSuiteSelector"
#define DE_BSS_BH_SUITE         DE_RADIO_BSS            "BackhaulSuiteSelector"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA */
#define DE_BSS_STA              DE_RADIO_BSS            "STA.{i}."
#define DE_STA_TABLE            DE_RADIO_BSS            "STA.{i}"
#define DE_STA_MACADDR          DE_BSS_STA              "MACAddress"
#define DE_STA_HTCAPS           DE_BSS_STA              "HTCapabilities"
#define DE_STA_VHTCAPS          DE_BSS_STA              "VHTCapabilities"
#define DE_STA_CLIENTCAPS       DE_BSS_STA              "ClientCapabilities"
#define DE_STA_LSTDTADLR        DE_BSS_STA              "LastDataDownlinkRate"
#define DE_STA_LSTDTAULR        DE_BSS_STA              "LastDataUplinkRate"
#define DE_STA_UTILRECV         DE_BSS_STA              "UtilizationReceive"
#define DE_STA_UTILTRMT         DE_BSS_STA              "UtilizationTransmit"
#define DE_STA_ESTMACDTARDL     DE_BSS_STA              "EstMACDataRateDownlink"
#define DE_STA_ESTMACDTARUL     DE_BSS_STA              "EstMACDataRateUplink"
#define DE_STA_SIGNALSTR        DE_BSS_STA              "SignalStrength"
#define DE_STA_LASTCONNTIME     DE_BSS_STA              "LastConnectTime"
#define DE_STA_BYTESSNT         DE_BSS_STA              "BytesSent"
#define DE_STA_BYTESRCV         DE_BSS_STA              "BytesReceived"
#define DE_STA_PCKTSSNT         DE_BSS_STA              "PacketsSent"
#define DE_STA_PCKTSRCV         DE_BSS_STA              "PacketsReceived"
#define DE_STA_ERRSSNT          DE_BSS_STA              "ErrorsSent"
#define DE_STA_ERRSRCV          DE_BSS_STA              "ErrorsReceived"
#define DE_STA_RETRANSCNT       DE_BSS_STA              "RetransCount"
#define DE_STA_IPV4ADDR         DE_BSS_STA              "IPV4Address"
#define DE_STA_IPV6ADDR         DE_BSS_STA              "IPV6Address"
#define DE_STA_HOSTNAME         DE_BSS_STA              "Hostname"
#define DE_STA_PAIRWSAKM        DE_BSS_STA              "PairwiseAKM"
#define DE_STA_PAIRWSCIPHER     DE_BSS_STA              "PairwiseCipher"
#define DE_STA_RSNCAPS          DE_BSS_STA              "RSNCapabilities"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.WiFi6Capabilities */
#define DE_STA_WIFI6CAPS        DE_BSS_STA              "WiFi6Capabilities."
#define DE_STAWF6CAPS_HE160     DE_STA_WIFI6CAPS        "HE160"
#define DE_STAWF6CAPS_MCSNSS    DE_STA_WIFI6CAPS        "MCSNSS"
/* Device.WiFi.DataElements.Network.Device.APMLD */
#define DE_DEVICE_APMLD         DE_NETWORK_DEVICE       "APMLD.{i}."
#define DE_APMLD_TABLE          DE_NETWORK_DEVICE       "APMLD.{i}"
#define DE_APMLD_MACADDRESS     DE_DEVICE_APMLD         "MLDMACAddress"
#define DE_APMLD_AFFAPNOE       DE_DEVICE_APMLD         "AffiliatedAPNumberOfEntries"
#define DE_APMLD_STAMLDNOE      DE_DEVICE_APMLD         "STAMLDNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.APMLD.APMLDConfig */
#define DE_APMLD_CONFIG         DE_DEVICE_APMLD         "APMLDConfig."
#define DE_APMLDCFG_EMLMR       DE_APMLD_CONFIG         "EMLMREnabled"
#define DE_APMLDCFG_EMLSR       DE_APMLD_CONFIG         "EMLSREnabled"
#define DE_APMLDCFG_STR         DE_APMLD_CONFIG         "STREnabled"
#define DE_APMLDCFG_NSTR        DE_APMLD_CONFIG         "NSTREnabled"
/* Device.WiFi.DataElements.Network.Device.APMLD.AffiliatedAP */
#define DE_APMLD_AFFAP          DE_DEVICE_APMLD         "AffiliatedAP.{i}."
#define DE_AFFAP_TABLE          DE_DEVICE_APMLD         "AffiliatedAP.{i}"
#define DE_AFFAP_BSSID          DE_APMLD_AFFAP          "BSSID"
#define DE_AFFAP_LINKID         DE_APMLD_AFFAP          "LinkID"
#define DE_AFFAP_RUID           DE_APMLD_AFFAP          "RUID"
#define DE_AFFAP_PCKTSSNT       DE_APMLD_AFFAP          "PacketsSent"
#define DE_AFFAP_PCKTSRCV       DE_APMLD_AFFAP          "PacketsReceived"
#define DE_AFFAP_ERRSSNT        DE_APMLD_AFFAP          "ErrorsSent"
#define DE_AFFAP_UCBYTESSNT     DE_APMLD_AFFAP          "UnicastBytesSent"
#define DE_AFFAP_UCBYTESRCV     DE_APMLD_AFFAP          "UnicastBytesReceived"
#define DE_AFFAP_MCBYTESSNT     DE_APMLD_AFFAP          "MulticastBytesSent"
#define DE_AFFAP_MCBYTESRCV     DE_APMLD_AFFAP          "MulticastBytesReceived"
#define DE_AFFAP_BCBYTESSNT     DE_APMLD_AFFAP          "BroadcastBytesSent"
#define DE_AFFAP_BCBYTESRCV     DE_APMLD_AFFAP          "BroadcastBytesReceived"
/* Device.WiFi.DataElements.Network.Device.APMLD.STAMLD */
#define DE_APMLD_STAMLD         DE_DEVICE_APMLD         "STAMLD.{i}."
#define DE_STAMLD_TABLE         DE_DEVICE_APMLD         "STAMLD.{i}"
#define DE_STAMLD_MLDMACADDR    DE_APMLD_STAMLD         "MLDMACAddress"
#define DE_STAMLD_ISBSTA        DE_APMLD_STAMLD         "IsbSTA"
#define DE_STAMLD_LASTCONTME    DE_APMLD_STAMLD         "LastConnectTime"
#define DE_STAMLD_BYTESSNT      DE_APMLD_STAMLD         "BytesReceived"
#define DE_STAMLD_BYTESRCV      DE_APMLD_STAMLD         "BytesSent"
#define DE_STAMLD_PCKTSSNT      DE_APMLD_STAMLD         "PacketsReceived"
#define DE_STAMLD_PCKTSRCV      DE_APMLD_STAMLD         "PacketsSent"
#define DE_STAMLD_ERRSSNT       DE_APMLD_STAMLD         "ErrorsReceived"
#define DE_STAMLD_ERRSRCVD      DE_APMLD_STAMLD         "ErrorsSent"
#define DE_STAMLD_RETRANSCNT    DE_APMLD_STAMLD         "RetransCount"
#define DE_STAMLD_AFFSTANOE     DE_APMLD_STAMLD         "AffiliatedSTANumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.APMLD.STAMLD.WiFi7Capabilities */
#define DE_STAMLD_WIFI7CAPS     DE_APMLD_STAMLD         "WiFi7Capabilities."
#define DE_WIFI7CAPS_EMLMR      DE_STAMLD_WIFI7CAPS     "EMLMRSupport"
#define DE_WIFI7CAPS_EMLSR      DE_STAMLD_WIFI7CAPS     "EMLSRSupport"
#define DE_WIFI7CAPS_STR        DE_STAMLD_WIFI7CAPS     "STRSupport"
#define DE_WIFI7CAPS_NSTR       DE_STAMLD_WIFI7CAPS     "NSTRSupport"
/* Device.WiFi.DataElements.Network.Device.APMLD.STAMLD.STAMLDConfig */
#define DE_STAMLD_CONFIG        DE_APMLD_STAMLD         "STAMLDConfig."
#define DE_STAMLDCFG_EMLMR      DE_STAMLD_CONFIG        "EMLMREnabled"
#define DE_STAMLDCFG_EMLSR      DE_STAMLD_CONFIG        "EMLSREnabled"
#define DE_STAMLDCFG_STR        DE_STAMLD_CONFIG        "STREnabled"
#define DE_STAMLDCFG_NSTR       DE_STAMLD_CONFIG        "NSTREnabled"
/* Device.WiFi.DataElements.Network.Device.APMLD.STAMLD.AffiliatedSTA */
#define DE_STAMLD_AFFSTA        DE_APMLD_STAMLD         "AffiliatedSTA.{i}."
#define DE_AFFSTA_TABLE         DE_APMLD_STAMLD         "AffiliatedSTA.{i}"
#define DE_AFFSTA_MACADDR       DE_STAMLD_AFFSTA        "MACAddress"
#define DE_AFFSTA_BSSID         DE_STAMLD_AFFSTA        "BSSID"
#define DE_AFFSTA_BYTESSNT      DE_STAMLD_AFFSTA        "BytesSent"
#define DE_AFFSTA_BYTESRCV      DE_STAMLD_AFFSTA        "BytesReceived"
#define DE_AFFSTA_PCKTSSNT      DE_STAMLD_AFFSTA        "PacketsSent"
#define DE_AFFSTA_PCKTSRCV      DE_STAMLD_AFFSTA        "PacketsReceived"
#define DE_AFFSTA_ERRSSNT       DE_STAMLD_AFFSTA        "ErrorsSent"
#define DE_AFFSTA_SIGNALSTR     DE_STAMLD_AFFSTA        "SignalStrength"
#define DE_AFFSTA_ESTMACDRDL    DE_STAMLD_AFFSTA        "EstMACDataRateDownlink"
#define DE_AFFSTA_ESTMACDRUL    DE_STAMLD_AFFSTA        "EstMACDataRateUplink"
/* Device.WiFi.DataElements.Network.Device.bSTAMLD */
#define DE_DEVICE_BSTAMLD       DE_NETWORK_DEVICE       "bSTAMLD."
#define DE_BSTAMLD_MACADDR      DE_DEVICE_BSTAMLD       "MLDMACAddress"
#define DE_BSTAMLD_BSSID        DE_DEVICE_BSTAMLD       "BSSID"
#define DE_BSTAMLD_AFFBSTAS     DE_DEVICE_BSTAMLD       "AffiliatedbSTAList"
/* Device.WiFi.DataElements.Network.Device.bSTAMLD.bSTAMLDConfig */
#define DE_BSTAMLD_CONFIG       DE_DEVICE_BSTAMLD       "bSTAMLDConfig."
#define DE_BSTACFG_EMLMR        DE_BSTAMLD_CONFIG       "EMLMREnabled"
#define DE_BSTACFG_EMLSR        DE_BSTAMLD_CONFIG       "EMLSREnabled"
#define DE_BSTACFG_STR          DE_BSTAMLD_CONFIG       "STREnabled"
#define DE_BSTACFG_NSTR         DE_BSTAMLD_CONFIG       "NSTREnabled"

typedef struct wfa_dml_data_model {
    uint32_t table_de_device_index;
    uint32_t table_de_radio_index;
    uint32_t table_de_bss_index;
    uint32_t table_de_sta_index;
    uint32_t table_de_ssid_index;
    uint32_t table_de_apmld_index;
    uint32_t table_de_stamld_index;
} wfa_dml_data_model_t;

/**
 * @brief Set bus callback function pointers for WFA Data Elements
 * 
 * This function assigns appropriate callback functions for WFA Data Elements
 * namespaces. It maps WFA-specific paths to their corresponding handler functions.
 * 
 * @param full_namespace The complete WFA namespace path (e.g., "Device.WiFi.DataElements.Network.Radio.{i}")
 * @param cb_table Pointer to the callback table to populate
 * @return RETURN_OK on success, RETURN_ERR on failure
 */
int wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table);

bus_error_t wfa_elem_num_of_table_row(char *event_name, uint32_t *table_row_size);

bus_error_t default_wfa_table_add_row_handler(char const* tableName, char const* aliasName, uint32_t* instNum);

#endif // WFA_DATA_MODEL_H