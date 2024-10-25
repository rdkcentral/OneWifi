/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>
#include "const.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include <netinet/in.h>
#include <time.h>
#include <openssl/sha.h>

/* enable PID in debug logs */
#define __ENABLE_PID__     0

/* local helper functions */
static wifi_interface_name_idex_map_t* get_vap_index_property(wifi_platform_property_t *wifi_prop, unsigned int vap_index, const char *func);
static wifi_interface_name_idex_map_t* get_vap_name_property(wifi_platform_property_t *wifi_prop, char *vap_name, const char *func);
static wifi_interface_name_idex_map_t* get_ifname_property(wifi_platform_property_t *wifi_prop, const char *if_name, const char *func);

void test_names(wifi_platform_property_t *wifi_prop);

#define GET_VAP_INDEX_PROPERTY(wifi_prop, vap_index) ({wifi_interface_name_idex_map_t *__if_prop = get_vap_index_property(wifi_prop, vap_index, __func__); __if_prop;})
#define GET_VAP_NAME_PROPERTY(wifi_prop, vap_name)   ({wifi_interface_name_idex_map_t *__if_prop = get_vap_name_property(wifi_prop, vap_name, __func__); __if_prop;})
#define GET_IFNAME_PROPERTY(wifi_prop, if_name)      ({wifi_interface_name_idex_map_t *__if_prop = get_ifname_property(wifi_prop, if_name, __func__); __if_prop;})

#define TOTAL_VAPS(vaps, wifi_prop) {\
    do {\
        vaps = 0;\
        for (unsigned int i = 0; i < wifi_prop->numRadios; ++i) {\
            vaps += wifi_prop->radiocap[i].maxNumberVAPs;\
        }\
    } while(0);\
}

#define TOTAL_INTERFACES(num_iface, wifi_prop) {\
    do {\
        num_iface = 0;\
        for(UINT i = 0; i < wifi_prop->numRadios*MAX_NUM_VAP_PER_RADIO; ++i) {\
            if ((wifi_prop->interface_map[i].interface_name[0] != '\0') && (wifi_prop->interface_map[i].vap_name[0] != '\0')) {\
                ++num_iface;\
            }\
        }\
    } while (0);\
}

struct wifiCountryEnumStrMap wifiCountryMap[] =
{
    {wifi_countrycode_AC,"AC"}, /**< ASCENSION ISLAND */
    {wifi_countrycode_AD,"AD"}, /**< ANDORRA */
    {wifi_countrycode_AE,"AE"}, /**< UNITED ARAB EMIRATES */
    {wifi_countrycode_AF,"AF"}, /**< AFGHANISTAN */
    {wifi_countrycode_AG,"AG"}, /**< ANTIGUA AND BARBUDA */
    {wifi_countrycode_AI,"AI"}, /**< ANGUILLA */
    {wifi_countrycode_AL,"AL"}, /**< ALBANIA */
    {wifi_countrycode_AM,"AM"}, /**< ARMENIA */
    {wifi_countrycode_AN,"AN"}, /**< NETHERLANDS ANTILLES */
    {wifi_countrycode_AO,"AO"}, /**< ANGOLA */
    {wifi_countrycode_AQ,"AQ"}, /**< ANTARCTICA */
    {wifi_countrycode_AR,"AR"}, /**< ARGENTINA */
    {wifi_countrycode_AS,"AS"}, /**< AMERICAN SAMOA */
    {wifi_countrycode_AT,"AT"}, /**< AUSTRIA */
    {wifi_countrycode_AU,"AU"}, /**< AUSTRALIA */
    {wifi_countrycode_AW,"AW"}, /**< ARUBA */
    {wifi_countrycode_AZ,"AZ"}, /**< AZERBAIJAN */
    {wifi_countrycode_BA,"BA"}, /**< BOSNIA AND HERZEGOVINA */
    {wifi_countrycode_BB,"BB"}, /**< BARBADOS */
    {wifi_countrycode_BD,"BD"}, /**< BANGLADESH */
    {wifi_countrycode_BE,"BE"}, /**< BELGIUM */
    {wifi_countrycode_BF,"BF"}, /**< BURKINA FASO */
    {wifi_countrycode_BG,"BG"}, /**< BULGARIA */
    {wifi_countrycode_BH,"BH"}, /**< BAHRAIN */
    {wifi_countrycode_BI,"BI"}, /**< BURUNDI */
    {wifi_countrycode_BJ,"BJ"}, /**< BENIN */
    {wifi_countrycode_BM,"BM"}, /**< BERMUDA */
    {wifi_countrycode_BN,"BN"}, /**< BRUNEI DARUSSALAM */
    {wifi_countrycode_BO,"BO"}, /**< BOLIVIA */
    {wifi_countrycode_BR,"BR"}, /**< BRAZIL */
    {wifi_countrycode_BS,"BS"}, /**< BAHAMAS */
    {wifi_countrycode_BT,"BT"}, /**< BHUTAN */
    {wifi_countrycode_BV,"BV"}, /**< BOUVET ISLAND */
    {wifi_countrycode_BW,"BW"}, /**< BOTSWANA */
    {wifi_countrycode_BY,"BY"}, /**< BELARUS */
    {wifi_countrycode_BZ,"BZ"}, /**< BELIZE */
    {wifi_countrycode_CA,"CA"}, /**< CANADA */
    {wifi_countrycode_CC,"CC"}, /**< COCOS (KEELING) ISLANDS */
    {wifi_countrycode_CD,"CD"}, /**< CONGO,THE DEMOCRATIC REPUBLIC OF THE */
    {wifi_countrycode_CF,"CF"}, /**< CENTRAL AFRICAN REPUBLIC */
    {wifi_countrycode_CG,"CG"}, /**< CONGO */
    {wifi_countrycode_CH,"CH"}, /**< SWITZERLAND */
    {wifi_countrycode_CI,"CI"}, /**< COTE D'IVOIRE */
    {wifi_countrycode_CK,"CK"}, /**< COOK ISLANDS */
    {wifi_countrycode_CL,"CL"}, /**< CHILE */
    {wifi_countrycode_CM,"CM"}, /**< CAMEROON */
    {wifi_countrycode_CN,"CN"}, /**< CHINA */
    {wifi_countrycode_CO,"CO"}, /**< COLOMBIA */
    {wifi_countrycode_CP,"CP"}, /**< CLIPPERTON ISLAND */
    {wifi_countrycode_CR,"CR"}, /**< COSTA RICA */
    {wifi_countrycode_CU,"CU"}, /**< CUBA */
    {wifi_countrycode_CV,"CV"}, /**< CAPE VERDE */
    {wifi_countrycode_CY,"CY"}, /**< CYPRUS */
    {wifi_countrycode_CX,"CX"}, /**< CHRISTMAS ISLAND */
    {wifi_countrycode_CZ,"CZ"}, /**< CZECH REPUBLIC */
    {wifi_countrycode_DE,"DE"}, /**< GERMANY */
    {wifi_countrycode_DJ,"DJ"}, /**< DJIBOUTI */
    {wifi_countrycode_DK,"DK"}, /**< DENMARK */
    {wifi_countrycode_DM,"DM"}, /**< DOMINICA */
    {wifi_countrycode_DO,"DO"}, /**< DOMINICAN REPUBLIC */
    {wifi_countrycode_DZ,"DZ"}, /**< ALGERIA */
    {wifi_countrycode_EC,"EC"}, /**< ECUADOR */
    {wifi_countrycode_EE,"EE"}, /**< ESTONIA */
    {wifi_countrycode_EG,"EG"}, /**< EGYPT */
    {wifi_countrycode_EH,"EH"}, /**< WESTERN SAHARA */
    {wifi_countrycode_ER,"ER"}, /**< ERITREA */
    {wifi_countrycode_ES,"ES"}, /**< SPAIN */
    {wifi_countrycode_ET,"ET"}, /**< ETHIOPIA */
    {wifi_countrycode_FI,"FI"}, /**< FINLAND */
    {wifi_countrycode_FJ,"FJ"}, /**< FIJI */
    {wifi_countrycode_FK,"FK"}, /**< FALKLAND ISLANDS (MALVINAS) */
    {wifi_countrycode_FM,"FM"}, /**< MICRONESIA FEDERATED STATES OF */
    {wifi_countrycode_FO,"FO"}, /**< FAROE ISLANDS */
    {wifi_countrycode_FR,"FR"}, /**< FRANCE */
    {wifi_countrycode_GA,"GA"}, /**< GABON */
    {wifi_countrycode_GB,"GB"}, /**< UNITED KINGDOM */
    {wifi_countrycode_GD,"GD"}, /**< GRENADA */
    {wifi_countrycode_GE,"GE"}, /**< GEORGIA */
    {wifi_countrycode_GF,"GF"}, /**< FRENCH GUIANA */
    {wifi_countrycode_GG,"GG"}, /**< GUERNSEY */
    {wifi_countrycode_GH,"GH"}, /**< GHANA */
    {wifi_countrycode_GI,"GI"}, /**< GIBRALTAR */
    {wifi_countrycode_GL,"GL"}, /**< GREENLAND */
    {wifi_countrycode_GM,"GM"}, /**< GAMBIA */
    {wifi_countrycode_GN,"GN"}, /**< GUINEA */
    {wifi_countrycode_GP,"GP"}, /**< GUADELOUPE */
    {wifi_countrycode_GQ,"GQ"}, /**< EQUATORIAL GUINEA */
    {wifi_countrycode_GR,"GR"}, /**< GREECE */
    {wifi_countrycode_GS,"GS"}, /**< SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS */
    {wifi_countrycode_GT,"GT"}, /**< GUATEMALA */
    {wifi_countrycode_GU,"GU"}, /**< GUAM */
    {wifi_countrycode_GW,"GW"}, /**< GUINEA-BISSAU */
    {wifi_countrycode_GY,"GY"}, /**< GUYANA */
    {wifi_countrycode_HR,"HR"}, /**< CROATIA */
    {wifi_countrycode_HT,"HT"}, /**< HAITI */
    {wifi_countrycode_HM,"HM"}, /**< HEARD ISLAND AND MCDONALD ISLANDS */
    {wifi_countrycode_HN,"HN"}, /**< HONDURAS */
    {wifi_countrycode_HK,"HK"}, /**< HONG KONG */
    {wifi_countrycode_HU,"HU"}, /**< HUNGARY */
    {wifi_countrycode_IS,"IS"}, /**< ICELAND */
    {wifi_countrycode_IN,"IN"}, /**< INDIA */
    {wifi_countrycode_ID,"ID"}, /**< INDONESIA */
    {wifi_countrycode_IR,"IR"}, /**< IRAN, ISLAMIC REPUBLIC OF */
    {wifi_countrycode_IQ,"IQ"}, /**< IRAQ */
    {wifi_countrycode_IE,"IE"}, /**< IRELAND */
    {wifi_countrycode_IL,"IL"}, /**< ISRAEL */
    {wifi_countrycode_IM,"IM"}, /**< MAN, ISLE OF */
    {wifi_countrycode_IT,"IT"}, /**< ITALY */
    {wifi_countrycode_IO,"IO"}, /**< BRITISH INDIAN OCEAN TERRITORY */
    {wifi_countrycode_JM,"JM"}, /**< JAMAICA */
    {wifi_countrycode_JP,"JP"}, /**< JAPAN */
    {wifi_countrycode_JE,"JE"}, /**< JERSEY */
    {wifi_countrycode_JO,"jo"}, /**< JORDAN */
    {wifi_countrycode_KE,"KE"}, /**< KENYA */
    {wifi_countrycode_KG,"KG"}, /**< KYRGYZSTAN */
    {wifi_countrycode_KH,"KH"}, /**< CAMBODIA */
    {wifi_countrycode_KI,"KI"}, /**< KIRIBATI */
    {wifi_countrycode_KM,"KM"}, /**< COMOROS */
    {wifi_countrycode_KN,"KN"}, /**< SAINT KITTS AND NEVIS */
    {wifi_countrycode_KP,"KP"}, /**< KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF */
    {wifi_countrycode_KR,"KR"}, /**< KOREA, REPUBLIC OF */
    {wifi_countrycode_KW,"KW"}, /**< KUWAIT */
    {wifi_countrycode_KY,"KY"}, /**< CAYMAN ISLANDS */
    {wifi_countrycode_KZ,"KZ"}, /**< KAZAKHSTAN */
    {wifi_countrycode_LA,"LA"}, /**< LAO PEOPLE'S DEMOCRATIC REPUBLIC */
    {wifi_countrycode_LB,"LB"}, /**< LEBANON */
    {wifi_countrycode_LC,"LC"}, /**< SAINT LUCIA */
    {wifi_countrycode_LI,"LI"}, /**< LIECHTENSTEIN */
    {wifi_countrycode_LK,"LK"}, /**< SRI LANKA */
    {wifi_countrycode_LR,"LR"}, /**< LIBERIA */
    {wifi_countrycode_LS,"LS"}, /**< LESOTHO */
    {wifi_countrycode_LT,"LT"}, /**< LITHUANIA */
    {wifi_countrycode_LU,"LU"}, /**< LUXEMBOURG */
    {wifi_countrycode_LV,"LV"}, /**< LATVIA */
    {wifi_countrycode_LY,"LY"}, /**< LIBYAN ARAB JAMAHIRIYA */
    {wifi_countrycode_MA,"MA"}, /**< MOROCCO */
    {wifi_countrycode_MC,"MC"}, /**< MONACO */
    {wifi_countrycode_MD,"MD"}, /**< MOLDOVA, REPUBLIC OF */
    {wifi_countrycode_ME,"ME"}, /**< MONTENEGRO */
    {wifi_countrycode_MG,"MG"}, /**< MADAGASCAR */
    {wifi_countrycode_MH,"MH"}, /**< MARSHALL ISLANDS */
    {wifi_countrycode_MK,"MK"}, /**< MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF */
    {wifi_countrycode_ML,"ML"}, /**< MALI */
    {wifi_countrycode_MM,"MM"}, /**< MYANMAR */
    {wifi_countrycode_MN,"MN"}, /**< MONGOLIA */
    {wifi_countrycode_MO,"MO"}, /**< MACAO */
    {wifi_countrycode_MQ,"MQ"}, /**< MARTINIQUE */
    {wifi_countrycode_MR,"MR"}, /**< MAURITANIA */
    {wifi_countrycode_MS,"MS"}, /**< MONTSERRAT */
    {wifi_countrycode_MT,"MT"}, /**< MALTA */
    {wifi_countrycode_MU,"MU"}, /**< MAURITIUS */
    {wifi_countrycode_MV,"MV"}, /**< MALDIVES */
    {wifi_countrycode_MW,"MW"}, /**< MALAWI */
    {wifi_countrycode_MX,"MX"}, /**< MEXICO */
    {wifi_countrycode_MY,"MY"}, /**< MALAYSIA */
    {wifi_countrycode_MZ,"MZ"}, /**< MOZAMBIQUE */
    {wifi_countrycode_NA,"NA"}, /**< NAMIBIA */
    {wifi_countrycode_NC,"NC"}, /**< NEW CALEDONIA */
    {wifi_countrycode_NE,"NE"}, /**< NIGER */
    {wifi_countrycode_NF,"NF"}, /**< NORFOLK ISLAND */
    {wifi_countrycode_NG,"NG"}, /**< NIGERIA */
    {wifi_countrycode_NI,"NI"}, /**< NICARAGUA */
    {wifi_countrycode_NL,"NL"}, /**< NETHERLANDS */
    {wifi_countrycode_NO,"NO"}, /**< NORWAY */
    {wifi_countrycode_NP,"NP"}, /**< NEPAL */
    {wifi_countrycode_NR,"NR"}, /**< NAURU */
    {wifi_countrycode_NU,"NU"}, /**< NIUE */
    {wifi_countrycode_NZ,"NZ"}, /**< NEW ZEALAND */
    {wifi_countrycode_MP,"MP"}, /**< NORTHERN MARIANA ISLANDS */
    {wifi_countrycode_OM,"OM"}, /**< OMAN */
    {wifi_countrycode_PA,"PA"}, /**< PANAMA */
    {wifi_countrycode_PE,"PE"}, /**< PERU */
    {wifi_countrycode_PF,"PF"}, /**< FRENCH POLYNESIA */
    {wifi_countrycode_PG,"PG"}, /**< PAPUA NEW GUINEA */
    {wifi_countrycode_PH,"PH"}, /**< PHILIPPINES */
    {wifi_countrycode_PK,"PK"}, /**< PAKISTAN */
    {wifi_countrycode_PL,"PL"}, /**< POLAND */
    {wifi_countrycode_PM,"PM"}, /**< SAINT PIERRE AND MIQUELON */
    {wifi_countrycode_PN,"PN"}, /**< PITCAIRN */
    {wifi_countrycode_PR,"PR"}, /**< PUERTO RICO */
    {wifi_countrycode_PS,"PS"}, /**< PALESTINIAN TERRITORY,OCCUPIED */
    {wifi_countrycode_PT,"PT"}, /**< PORTUGAL */
    {wifi_countrycode_PW,"PW"}, /**< PALAU */
    {wifi_countrycode_PY,"PY"}, /**< PARAGUAY */
    {wifi_countrycode_QA,"QA"}, /**< QATAR */
    {wifi_countrycode_RE,"RE"}, /**< REUNION */
    {wifi_countrycode_RO,"RO"}, /**< ROMANIA */
    {wifi_countrycode_RS,"RS"}, /**< SERBIA */
    {wifi_countrycode_RU,"RU"}, /**< RUSSIAN FEDERATION */
    {wifi_countrycode_RW,"RW"}, /**< RWANDA */
    {wifi_countrycode_SA,"SA"}, /**< SAUDI ARABIA */
    {wifi_countrycode_SB,"SB"}, /**< SOLOMON ISLANDS */
    {wifi_countrycode_SD,"SD"}, /**< SUDAN */
    {wifi_countrycode_SE,"SE"}, /**< SWEDEN */
    {wifi_countrycode_SC,"SC"}, /**< SEYCHELLES */
    {wifi_countrycode_SG,"SG"}, /**< SINGAPORE */
    {wifi_countrycode_SH,"SH"}, /**< SAINT HELENA */
    {wifi_countrycode_SI,"SI"}, /**< SLOVENIA */
    {wifi_countrycode_SJ,"SJ"}, /**< SVALBARD AND JAN MAYEN */
    {wifi_countrycode_SK,"SK"}, /**< SLOVAKIA */
    {wifi_countrycode_SL,"SL"}, /**< SIERRA LEONE */
    {wifi_countrycode_SM,"SM"}, /**< SAN MARINO */
    {wifi_countrycode_SN,"SN"}, /**< SENEGAL */
    {wifi_countrycode_SO,"SO"}, /**< SOMALIA */
    {wifi_countrycode_SR,"SR"}, /**< SURINAME */
    {wifi_countrycode_ST,"ST"}, /**< SAO TOME AND PRINCIPE */
    {wifi_countrycode_SV,"SV"}, /**< EL SALVADOR */
    {wifi_countrycode_SY,"SY"}, /**< SYRIAN ARAB REPUBLIC */
    {wifi_countrycode_SZ,"SZ"}, /**< SWAZILAND */
    {wifi_countrycode_TA,"TA"}, /**< TRISTAN DA CUNHA */
    {wifi_countrycode_TC,"TC"}, /**< TURKS AND CAICOS ISLANDS */
    {wifi_countrycode_TD,"TD"}, /**< CHAD */
    {wifi_countrycode_TF,"TF"}, /**< FRENCH SOUTHERN TERRITORIES */
    {wifi_countrycode_TG,"TG"}, /**< TOGO */
    {wifi_countrycode_TH,"TH"}, /**< THAILAND */
    {wifi_countrycode_TJ,"TJ"}, /**< TAJIKISTAN */
    {wifi_countrycode_TK,"TK"}, /**< TOKELAU */
    {wifi_countrycode_TL,"TL"}, /**< TIMOR-LESTE (EAST TIMOR) */
    {wifi_countrycode_TM,"TM"}, /**< TURKMENISTAN */
    {wifi_countrycode_TN,"TN"}, /**< TUNISIA */
    {wifi_countrycode_TO,"TO"}, /**< TONGA */
    {wifi_countrycode_TR,"TR"}, /**< TURKEY */
    {wifi_countrycode_TT,"TT"}, /**< TRINIDAD AND TOBAGO */
    {wifi_countrycode_TV,"TV"}, /**< TUVALU */
    {wifi_countrycode_TW,"TW"}, /**< TAIWAN, PROVINCE OF CHINA */
    {wifi_countrycode_TZ,"TZ"}, /**< TANZANIA, UNITED REPUBLIC OF */
    {wifi_countrycode_UA,"UA"}, /**< UKRAINE */
    {wifi_countrycode_UG,"UG"}, /**< UGANDA */
    {wifi_countrycode_UM,"UM"}, /**< UNITED STATES MINOR OUTLYING ISLANDS */
    {wifi_countrycode_US,"US"}, /**< UNITED STATES */
    {wifi_countrycode_UY,"UY"}, /**< URUGUAY */
    {wifi_countrycode_UZ,"UZ"}, /**< UZBEKISTAN */
    {wifi_countrycode_VA,"VA"}, /**< HOLY SEE (VATICAN CITY STATE) */
    {wifi_countrycode_VC,"VC"}, /**< SAINT VINCENT AND THE GRENADINES */
    {wifi_countrycode_VE,"VE"}, /**< VENEZUELA */
    {wifi_countrycode_VG,"VG"}, /**< VIRGIN ISLANDS, BRITISH */
    {wifi_countrycode_VI,"VI"}, /**< VIRGIN ISLANDS, U.S. */
    {wifi_countrycode_VN,"VN"}, /**< VIET NAM */
    {wifi_countrycode_VU,"VU"}, /**< VANUATU */
    {wifi_countrycode_WF,"WF"}, /**< WALLIS AND FUTUNA */
    {wifi_countrycode_WS,"WS"}, /**< SAMOA */
    {wifi_countrycode_YE,"YE"}, /**< YEMEN */
    {wifi_countrycode_YT,"YT"}, /**< MAYOTTE */
    {wifi_countrycode_YU,"YU"}, /**< YUGOSLAVIA */
    {wifi_countrycode_ZA,"ZA"}, /**< SOUTH AFRICA */
    {wifi_countrycode_ZM,"ZM"}, /**< ZAMBIA */
    {wifi_countrycode_ZW,"ZW"} /**< ZIMBABWE */
};

struct wifiEnvironmentEnumStrMap wifiEnviromentMap[] =
{
    {wifi_operating_env_all, " "},
    {wifi_operating_env_indoor, "I"},
    {wifi_operating_env_outdoor, "O"},
    {wifi_operating_env_non_country, "X"}
};

void write_to_file(const char *file_name, char *fmt, ...)
{
    FILE *fp = NULL;
    va_list args;
    char buff[1024] = {0};
    

    va_start(args, fmt);
    vsnprintf(&buff[strlen(buff)], 1024, fmt, args);
    va_end(args);

    fp = fopen(file_name, "a+");
    if (fp == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Error, open file_name: %s\n",__func__, __LINE__, file_name);
        return;
    }

    fputs(buff, fp);
    fflush(fp);
    fclose(fp);
}

void copy_string(char*  destination, char*  source)
{
    if ( !source )
    {
        destination[0] = 0;
    }
    else
    {
        strcpy(destination, source);
    }
}

wifi_interface_name_t *get_interface_name_for_vap_index(unsigned int vap_index, wifi_platform_property_t *wifi_prop)
{
    unsigned int i, total_vaps=0;
    wifi_interface_name_idex_map_t *tmp = wifi_prop->interface_map;

    TOTAL_INTERFACES(total_vaps, wifi_prop);

    for (i = 0; i < total_vaps; i++) {
        if (tmp->index == vap_index) {
            return &tmp->interface_name;
        }
        tmp++;
    }

    return NULL;
}

void print_interface_map(wifi_platform_property_t *wifi_prop)
{
    UINT total_vaps;

    TOTAL_INTERFACES(total_vaps, wifi_prop);

    wifi_util_dbg_print(WIFI_WEBCONFIG, "   Interface Map: Number of Radios = %u\n", wifi_prop->numRadios);
    for (unsigned int i = 0; i < total_vaps; ++i) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "      phy=%u, radio=%u, ifname=%s, bridge=%s, index=%u, vap_name=%s\n", \
                                             wifi_prop->interface_map[i].phy_index, \
                                             wifi_prop->interface_map[i].rdk_radio_index, \
                                             wifi_prop->interface_map[i].interface_name, \
                                             wifi_prop->interface_map[i].bridge_name, \
                                             wifi_prop->interface_map[i].index, \
                                             wifi_prop->interface_map[i].vap_name);
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "  Radio Interface Map: Number of Radios = %u\n", wifi_prop->numRadios);
    for (unsigned int i = 0; i < total_vaps; ++i) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "      phy=%u, radio=%u, ifname=%s\n", \
                                             wifi_prop->radio_interface_map[i].phy_index, \
                                             wifi_prop->radio_interface_map[i].radio_index, \
                                             wifi_prop->radio_interface_map[i].interface_name);
    }
}

static wifi_interface_name_idex_map_t* get_vap_index_property(wifi_platform_property_t *wifi_prop, unsigned int vap_index, const char *func)
{
    wifi_interface_name_idex_map_t *if_prop = NULL;
    UINT total_vaps;

    TOTAL_INTERFACES(total_vaps, wifi_prop);
    for (UINT i = 0; i < total_vaps; ++i) {
        if (wifi_prop->interface_map[i].index == vap_index) {
            if_prop = &wifi_prop->interface_map[i];
            break;
        }
    }

    return if_prop;
}

static wifi_interface_name_idex_map_t* get_vap_name_property(wifi_platform_property_t *wifi_prop, char *vap_name, const char *func)
{
    wifi_interface_name_idex_map_t *if_prop = NULL;
    UINT total_vaps;

    TOTAL_INTERFACES(total_vaps, wifi_prop);
    for (UINT i = 0; i < total_vaps; ++i) {
        if (!strcmp(vap_name, wifi_prop->interface_map[i].vap_name)) {
            if_prop = &wifi_prop->interface_map[i];
            break;
        }
    }

    return if_prop;
}

static wifi_interface_name_idex_map_t* get_ifname_property(wifi_platform_property_t *wifi_prop, const char *if_name, const char *func)
{
    wifi_interface_name_idex_map_t *if_prop = NULL;
    UINT total_vaps = wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO;

    for (UINT i = 0; i < total_vaps ; ++i) {
        if (!strcmp(if_name, wifi_prop->interface_map[i].interface_name)) {
            if_prop = &wifi_prop->interface_map[i];
            break;
        }
    }

    return if_prop;
}

int get_number_of_radios(wifi_platform_property_t *wifi_prop)
{
    return (int)wifi_prop->numRadios;
}

int get_total_number_of_vaps(wifi_platform_property_t *wifi_prop)
{
    int total_vaps=0;

    TOTAL_INTERFACES(total_vaps, wifi_prop);

    return total_vaps;
}

int get_number_of_interfaces(wifi_platform_property_t *wifi_prop)
{
    int num_vaps;

    TOTAL_INTERFACES(num_vaps, wifi_prop);
    return num_vaps;
}

BOOL wifi_util_is_vap_index_valid(wifi_platform_property_t *wifi_prop, int vap_index)
{
    wifi_interface_name_idex_map_t *prop;

    prop = GET_VAP_INDEX_PROPERTY(wifi_prop, vap_index);

    return (prop) ? TRUE : FALSE;
}

int convert_vap_name_to_index(wifi_platform_property_t *wifi_prop, char *vap_name)
{
    wifi_interface_name_idex_map_t *prop;

    prop = GET_VAP_NAME_PROPERTY(wifi_prop, vap_name);
    if (prop == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s - Failed to get VAP index for %s\n", __FUNCTION__, vap_name);
    }

    return (prop) ? (int)prop->index : RETURN_ERR;
}

int convert_vap_name_to_array_index(wifi_platform_property_t *wifi_prop, char *vap_name)
{
    UINT radio_index = 0;
    UINT vap_index = 0;
    int vap_array_index = -1;
    wifi_interface_name_idex_map_t *if_prop;

    if_prop = GET_VAP_NAME_PROPERTY(wifi_prop, vap_name);
    if (if_prop) {
        radio_index = if_prop->rdk_radio_index;
        vap_index = if_prop->index;

        UINT total_vaps = wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO;

        for (UINT i = 0; i < total_vaps; i++) {
            if (wifi_prop->interface_map[i].rdk_radio_index == radio_index) {
                vap_array_index++;
            }
            if (wifi_prop->interface_map[i].index == vap_index) {
                break;
            }
        }
   }

    if (vap_array_index == -1) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Error, could not find vap index for '%s'\n",__func__, __LINE__, vap_name);
    }

    return vap_array_index;
}

int convert_vap_name_to_radio_array_index(wifi_platform_property_t *wifi_prop, char *vap_name)
{
    wifi_interface_name_idex_map_t *prop;

    prop = GET_VAP_NAME_PROPERTY(wifi_prop, vap_name);
    if (prop == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s - Failed to get radio index for %s\n", __FUNCTION__, vap_name);
    }

    return (prop) ? (int)prop->rdk_radio_index : RETURN_ERR;
}

int get_vap_and_radio_index_from_vap_instance(wifi_platform_property_t *wifi_prop, uint8_t vap_instance, uint8_t *radio_index, uint8_t *vap_index)
{
    int status = RETURN_OK;
    int vap_array_index = -1;
    wifi_interface_name_idex_map_t *if_prop;

    *radio_index = 0;
    *vap_index = 0;
    if_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, vap_instance);
    if (if_prop) {
        *radio_index = (uint8_t)if_prop->rdk_radio_index;

        UINT total_vaps = wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO;

        for (unsigned int i = 0; i < total_vaps; i++) {
            if((uint8_t)wifi_prop->interface_map[i].rdk_radio_index == *radio_index) {
                vap_array_index++;
            }
            if ((uint8_t)wifi_prop->interface_map[i].index == vap_instance) {
                *vap_index = (uint8_t)vap_array_index;
                break;
            }
        }
    }

    if (vap_array_index == -1) {
        status = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Error, could not find vap array index and radio index for vap_index %d\n",__func__, __LINE__, vap_instance);
    }

    return status;
}

/* return the pointer of the vap name in hal_cap given a vap index */
char *get_vap_name(wifi_platform_property_t *wifi_prop, int vap_index)
{
    wifi_interface_name_idex_map_t *prop;

    if ((prop = GET_VAP_INDEX_PROPERTY(wifi_prop, vap_index)) == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s - Failed to get VAP name for index %d\n", __FUNCTION__, vap_index);
    }
    
    return (prop) ? &prop->vap_name[0] : NULL;
}

/* copy the vap name to a buffer given a vap index */
int convert_vap_index_to_name(wifi_platform_property_t* wifi_prop, int vap_index, char *vap_name)
{
    wifi_interface_name_idex_map_t *prop = NULL;

    prop = GET_VAP_INDEX_PROPERTY(wifi_prop, vap_index);
    if (prop) {
        strcpy(vap_name, prop->vap_name);
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s - convert VAP index %d to VAP name failed\n", __func__, vap_index);
    }

    return (prop) ? RETURN_OK : RETURN_ERR;
}

int convert_radio_name_to_index(unsigned int *index,char *name)
{
    int radio_index;
    if (name == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Error, radio name NULL\n",__func__, __LINE__);
        return -1;
    }
    if (sscanf(name, "radio%d", &radio_index) == 1) {
        *index = radio_index-1;
        return 0;
    }
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Error, invalid radio name '%s'\n",__func__, __LINE__, name);
    return -1;
}

unsigned long long int get_current_ms_time(void)
{
    struct timeval tv_now = { 0 };
    unsigned long long int milliseconds = 0;
    gettimeofday(&tv_now, NULL);
    milliseconds = (tv_now.tv_sec*1000LL + tv_now.tv_usec/1000);
    return milliseconds;
}

char *get_formatted_time(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = (struct tm *)localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%y%m%d-%T", tm_info);

    snprintf(time, 128, "%s.%06lld", tmp, (long long)tv_now.tv_usec);
    return time;
}

void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, char *format, ...)
{
    char buff[2048*200] = {0};
    va_list list;
    FILE *fpg = NULL;
#if defined(__ENABLE_PID__) && (__ENABLE_PID__)
    pid_t pid;
#endif
    char filename_dbg_enable[32];
    char module_filename[32];
    char filename[100];

    switch(module)
    {
        case WIFI_DB:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiDbDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiDb");
            break;
        }
        case WIFI_MGR:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiMgrDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiMgr");
            break;
        }
        case WIFI_WEBCONFIG:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiWebConfigDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiWebConfig");
            break;
        }
        case WIFI_CTRL:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiCtrlDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiCtrl");
            break;
        }
        case WIFI_PASSPOINT:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiPasspointDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiPasspointDbg");
            break;
        }
        case WIFI_DPP:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiDppDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiDPP");
            break;
        }
        case WIFI_MON:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiMonDbg");
            snprintf(module_filename, sizeof(module_filename), "wifiMon");
            break;
        }
        case WIFI_DMCLI:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiDMCLI");
            snprintf(module_filename, sizeof(module_filename), "wifiDMCLI");
            break;
        }
        case WIFI_LIB:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiLib");
            snprintf(module_filename, sizeof(module_filename), "wifiLib");
            break;
        }
        case WIFI_PSM:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiPsm");
            snprintf(module_filename, sizeof(module_filename), "wifiPsm");
            break;
        }
        case WIFI_ANALYTICS:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiAnalytics");
            snprintf(module_filename, sizeof(module_filename), "wifiAnalytics");
            break;
        }
        case WIFI_APPS:{
            snprintf(filename_dbg_enable, sizeof(filename_dbg_enable), "/nvram/wifiApps");
            snprintf(module_filename, sizeof(module_filename), "wifiApps");
            break;
        }
        default:
            return;
    }

    if ((access(filename_dbg_enable, R_OK)) == 0) {
        snprintf(filename, sizeof(filename), "/tmp/%s", module_filename);
        fpg = fopen(filename, "a+");
        if (fpg == NULL) {
            return;
        }
    } else {
        switch (level) {
            case WIFI_LOG_LVL_INFO:
            case WIFI_LOG_LVL_ERROR:
                snprintf(filename, sizeof(filename), "/rdklogs/logs/%s.txt", module_filename);
                fpg = fopen(filename, "a+");
                if (fpg == NULL) {
                    return;
                }
                break;
            case WIFI_LOG_LVL_DEBUG:
            default:
                return;
        }
    }

    // formatting here. For analytics, do not need any time formatting, need timestamp for all others
    switch (module) {
        case WIFI_ANALYTICS:
            buff[0] = 0;
            break;

        default:
#if defined(__ENABLE_PID__) && (__ENABLE_PID__)
            pid = syscall(__NR_gettid);
            sprintf(&buff[0], "%d - ", pid);
            get_formatted_time(&buff[strlen(buff)]);
#else
            get_formatted_time(buff);
#endif
            strcat(buff, " ");
            break;
    }

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    fputs(buff, fpg);
    fflush(fpg);
    fclose(fpg);

}

int WiFi_IsValidMacAddr(const char* mac)
{
    int i = 0;
    int s = 0;

    while (*mac)
    {
        if (isxdigit(*mac))
        {
            i++;
        }
        else if (*mac == ':')
        {
            if (i == 0 || i / 2 - 1 != s)
                break;
            ++s;
        }
        else
        {
            s = -1;
        }
        ++mac;
    }
    return (i == 12 && (s == 5 || s == 0));
}

INT getIpAddressFromString (const char * ipString, ip_addr_t * ip)
{
    if (inet_pton(AF_INET, ipString, &ip->u.IPv4addr) > 0)
    {
        ip->family = wifi_ip_family_ipv4;
    }
    else if (inet_pton(AF_INET6, ipString, ip->u.IPv6addr) > 0)
    {
        ip->family = wifi_ip_family_ipv6;
    }
    else
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_ERROR, %s IP not recognise\n", __func__);
        return 0;
    }

    return 1;
}

INT getIpStringFromAdrress (char * ipString, const ip_addr_t * ip)
{
    if (ip->family == wifi_ip_family_ipv4)
    {
        inet_ntop(AF_INET, &ip->u.IPv4addr, ipString, INET_ADDRSTRLEN);
    }
    else if (ip->family == wifi_ip_family_ipv6)
    {
        inet_ntop(AF_INET6, &ip->u.IPv6addr, ipString, INET_ADDRSTRLEN);
    }
    else
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"RDK_LOG_ERROR, %s IP not recognise\n", __func__);
        return 0;
    }

    return 1;
}

void uint8_mac_to_string_mac(uint8_t *mac, char *s_mac)
{

    if((mac == NULL) || (s_mac == NULL))
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d:parameters is NULL\n", __func__, __LINE__);
        return;
    }
    snprintf(s_mac, 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac[0],mac[1], mac[2], mac[3], mac[4],mac[5]);
}

void string_mac_to_uint8_mac(uint8_t *mac, char *s_mac)
{

    if((mac == NULL) || (s_mac == NULL))
    {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d:parameters is NULL\n", __func__, __LINE__);
        return;
    }
    sscanf(s_mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2],&mac[3], &mac[4], &mac[5]);
}

int convert_radio_name_to_radio_index(char *name)
{
    //remove this function, it is duplicationg convert_radio_name_to_index
    if (strcmp(name, "radio1") == 0) {
        return 0;
    } else if (strcmp(name, "radio2") == 0) {
        return 1;
    } else if (strcmp(name, "radio3") == 0) {
        return 2;
    }
    return -1;
}

int convert_radio_index_to_radio_name(int index, char *name)
{
    if (index == 0) {
        strncpy(name,"radio1",BUFFER_LENGTH_WIFIDB);
        return 0;
    } else if (index == 1) {
        strncpy(name,"radio2",BUFFER_LENGTH_WIFIDB);
        return 0;
    } else if (index == 2) {
        strncpy(name,"radio3",BUFFER_LENGTH_WIFIDB);
        return 0;
    }

    return -1;
}

int convert_security_mode_integer_to_string(int m,char *mode)
{
    if(m==2) {
        strcpy(mode,"Required");
        return RETURN_OK;
    } else if(m==1) {
        strcpy(mode,"Optional");
        return RETURN_OK;
    } else {
        strcpy(mode,"Disabled");
        return RETURN_OK;
    }
    return RETURN_ERR;
}

int convert_security_mode_string_to_integer(int *m,char *mode)
{
    if(strcmp(mode,"Required") == 0) {
        *m = 2;
        return RETURN_OK;
    } else if(strcmp(mode,"Optional")== 0) {
        *m = 1;
        return RETURN_OK;
    } else {
        *m = 0;
        return RETURN_OK;
    }
    return RETURN_ERR;
}

int security_mode_support_radius(int mode)
{
    int sec_mode = 0;
    if((mode == wifi_security_mode_wpa_enterprise) || (mode ==wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)){
        sec_mode = 1;
    } else {
        sec_mode = 0;
    }

    return sec_mode;
}


/* Note: Need to find a better way to return the radio index.
         In the case of XLE, it has 3 radios but no 6GHz.
         It has 2 5GHz radios, 5L and 5H. This function will not function correctly.
*/
int convert_freq_band_to_radio_index(int band, int *radio_index)
{
    int status = RETURN_OK;

    switch (band) {
        case WIFI_FREQUENCY_2_4_BAND:
            *radio_index = 0;
            break;

        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
            *radio_index = 1;
            break;

        case WIFI_FREQUENCY_5H_BAND:
        case WIFI_FREQUENCY_6_BAND:
            *radio_index = 2;
            break;

        default:
            status = RETURN_ERR;
            break;
    }

    return status;
}

int convert_ifname_to_radio_index(wifi_platform_property_t *wifi_prop, char *if_name, unsigned int *radio_index)
{
    wifi_interface_name_idex_map_t *prop;
    
    //return the radio Index based in Interface Name
    if (if_name == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"WIFI %s:%d input if_name is NULL \n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    prop = GET_IFNAME_PROPERTY(wifi_prop, if_name);
    if (prop) {
        *radio_index = prop->rdk_radio_index;
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d - No interface %s found\n", __FUNCTION__, __LINE__, if_name);
    }
    return (prop) ? RETURN_OK : RETURN_ERR;
}

int convert_radio_index_to_ifname(wifi_platform_property_t *wifi_prop, unsigned int radio_index, char *if_name, int ifname_len)
{
    bool b_valid = false;
    unsigned int num_radios;
    radio_interface_mapping_t *radio;

    if (if_name == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"WIFI %s:%d input if_name is NULL \n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    num_radios = wifi_prop->numRadios;
    radio = &wifi_prop->radio_interface_map[0];

    if (radio_index >= num_radios) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid radioIndex : %d!!!\n", __FUNCTION__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    for (unsigned int index = 0; index < num_radios; ++index) {
        if (radio[index].radio_index == radio_index) {
            strncpy(if_name, &radio[index].interface_name[0], ifname_len);
            b_valid = true;
            break;
        }
    }

    return (b_valid) ? RETURN_OK : RETURN_ERR;
}

int convert_apindex_to_ifname(wifi_platform_property_t *wifi_prop, int idx, char *if_name, unsigned int len)
{
    wifi_interface_name_idex_map_t *prop;

    /* for 3rd radio, the vap index can be larger than total number of vaps */
    if (NULL == if_name || idx  >= (int)(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!!\n", __FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    prop = GET_VAP_INDEX_PROPERTY(wifi_prop, idx);
    if (prop) {
        strncpy(if_name, prop->interface_name, len);
    }

    return (prop) ? RETURN_OK : RETURN_ERR;
}

int convert_ifname_to_vapname(wifi_platform_property_t *wifi_prop, char *if_name, char *vap_name, int vapname_len)
{
    wifi_interface_name_idex_map_t *prop;

    if ((if_name == NULL) || (vap_name == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!!\n", __FUNCTION__, __LINE__);
        return RETURN_ERR;
    }
    
    prop = GET_IFNAME_PROPERTY(wifi_prop, if_name);
    if (prop) {
        strncpy(vap_name, prop->vap_name, vapname_len);
    }

    return (prop) ? RETURN_OK : RETURN_ERR;
}



int vap_mode_conversion(wifi_vap_mode_t *vapmode_enum, char *vapmode_str, size_t vapmode_str_len, unsigned int conv_type)
{
    if ((vapmode_enum == NULL) || (vapmode_str == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguments is NULL \n",__func__, __LINE__);
        return RETURN_ERR;
    }

    if (conv_type == ENUM_TO_STRING) {
        switch(*vapmode_enum)
        {
            case wifi_vap_mode_ap:
                snprintf(vapmode_str, vapmode_str_len, "%s", "ap");
                return RETURN_OK;

            case wifi_vap_mode_sta:
                snprintf(vapmode_str, vapmode_str_len, "%s", "sta");
                return RETURN_OK;

            case wifi_vap_mode_monitor:
                snprintf(vapmode_str, vapmode_str_len, "%s", "monitor");
                return RETURN_OK;
            default:
            break;
        }

    } else if (conv_type == STRING_TO_ENUM) {
        if (strncmp(vapmode_str, "ap", strlen("ap")) == 0) {
            *vapmode_enum = wifi_vap_mode_ap;
            return RETURN_OK;
        } else if (strncmp(vapmode_str, "sta", strlen("sta")) == 0) {
            *vapmode_enum = wifi_vap_mode_sta;
            return RETURN_OK;
        } else if (strncmp(vapmode_str, "monitor", strlen("monitor")) == 0) {
            *vapmode_enum = wifi_vap_mode_monitor;
            return RETURN_OK;
        }
    }
    return RETURN_ERR;
}

int macfilter_conversion(char *mac_list_type, size_t string_len,  wifi_vap_info_t *vap_info, unsigned int conv_type)
{
    if ((mac_list_type == NULL) || (vap_info == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguments is NULL \n",__func__, __LINE__);
        return RETURN_ERR;
    }

    if (conv_type == STRING_TO_ENUM) {
        if (strncmp(mac_list_type, "whitelist", strlen("whitelist")) == 0) {
            vap_info->u.bss_info.mac_filter_enable = TRUE;
            vap_info->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
            return RETURN_OK;
        } else if (strncmp(mac_list_type, "blacklist", strlen("blacklist")) == 0) {
            vap_info->u.bss_info.mac_filter_enable = TRUE;
            vap_info->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
            return RETURN_OK;
        } else if (strncmp(mac_list_type, "none", strlen("none")) == 0) {
            vap_info->u.bss_info.mac_filter_enable = FALSE;
            vap_info->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
            return RETURN_OK;
        } else if (mac_list_type[0] == '\0') {
            vap_info->u.bss_info.mac_filter_enable = FALSE;
            vap_info->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
            return RETURN_OK;
        }
    } else if (conv_type == ENUM_TO_STRING) {
        if ((vap_info->u.bss_info.mac_filter_enable == TRUE) && (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list)) {
            snprintf(mac_list_type, string_len, "whitelist");
            return RETURN_OK;
        } else if ((vap_info->u.bss_info.mac_filter_enable == TRUE) && (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list)) {
            snprintf(mac_list_type, string_len, "blacklist");
            return RETURN_OK;
        } else if ((vap_info->u.bss_info.mac_filter_enable == FALSE)) {
            snprintf(mac_list_type, string_len, "none");
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}

int ssid_broadcast_conversion(char *broadcast_string, size_t string_len, BOOL *broadcast_bool, unsigned int conv_type)
{
    if ((broadcast_string == NULL) || (broadcast_bool == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Input arguments is NULL \n",__func__, __LINE__);
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        if ((strncmp(broadcast_string, "disabled", strlen("disabled")) == 0) || (strncmp(broadcast_string, "disabled_null", strlen("disabled_null")) == 0)) {
            *broadcast_bool =  FALSE;
            return RETURN_OK;
        } else if (strncmp(broadcast_string, "enabled", strlen("enabled")) == 0) {
            *broadcast_bool = TRUE;
            return RETURN_OK;
        }
    } else if (conv_type == ENUM_TO_STRING) {
        if (*broadcast_bool == TRUE) {
            snprintf(broadcast_string, string_len, "enabled");
            return RETURN_OK;
        } else {
            snprintf(broadcast_string, string_len, "disabled");
            return RETURN_OK;
        }

    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: broadcast update failed \n",__func__, __LINE__);
    return RETURN_ERR;
}

int freq_band_conversion(wifi_freq_bands_t *band_enum, char *freq_band, int freq_band_len, unsigned int conv_type)
{
    if ((freq_band == NULL) || (band_enum == NULL)) {
        return RETURN_ERR;
    }

    if (conv_type == STRING_TO_ENUM) {
        if (!strncmp(freq_band, "2.4G", strlen("2.4G")+1)) {
            *band_enum = WIFI_FREQUENCY_2_4_BAND;
            return RETURN_OK;
        } else if (!strncmp(freq_band, "5G", strlen("5G")+1)) {
            *band_enum = WIFI_FREQUENCY_5_BAND;
            return RETURN_OK;
        } else if (!strncmp(freq_band, "5GL", strlen("5GL")+1)) {
            *band_enum = WIFI_FREQUENCY_5L_BAND;
            return RETURN_OK;
        } else if (!strncmp(freq_band, "5GU", strlen("5GU")+1)) {
            *band_enum = WIFI_FREQUENCY_5H_BAND;
            return RETURN_OK;
        } else if (!strncmp(freq_band, "6G", strlen("6G")+1)) {
            *band_enum = WIFI_FREQUENCY_6_BAND;
            return RETURN_OK;
        }
    } else if (conv_type == ENUM_TO_STRING) {
        switch(*band_enum){
            case WIFI_FREQUENCY_2_4_BAND:
                snprintf(freq_band, freq_band_len, "2.4G");
                return RETURN_OK;
            case WIFI_FREQUENCY_5_BAND:
                snprintf(freq_band, freq_band_len, "5G");
                return RETURN_OK;
            case WIFI_FREQUENCY_5L_BAND:
                snprintf(freq_band, freq_band_len, "5GL");
                return RETURN_OK;
            case WIFI_FREQUENCY_5H_BAND:
                snprintf(freq_band, freq_band_len, "5GU");
                return RETURN_OK;
            case WIFI_FREQUENCY_6_BAND:
                snprintf(freq_band, freq_band_len, "6G");
                return RETURN_OK;
            default:
                break;
        }
    }

    return RETURN_ERR;
}

BOOL is_vap_private(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "private_ssid", strlen("private_ssid"))) ? FALSE : TRUE;
}

BOOL is_vap_xhs(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "iot_ssid", strlen("iot_ssid"))) ? FALSE : TRUE;
}

BOOL is_vap_hotspot(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
     wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "hotspot", strlen("hotspot"))) ? FALSE : TRUE;
}

BOOL is_vap_hotspot_open(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "hotspot_open", strlen("hotspot_open"))) ? FALSE : TRUE;
}

BOOL is_vap_lnf(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
     wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "lnf", strlen("lnf"))) ? FALSE : TRUE;
}

BOOL is_vap_lnf_psk(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "lnf_psk", strlen("lnf_psk"))) ? FALSE : TRUE;
}

BOOL is_vap_mesh(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "mesh", strlen("mesh"))) ? FALSE : TRUE;
}

BOOL is_vap_mesh_backhaul(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "mesh_backhaul", strlen("mesh_backhaul"))) ? FALSE : TRUE;
}

BOOL is_vap_hotspot_secure(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "hotspot_secure", strlen("hotspot_secure"))) ? FALSE : TRUE;
}

BOOL is_vap_lnf_radius(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "lnf_radius", strlen("lnf_radius"))) ? FALSE : TRUE;
}

BOOL is_vap_mesh_sta(wifi_platform_property_t *wifi_prop, UINT ap_index)
{
    wifi_interface_name_idex_map_t* vap_prop;

    if ((vap_prop = GET_VAP_INDEX_PROPERTY(wifi_prop, ap_index)) == NULL) {
        return FALSE;
    }

    return (strncmp((char *)&vap_prop->vap_name[0], "mesh_sta", strlen("mesh_sta"))) ? FALSE :TRUE;
}

int country_code_conversion(wifi_countrycode_type_t *country_code, char *country, int country_len, unsigned int conv_type)
{
    int i = 0;
    if ((country_code == NULL) || (country == NULL)) {
        return RETURN_ERR;
    }

    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < MAX_WIFI_COUNTRYCODE; i++) {
            if(strcasecmp(country, wifiCountryMap[i].countryStr) == 0) {
                *country_code = wifiCountryMap[i].countryCode;
                return RETURN_OK;
            }
        }

        if(i == MAX_WIFI_COUNTRYCODE) {
            return RETURN_ERR;
        }

    } else if (conv_type == ENUM_TO_STRING) {
        if ( i >= MAX_WIFI_COUNTRYCODE) {
            return RETURN_ERR;
        }
        snprintf(country, country_len, "%s", wifiCountryMap[*country_code].countryStr);
        return RETURN_OK;
    }

    return RETURN_ERR;
}


int hw_mode_conversion(wifi_ieee80211Variant_t *hw_mode_enum, char *hw_mode, int hw_mode_len, unsigned int conv_type)
{
    char arr_str[][8] = {"11a", "11b", "11g", "11n", "11ac", "11ax"};
    wifi_ieee80211Variant_t arr_enum[] = {WIFI_80211_VARIANT_A, WIFI_80211_VARIANT_B, WIFI_80211_VARIANT_G, WIFI_80211_VARIANT_N, WIFI_80211_VARIANT_AC, WIFI_80211_VARIANT_AX};
    bool is_mode_valid = false;

    unsigned int i = 0;
    if ((hw_mode_enum == NULL) || (hw_mode == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], hw_mode) == 0) {
                *hw_mode_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if ((arr_enum[i] & *hw_mode_enum) == arr_enum[i]) {
                snprintf(hw_mode, hw_mode_len, "%s", arr_str[i]);
                is_mode_valid = true;
            }
        }

        if (is_mode_valid == true) {
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}

int ht_mode_conversion(wifi_channelBandwidth_t *ht_mode_enum, char *ht_mode, int ht_mode_len, unsigned int conv_type)
{
    char arr_str[][8] = {"HT20", "HT40", "HT80", "HT160"};
    wifi_channelBandwidth_t arr_enum[] = {WIFI_CHANNELBANDWIDTH_20MHZ, WIFI_CHANNELBANDWIDTH_40MHZ, WIFI_CHANNELBANDWIDTH_80MHZ, WIFI_CHANNELBANDWIDTH_160MHZ};

    unsigned int i = 0;
    if ((ht_mode_enum == NULL) || (ht_mode == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], ht_mode) == 0) {
                *ht_mode_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *ht_mode_enum) {
                snprintf(ht_mode, ht_mode_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int get_sta_vap_index_for_radio(wifi_platform_property_t *wifi_prop, unsigned int radio_index)
{
    int index;
    int num_vaps;
    int vap_index = RETURN_ERR;
    wifi_interface_name_idex_map_t *if_prop;

    TOTAL_INTERFACES(num_vaps, wifi_prop);
    if_prop = wifi_prop->interface_map;
    
    for (index = 0; index < num_vaps; ++index) {
        if (if_prop->rdk_radio_index == radio_index) {
            if (!strncmp(if_prop->vap_name, "mesh_sta", strlen("mesh_sta"))) {
                vap_index = if_prop->index;
                break;
            }
        }
        if_prop++;
    }

    return vap_index;
}

int channel_mode_conversion(BOOL *auto_channel_bool, char *auto_channel_string, int auto_channel_strlen, unsigned int conv_type)
{
    if ((auto_channel_bool == NULL) || (auto_channel_string == NULL)) {
        return RETURN_ERR;
    }

    if (conv_type == STRING_TO_ENUM) {
        if ((strcmp(auto_channel_string, "auto")) || (strcmp(auto_channel_string, "cloud")) || (strcmp(auto_channel_string, "acs"))) {
            *auto_channel_bool = true;
            return RETURN_OK;
        } else if (strcmp(auto_channel_string, "manual")) {
            *auto_channel_bool = false;
            return RETURN_OK;
        }
    } else if (conv_type == ENUM_TO_STRING) {
        if (*auto_channel_bool == true) {
            snprintf(auto_channel_string, auto_channel_strlen, "%s", "auto");
            return RETURN_OK;
        } else  if (*auto_channel_bool == false)  {
            snprintf(auto_channel_string, auto_channel_strlen, "%s", "manual");
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}

int is_wifi_channel_valid(wifi_platform_property_t *wifi_prop, wifi_freq_bands_t wifi_band,
    UINT wifi_channel)
{
    int i, radio_index;
    wifi_channels_list_t *channels;

    if (convert_freq_band_to_radio_index(wifi_band, &radio_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to get radio index for band %d\n",
            __func__, __LINE__, wifi_band);
        return RETURN_ERR;
    }

    channels = &wifi_prop->radiocap[radio_index].channel_list[0];
    for (i = 0; i < channels->num_channels; i++)
    {
        if (channels->channels_list[i] == (int)wifi_channel) {
            return RETURN_OK;
        }
    }

    return RETURN_ERR;
}


int is_ssid_name_valid(char *ssid_name)
{
    int i = 0, ssid_len;

    if(!ssid_name){
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: SSID is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > WIFI_MAX_SSID_NAME_LEN)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: SSID invalid length\n", __func__, __LINE__);
        return RETURN_ERR;
    }


    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: SSID invalid characters\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

void str_to_mac_bytes (char *key, mac_addr_t bmac) {
    unsigned int mac[6];
    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
    bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

int get_cm_mac_address(char *mac)
{
    FILE *f;
    char ptr[32];
    char *cmd = "deviceinfo.sh -cmac";

    memset (ptr, 0, sizeof(ptr));

    if ((f = popen(cmd, "r")) == NULL) {
        return RETURN_ERR;
    } else {
        *ptr = 0;
        fgets(ptr,32,f);
        pclose(f);
    }

    strncpy(mac, ptr, strlen(ptr));

    return RETURN_OK;
}

/************************************************************************************
 ************************************************************************************
 Function    : get_ssid_from_device_mac
 Parameter   : ssid - Name of ssid
 Description : Get ssid information from cm mac address
 *************************************************************************************
 **************************************************************************************/
int get_ssid_from_device_mac(char *ssid)
{
    int ret = RETURN_OK;
    char s_mac[BUFFER_LENGTH_WIFIDB] = {0};
    mac_address_t mac;
    memset(mac, 0, sizeof(mac));

    ret = get_cm_mac_address(s_mac);
    if(ret != RETURN_OK)
    {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: get cm mac address failure: %d \n",__func__, __LINE__, ret);
        return ret;
    }

    string_mac_to_uint8_mac(mac, s_mac);

    memset(s_mac, 0, sizeof(s_mac));
    sprintf(s_mac, "XFSETUP-%02hhX%02hhX", mac[4], mac[5]);
    strncpy(ssid, s_mac, strlen(s_mac));
    return ret;
}

int key_mgmt_conversion_legacy(wifi_security_modes_t *mode_enum, wifi_encryption_method_t *encryp_enum, char *str_mode, int mode_len, char *str_encryp, int encryp_len, unsigned int conv_type)
{
    //ovs encrytion: "OPEN", "WEP", "WPA-PSK", "WPA-EAP"
    //ovs mode: "64", "128", "1", "2", "mixed"
    int ret = RETURN_OK;

    if ((mode_enum == NULL) || (encryp_enum == NULL) || (str_mode == NULL) || (str_encryp == NULL)) {
        return RETURN_ERR;
    }

    if (conv_type == STRING_TO_ENUM) {
        if (strcmp(str_encryp, "OPEN") == 0) {
            *mode_enum = wifi_security_mode_none;
            *encryp_enum = wifi_encryption_none;
        } else if (strcmp(str_encryp, "WEP") == 0) {
            if (strcmp(str_mode, "64") == 0) {
                *mode_enum = wifi_security_mode_wep_64;
            } else if (strcmp(str_mode, "128") == 0) {
                *mode_enum = wifi_security_mode_wep_128;
            } else {
                ret = RETURN_ERR;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid encryption '%s' and mode '%s'\n", __func__, __LINE__, str_encryp, str_mode);
            }
        } else if (strcmp(str_encryp, "WPA-PSK") == 0) {
            if (strcmp(str_mode, "1") == 0) {
                *mode_enum = wifi_security_mode_wpa_personal;
                *encryp_enum = wifi_encryption_tkip;
            } else if (strcmp(str_mode, "2") == 0) {
                *mode_enum = wifi_security_mode_wpa2_personal;
                *encryp_enum = wifi_encryption_aes;
            } else if (strcmp(str_mode, "mixed") == 0) {
                *mode_enum = wifi_security_mode_wpa_wpa2_personal;
                *encryp_enum = wifi_encryption_aes_tkip;
            } else {
                ret = RETURN_ERR;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid encryption '%s' and mode '%s'\n", __func__, __LINE__, str_encryp, str_mode);
            }
        } else if (strcmp(str_encryp, "WPA-EAP") == 0) {
            if (strcmp(str_mode, "1") == 0) {
                *mode_enum = wifi_security_mode_wpa_enterprise;
                *encryp_enum = wifi_encryption_tkip;
            } else if (strcmp(str_mode, "2") == 0) {
                *mode_enum = wifi_security_mode_wpa2_enterprise;
                *encryp_enum = wifi_encryption_aes;
            } else if (strcmp(str_mode, "mixed") == 0) {
                *mode_enum = wifi_security_mode_wpa_wpa2_enterprise;
                *encryp_enum = wifi_encryption_aes_tkip;
            } else {
                ret = RETURN_ERR;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid encryption '%s' and mode '%s'\n", __func__, __LINE__, str_encryp, str_mode);
            }
        } else if (strcmp(str_encryp, "WPA-PSK SAE") == 0) {
            if (strcmp(str_mode, "2") == 0) {
                *mode_enum = wifi_security_mode_wpa3_transition;
                *encryp_enum = wifi_encryption_aes;
            }
        } else if (strcmp(str_encryp, "SAE") == 0) {
            if (strcmp(str_mode, "2") == 0) {
                *mode_enum = wifi_security_mode_wpa3_personal;
                *encryp_enum = wifi_encryption_aes;
            }
        } else {
            ret = RETURN_ERR;
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid encryption '%s'\n", __func__, __LINE__, str_encryp);
        }
    } else if (conv_type == ENUM_TO_STRING) {
        switch (*mode_enum) {
        case wifi_security_mode_none:
            snprintf(str_encryp, encryp_len, "OPEN");
            break;
        case wifi_security_mode_wep_64:
            snprintf(str_mode, mode_len, "64");
            snprintf(str_encryp, encryp_len, "WEP");
            break;
        case wifi_security_mode_wep_128:
            snprintf(str_mode, mode_len, "128");
            snprintf(str_encryp, encryp_len, "WEP");
            break;
        case wifi_security_mode_wpa_enterprise:
            snprintf(str_mode, mode_len, "1");
            snprintf(str_encryp, encryp_len, "WPA-EAP");
            break;
        case wifi_security_mode_wpa2_enterprise:
            snprintf(str_mode, mode_len, "2");
            snprintf(str_encryp, encryp_len, "WPA-EAP");
            break;
        case wifi_security_mode_wpa_wpa2_enterprise:
            snprintf(str_mode, mode_len, "mixed");
            snprintf(str_encryp, encryp_len, "WPA-EAP");
            break;
        case wifi_security_mode_wpa_personal:
            snprintf(str_mode, mode_len, "1");
            snprintf(str_encryp, encryp_len, "WPA-PSK");
            break;
        case wifi_security_mode_wpa2_personal:
            snprintf(str_mode, mode_len, "2");
            snprintf(str_encryp, encryp_len, "WPA-PSK");
            break;
        case wifi_security_mode_wpa_wpa2_personal:
            snprintf(str_mode, mode_len, "mixed");
            snprintf(str_encryp, encryp_len, "WPA-PSK");
            break;
        case wifi_security_mode_wpa3_personal:
            snprintf(str_mode, mode_len, "2");
            snprintf(str_encryp, encryp_len, "SAE");
            break;
        case wifi_security_mode_wpa3_transition:
            snprintf(str_mode, mode_len, "2");
            snprintf(str_encryp, encryp_len, "WPA-PSK SAE");
            break;
        case wifi_security_mode_wpa3_enterprise:
        /* fallthrough */
        default:
            ret = RETURN_ERR;
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: unsupported security mode %d\n", __func__, __LINE__, *mode_enum);
            break;
        }
    }

    return ret;
}

int key_mgmt_conversion(wifi_security_modes_t *enum_sec, char *str_sec, int sec_len, unsigned int conv_type)
{
    char arr_str[][16] = {"wpa-psk", "wpa2-psk", "wpa2-eap", "sae", "wpa2-psk sae"};
    wifi_security_modes_t  arr_num[] = {wifi_security_mode_wpa_personal, wifi_security_mode_wpa2_personal, wifi_security_mode_wpa2_enterprise, wifi_security_mode_wpa3_personal,\
                                        wifi_security_mode_wpa3_transition};
    unsigned int i = 0;

    if ((enum_sec == NULL) || (str_sec == NULL)) {
        return RETURN_ERR;
    }

    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], str_sec) == 0) {
                *enum_sec = arr_num[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_num); i++) {
            if (arr_num[i]  == *enum_sec) {
                snprintf(str_sec, sec_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int get_radio_if_hw_type(char *str, int str_len)
{
    if (str == NULL) {
        return RETURN_ERR;
    }

    snprintf(str, str_len, "BCM43684");
    return RETURN_OK;
}

char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

int convert_vapname_to_ifname(wifi_platform_property_t *wifi_prop, char *vap_name, char *if_name, int ifname_len)
{
    wifi_interface_name_idex_map_t *if_prop = NULL;
 
    if ((if_name == NULL) || (vap_name == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if_prop = GET_VAP_NAME_PROPERTY(wifi_prop, vap_name);
    if (if_prop) {
        strncpy(if_name, if_prop->interface_name, ifname_len);
    }

    return (if_prop) ? RETURN_OK : RETURN_ERR;
}

int get_bridgename_from_vapname(wifi_platform_property_t *wifi_prop, char *vap_name, char *bridge_name, int bridge_name_len)
{
    wifi_interface_name_idex_map_t *if_prop = NULL;
 
    if ((bridge_name == NULL) || (vap_name == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if_prop = GET_VAP_NAME_PROPERTY(wifi_prop, vap_name);
    if (if_prop) {
        strncpy(bridge_name, if_prop->bridge_name, bridge_name_len);
    }

    return (if_prop) ? RETURN_OK : RETURN_ERR;
}

unsigned int create_vap_mask(wifi_platform_property_t *wifi_prop, unsigned int num_names, ...)
{
    char *vap_type;
    unsigned int num_vaps;
    unsigned int mask = 0;
    va_list args;
    wifi_interface_name_idex_map_t *interface_map;

    interface_map = &wifi_prop->interface_map[0];

    TOTAL_INTERFACES(num_vaps, wifi_prop);
    va_start(args, num_names);
    for (UINT num = 0; num < num_names; num++) {
        vap_type = va_arg(args, char *);

        for (UINT array_index = 0; array_index < num_vaps; ++array_index) {
            if (!strncmp((char *)&interface_map[array_index].vap_name[0], vap_type, strlen(vap_type))) {
                mask |= 1 << wifi_prop->interface_map[array_index].index;
            }
        }
    }

    va_end(args);

    return mask;
}

int get_list_of_vap_names(wifi_platform_property_t *wifi_prop, wifi_vap_name_t vap_names[], int list_size, int num_types, ...)
{
    int total_vaps;
    int num_vaps = 0;
    char *vap_type;
    va_list args;

    va_start(args, num_types);

    memset(&vap_names[0], 0, list_size*sizeof(wifi_vap_name_t));
    TOTAL_INTERFACES(total_vaps, wifi_prop);
    for (int num = 0; num < num_types; num++) {
        vap_type = va_arg(args, char *);
        for (int index = 0; (index < total_vaps) && (num_vaps < list_size); ++index) {
            if (!strncmp(wifi_prop->interface_map[index].vap_name, vap_type, strlen(vap_type))) {
                strncpy(&vap_names[num_vaps++][0], wifi_prop->interface_map[index].vap_name, sizeof(wifi_vap_name_t)-1);
            }
        }
    }

    va_end(args);
    return num_vaps;
}

int get_list_of_private_ssid(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_PRIVATE);
}

int get_list_of_hotspot_open(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_HOTSPOT_OPEN);
}

int get_list_of_hotspot_secure(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_HOTSPOT_SECURE);
}

int get_list_of_lnf_psk(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_LNF_PSK);
}

int get_list_of_lnf_radius(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_LNF_RADIUS);
}

int get_list_of_mesh_backhaul(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_MESH_BACKHAUL);
}

int get_list_of_mesh_sta(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_MESH_STA);
}

int get_list_of_iot_ssid(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[])
{
    return get_list_of_vap_names(wifi_prop, vap_names, list_size, 1, VAP_PREFIX_IOT);
}

int get_radio_index_for_vap_index(wifi_platform_property_t* wifi_prop, int vap_index)
{
    wifi_interface_name_idex_map_t *prop = NULL;

    prop = GET_VAP_INDEX_PROPERTY(wifi_prop, vap_index);
    if (!prop) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s - VAP index %d not found\n", __func__, vap_index);
    }

    return (prop) ? (int)prop->rdk_radio_index : RETURN_ERR;
}


int  min_hw_mode_conversion(unsigned int vapIndex, char *inputStr, char *outputStr, char *tableType)
{
    static char  min_hw_mode[MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS][8];
    if (tableType == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input table type error!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (strcmp(tableType, "CONFIG") == 0) {
        if (inputStr == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d NULL Arguments!!!\n", __func__, __LINE__);
            return RETURN_ERR;
        }
        snprintf(min_hw_mode[vapIndex], sizeof(min_hw_mode[vapIndex]), "%s", inputStr);
        return RETURN_OK;
    } else if (strcmp(tableType, "STATE") == 0) {
        if (outputStr == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d NULL Arguments!!!\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        if (strlen(min_hw_mode[vapIndex]) == 0) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d min_hw_mode is not filled for vapIndex : %d !!!\n", __func__, __LINE__, vapIndex);
            return RETURN_ERR;
        }
        snprintf(outputStr, sizeof(min_hw_mode[vapIndex]), "%s", min_hw_mode[vapIndex]);
        return RETURN_OK;
    }

    return RETURN_ERR;
}

int stats_type_conversion(stats_type_t *stat_type_enum, char *stat_type, int stat_type_len, unsigned int conv_type)
{
    char arr_str[][32] = {"neighbor", "survey", "client", "capacity", "radio", "essid", "quality", "device", "rssi", "steering", "client_auth_fails"};
    stats_type_t arr_enum[] = {stats_type_neighbor, stats_type_survey, stats_type_client, stats_type_capacity, stats_type_radio, stats_type_essid,
                       stats_type_quality, stats_type_device, stats_type_rssi, stats_type_steering, stats_type_client_auth_fails};

    unsigned int i = 0;
    if ((stat_type_enum == NULL) || (stat_type == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], stat_type) == 0) {
                *stat_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *stat_type_enum) {
                snprintf(stat_type, stat_type_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}


int  vif_radio_idx_conversion(unsigned int vapIndex, int *input, int *output, char *tableType)
{
    static int  vif_radio_idx[MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS];
    if (tableType == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input table type error!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (strcmp(tableType, "CONFIG") == 0) {
        if (input == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d NULL Arguments!!!\n", __func__, __LINE__);
            return RETURN_ERR;
        }
        vif_radio_idx[vapIndex] = *input;
        return RETURN_OK;
    } else if (strcmp(tableType, "STATE") == 0) {
        if (output == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s %d NULL Arguments!!!\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        *output = vif_radio_idx[vapIndex];
        return RETURN_OK;
    }

    return RETURN_ERR;
}

int get_allowed_channels(wifi_freq_bands_t band, wifi_radio_capabilities_t *radio_cap, int *channels, int *channels_len)
{
    unsigned int band_arr_index = 0;
    int chan_arr_index = 0;
    if ((radio_cap == NULL) || (channels == NULL) || (channels_len == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Input arguements are NULL radio_cap : %p channels : %p channels_len : %p\n", __func__, __LINE__, radio_cap, channels, channels_len);
        return RETURN_ERR;
    }
    for (chan_arr_index = 0; chan_arr_index < radio_cap->channel_list[band_arr_index].num_channels; chan_arr_index++) {
        channels[chan_arr_index] =  radio_cap->channel_list[band_arr_index].channels_list[chan_arr_index];
    }
    *channels_len = radio_cap->channel_list[band_arr_index].num_channels;
    return RETURN_OK;
}

int get_allowed_channels_str(wifi_freq_bands_t band, wifi_radio_capabilities_t *radio_cap,
    char *buf, size_t buf_size)
{
    int i;
    char channel_str[8];
    wifi_channels_list_t *channels;

    if ((radio_cap == NULL) || (buf == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input arguments are NULL: radio_cap : %p "
            "buf : %p\n", __func__, __LINE__, radio_cap, buf);
        return RETURN_ERR;
    }

    channels = &radio_cap->channel_list[0];

    // check buffer can accommodate n * (3 digit channel + comma separator)
    if (channels->num_channels * 4 >= (int)buf_size) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d The buffer of size %zu cannot accomodate all "
            "%d channels\n", __func__, __LINE__, buf_size, channels->num_channels);
        return RETURN_ERR;
    }

    *buf = '\0';
    for (i = 0; i < channels->num_channels; i++) {
        snprintf(channel_str, sizeof(channel_str), i == 0 ? "%u" : ",%u",
            channels->channels_list[i]);
        strcat(buf, channel_str);
    }

    return RETURN_OK;
}

int convert_radio_index_to_freq_band(wifi_platform_property_t *wifi_prop, unsigned int radio_index,
    int *band)
{
    int index, num_vaps;
    wifi_interface_name_idex_map_t *if_prop;

    TOTAL_INTERFACES(num_vaps, wifi_prop);
    if_prop = wifi_prop->interface_map;

    for (index = 0; index < num_vaps; index++) {
        if (if_prop->rdk_radio_index == radio_index) {
            if (strstr(if_prop->vap_name, NAME_FREQUENCY_2_4_G)) {
                *band = WIFI_FREQUENCY_2_4_BAND;
                return RETURN_OK;
            }
            if (strstr(if_prop->vap_name, NAME_FREQUENCY_5L_G)) {
                *band = WIFI_FREQUENCY_5L_BAND;
                return RETURN_OK;
            }
            if (strstr(if_prop->vap_name, NAME_FREQUENCY_5H_G)) {
                *band = WIFI_FREQUENCY_5H_BAND;
                return RETURN_OK;
            }
            if (strstr(if_prop->vap_name, NAME_FREQUENCY_5_G)) {
                *band = WIFI_FREQUENCY_5_BAND;
                return RETURN_OK;
            }
            if (strstr(if_prop->vap_name, NAME_FREQUENCY_6_G)) {
                *band = WIFI_FREQUENCY_6_BAND;
                return RETURN_OK;
            }
        }
        if_prop++;
    }

    return RETURN_ERR;
}

struct wifiStdHalMap
{
    wifi_ieee80211Variant_t halWifiStd;
    char wifiStdName[4];
};

struct  wifiStdHalMap wifiStdMap[] =
{
    {WIFI_80211_VARIANT_A, "a"},
    {WIFI_80211_VARIANT_B, "b"},
    {WIFI_80211_VARIANT_G, "g"},
    {WIFI_80211_VARIANT_N, "n"},
    {WIFI_80211_VARIANT_H, "h"},
    {WIFI_80211_VARIANT_AC, "ac"},
    {WIFI_80211_VARIANT_AD, "ad"},
    {WIFI_80211_VARIANT_AX, "ax"}
};

bool wifiStandardStrToEnum(char *pWifiStdStr, wifi_ieee80211Variant_t *p80211VarEnum, ULONG instance_number, bool twoG80211axEnable)
{
    unsigned int seqCounter = 0;
    bool isWifiStdInvalid = TRUE;
    char *token;
    char tmpInputString[128] = {0};

    if ((pWifiStdStr == NULL) || (p80211VarEnum == NULL))
    {
        wifi_util_dbg_print(WIFI_MON, "%s Invalid Argument\n",__func__);
        return FALSE;
    }

    *p80211VarEnum = 0;
    snprintf(tmpInputString, sizeof(tmpInputString), "%s", pWifiStdStr);

    token = strtok(tmpInputString, ",");
    while (token != NULL)
    {

        isWifiStdInvalid = TRUE;
        for (seqCounter = 0; seqCounter < (unsigned int)ARRAY_SIZE(wifiStdMap); seqCounter++)
        {
            if ((!strcmp("ax", token)) && (instance_number == 0)
                    && !twoG80211axEnable)
            {
                wifi_util_dbg_print(WIFI_MON, "RDK_LOG_INFO, Radio instanceNumber:%lu Device.WiFi.2G80211axEnable"
                            "is set to FALSE(%d), hence unable to set 'AX' as operating standard\n",
                            instance_number,twoG80211axEnable);
                isWifiStdInvalid = FALSE;
            }
            else if (!strcmp(token, wifiStdMap[seqCounter].wifiStdName))
            {
                *p80211VarEnum |= wifiStdMap[seqCounter].halWifiStd;
                wifi_util_dbg_print(WIFI_MON, "%s input : %s wifiStandard : %d\n", __func__, pWifiStdStr, *p80211VarEnum);
                isWifiStdInvalid = FALSE;
            }
        }

        if (isWifiStdInvalid == TRUE)
        {
            wifi_util_dbg_print(WIFI_MON, "RDK_LOG_ERROR, %s Invalid Wifi Standard : %s\n", __func__, pWifiStdStr);
            return FALSE;
        }

        token = strtok(NULL, ",");
    }
    return TRUE;
}

int report_type_conversion(report_type_t *report_type_enum, char *report_type, int report_type_len, unsigned int conv_type)
{
    char arr_str[][16] = {"raw", "average", "histogram", "percentile",  "diff"};

    report_type_t arr_enum[] = {report_type_raw, report_type_average, report_type_histogram, report_type_percentile, report_type_diff};

    unsigned int i = 0;
    if ((report_type_enum == NULL) || (report_type == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], report_type) == 0) {
                *report_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *report_type_enum) {
                snprintf(report_type, report_type_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int survey_type_conversion(survey_type_t *survey_type_enum, char *survey_type, int survey_type_len, unsigned int conv_type)
{
    char arr_str[][16] = { "on-chan", "off-chan", "full"};
    survey_type_t arr_enum[] = {survey_type_on_channel, survey_type_off_channel, survey_type_full};

    unsigned int i = 0;
    if ((survey_type_enum == NULL) || (survey_type == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], survey_type) == 0) {
                *survey_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *survey_type_enum) {
                snprintf(survey_type, survey_type_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int get_steering_cfg_id(char *key, int key_len, unsigned char * id, int id_len, const steering_config_t *st_cfg)
{
    int out_bytes = 0;
    char buff[512];
    int i = 0, outbytes = 0;
    SHA256_CTX ctx;
    if ((key == NULL) || (id == NULL) || (st_cfg == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input arguements are NULL!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    for (i=0; i < st_cfg->vap_name_list_len; i++) {
        if ((st_cfg->vap_name_list[i] == NULL) || (strlen(st_cfg->vap_name_list[i]) == 0)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_name_list failed!!!\n", __func__, __LINE__);
            return RETURN_ERR;

        }

        outbytes +=  snprintf(&buff[outbytes], (sizeof(buff) - outbytes), "%s", st_cfg->vap_name_list[i]);
        if ((out_bytes < 0) || (out_bytes >= key_len)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    }


    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buff, 512);
    SHA256_Final(id, &ctx);

    out_bytes = snprintf(key, key_len, "%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            id[0], id[1], id[2],
            id[3], id[4], id[5],
            id[6], id[7], id[8]);
    if ((out_bytes < 0) || (out_bytes >= key_len)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key:%s\n", __func__, __LINE__, key);

    return RETURN_OK;
}

int get_stats_cfg_id(char *key, int key_len, unsigned char *id, int id_len, const unsigned int stats_type, const unsigned int report_type, const unsigned int radio_type, const unsigned int survey_type)
{
    unsigned char buff[256];
    SHA256_CTX ctx;
    unsigned int pos;
    int out_bytes = 0;

    if ((key == NULL) || (id == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input arguements are NULL!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(buff, 0, 256);

    pos = 0;
    memcpy(&buff[pos], (unsigned char *)&stats_type, sizeof(stats_type)); pos += sizeof(stats_type);
    memcpy(&buff[pos], (unsigned char *)&report_type, sizeof(report_type)); pos += sizeof(report_type);
    memcpy(&buff[pos], (unsigned char *)&radio_type, sizeof(radio_type)); pos += sizeof(radio_type);
    memcpy(&buff[pos], (unsigned char *)&survey_type, sizeof(survey_type));

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buff, 256);
    SHA256_Final(id, &ctx);

    out_bytes = snprintf(key, key_len, "%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            id[0], id[1], id[2],
            id[3], id[4], id[5],
            id[6], id[7], id[8]);
    if ((out_bytes < 0) || (out_bytes >= key_len)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key:%s\n", __func__, __LINE__, key);

    return RETURN_OK;
}

int get_steering_clients_id(char *key, int key_len, unsigned char *id, int id_len, const char *mac)
{
    int out_bytes = 0;
    if ((key == NULL) || (id == NULL) || (mac == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input arguements are NULL!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (WiFi_IsValidMacAddr(mac) != TRUE) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not valid MAC Address : %s!!!\n", __func__, __LINE__, mac);
        return RETURN_ERR;
    }

    out_bytes = snprintf(key, key_len, "%s", mac);
    if ((out_bytes < 0) || (out_bytes >= key_len)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key:%s\n", __func__, __LINE__, key);

    return RETURN_OK;
}

int cs_state_type_conversion(cs_state_t *cs_state_type_enum, char *cs_state, int cs_state_len, unsigned int conv_type)
{
    char arr_str[][16] = {"none", "steering", "expired", "failed", "xing_low", "xing_high", "xing_disabled"};
    cs_state_t arr_enum[] = {cs_state_none, cs_state_steering, cs_state_expired, cs_state_failed, cs_state_xing_low, cs_state_xing_high, cs_state_xing_disabled};

    unsigned int i = 0;
    if ((cs_state_type_enum == NULL) || (cs_state == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], cs_state) == 0) {
                *cs_state_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *cs_state_type_enum) {
                snprintf(cs_state, cs_state_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int cs_mode_type_conversion(cs_mode_t *cs_mode_type_enum, char *cs_mode, int cs_mode_len, unsigned int conv_type)
{
    char arr_str[][16] = {"off", "home", "away"};
    cs_mode_t arr_enum[] = {cs_mode_off, cs_mode_home, cs_mode_away};

    unsigned int i = 0;
    if ((cs_mode_type_enum == NULL) || (cs_mode == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], cs_mode) == 0) {
                *cs_mode_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *cs_mode_type_enum) {
                snprintf(cs_mode, cs_mode_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int force_kick_type_conversion(force_kick_t *force_kick_type_enum, char *force_kick, int force_kick_len, unsigned int conv_type)
{
    char arr_str[][16] = {"none", "speculative", "directed", "ghost_device"};
    force_kick_t arr_enum[] = { force_kick_none, force_kick_speculative, force_kick_directed, force_kick_ghost_device};

    unsigned int i = 0;
    if ((force_kick_type_enum == NULL) || (force_kick == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], force_kick) == 0) {
                *force_kick_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *force_kick_type_enum) {
                snprintf(force_kick, force_kick_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int kick_type_conversion(kick_type_t *kick_type_enum, char *kick_type, int kick_type_len, unsigned int conv_type)
{
    char arr_str[][16] = {"none", "deauth", "disassoc", "bss_tm_req", "rrm_br_req", "btm_deauth","btm_disassoc"};
    kick_type_t arr_enum[] = { kick_type_none, kick_type_deauth, kick_type_disassoc, kick_type_bss_tm_req, kick_type_rrm_br_req, kick_type_btm_deauth, kick_type_btm_disassoc};

    unsigned int i = 0;
    if ((kick_type_enum == NULL) || (kick_type == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], kick_type) == 0) {
                *kick_type_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *kick_type_enum) {
                snprintf(kick_type, kick_type_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int pref_5g_conversion(pref_5g_t *pref_5g_enum, char *pref_5g, int pref_5g_len, unsigned int conv_type)
{
    char arr_str[][16] = {"hwm", "never", "always", "nonDFS"};
    pref_5g_t arr_enum[] = {pref_5g_hwm, pref_5g_never, pref_5g_always, pref_5g_nonDFS};

    unsigned int i = 0;
    if ((pref_5g_enum == NULL) || (pref_5g == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], pref_5g) == 0) {
                *pref_5g_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *pref_5g_enum) {
                snprintf(pref_5g, pref_5g_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}


int reject_detection_conversion(reject_detection_t *reject_detection_enum, char *reject_detection, int reject_detection_len, unsigned int conv_type)
{
    char arr_str[][16] = {"none", "probe_all", "probe_null", "probe_direct", "auth_block"};
    reject_detection_t arr_enum[] = {reject_detection_none, reject_detection_probe_all, reject_detection_probe_null, reject_detection_probe_direcet, reject_detection_auth_blocked};

    unsigned int i = 0;
    if ((reject_detection_enum == NULL) || (reject_detection == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], reject_detection) == 0) {
                *reject_detection_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *reject_detection_enum) {
                snprintf(reject_detection, reject_detection_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int sc_kick_type_conversion(sc_kick_type_t *sc_kick_enum, char *sc_kick, int sc_kick_len, unsigned int conv_type)
{
    char arr_str[][16] = {"none", "deauth", "disassoc", "bss_tm_req", "rrm_br_req", "btm_deauth", "btm_disassoc", "rrm_deauth", "rrm_disassoc"};
    sc_kick_type_t arr_enum[] = { sc_kick_type_none, sc_kick_type_deauth, sc_kick_type_disassoc, sc_kick_type_bss_tm_req, sc_kick_type_rrm_br_req, sc_kick_type_btm_deauth, sc_kick_type_btm_disassoc, sc_kick_type_rrm_deauth, sc_kick_type_rrm_disassoc};

    unsigned int i = 0;
    if ((sc_kick_enum == NULL) || (sc_kick == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], sc_kick) == 0) {
                *sc_kick_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *sc_kick_enum) {
                snprintf(sc_kick, sc_kick_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int sticky_kick_type_conversion(sticky_kick_type_t *sticky_kick_enum, char *sticky_kick, int sticky_kick_len, unsigned int conv_type)
{
    char arr_str[][16] =  {"none", "deauth", "disassoc", "bss_tm_req", "rrm_br_req", "btm_deauth", "btm_disassoc"};
    sticky_kick_type_t arr_enum[] = { sticky_kick_type_none, sticky_kick_type_deauth, sticky_kick_type_disassoc, sticky_kick_type_bss_tm_req, sticky_kick_type_rrm_br_req, sticky_kick_type_btm_deauth, sticky_kick_type_btm_disassoc};

    unsigned int i = 0;
    if ((sticky_kick_enum == NULL) || (sticky_kick == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], sticky_kick) == 0) {
                *sticky_kick_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *sticky_kick_enum) {
                snprintf(sticky_kick, sticky_kick_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int get_vif_neighbor_id(char *key, int key_len, unsigned char *id, int id_len, const char *mac)
{
    int out_bytes = 0;
    if ((key == NULL) || (id == NULL) || (mac == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: input arguements are NULL!!!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (WiFi_IsValidMacAddr(mac) != TRUE) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not valid MAC Address : %s!!!\n", __func__, __LINE__, mac);
        return RETURN_ERR;
    }

    out_bytes = snprintf(key, key_len, "%s", mac);
    if ((out_bytes < 0) || (out_bytes >= key_len)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key:%s\n", __func__, __LINE__, key);

    return RETURN_OK;
}

int vif_neighbor_htmode_conversion(ht_mode_t *ht_mode_enum, char *ht_mode, int ht_mode_len, unsigned int conv_type)
{
    char arr_str[][16] = {"HT20", "HT2040", "HT40", "HT40+", "HT40-", "HT80", "HT160", "HT80+80"};
    ht_mode_t arr_enum[] = {ht_mode_HT20, ht_mode_HT2040, ht_mode_HT40, ht_mode_HT40plus, ht_mode_HT20minus, ht_mode_HT80, ht_mode_HT160, ht_mode_HT80plus80};

    unsigned int i = 0;
    if ((ht_mode_enum == NULL) || (ht_mode == NULL)) {
        return RETURN_ERR;
    }
    if (conv_type == STRING_TO_ENUM) {
        for (i = 0; i < ARRAY_SIZE(arr_str); i++) {
            if (strcmp(arr_str[i], ht_mode) == 0) {
                *ht_mode_enum = arr_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == ENUM_TO_STRING) {
        for (i = 0; i < ARRAY_SIZE(arr_enum); i++) {
            if (arr_enum[i] == *ht_mode_enum) {
                snprintf(ht_mode, ht_mode_len, "%s", arr_str[i]);
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}
