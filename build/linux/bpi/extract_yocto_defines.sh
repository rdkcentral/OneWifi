#!/bin/bash
META_RECIPE_PATH="meta-cmf-bananapi/meta-rdk-mtk-bpir4/recipes-ccsp/ccsp/ccsp-one-wifi.bbappend"
DISTROCONF_PATH="meta-cmf-bananapi/conf/distro/include/rdk-bpi.inc"

FEATURES=$(awk -F '"' '(/DISTRO_FEATURES_append/ || /DISTRO_FEATURES +=/) && !/#/ {print substr($0, index($0, $2))}' "${DISTROCONF_PATH}" | tr -d "\"" | tr '\n' ' ')
RECIPE_CFLAGS=$(awk -F '=' '(/CFLAGS/) {print $0}' "${META_RECIPE_PATH}")
OECONF_EXTRAS=$(awk '/EXTRA_OECONF/ {print $0}' "${META_RECIPE_PATH}")
LDFLAGS=$(awk -F '=' '/LDFLAGS/ {print $2}' "${META_RECIPE_PATH}" | tr -d '"' | tr '\n' ' ')

#Check following:
#if has conditional - check if applicable, then add/remove
#otherwise add/remove

extract_variables() {
    local CONFLIST="${1}"
    local OUT=""
    while IFS= read -r flag; do
        if [[ ${flag} =~ "utils" ]]; then
            cond_flag=$(awk -F ',' '{print $3}' <<< "${flag}")
            cond_flag=${cond_flag//\'/}
            feature=$(awk -F ',' '{print $2}' <<< "${flag}")
            feature=${feature//\'/}
            #Distro feature specified ?
            if [[ ${FEATURES} =~ ${feature} ]]; then
                #add/remove
                if [[ ${flag} =~ "append" ]] || [[ ${flag} =~ "+=" ]]; then
                    OUT+=" ${cond_flag} "
                else
                    REMOVE=$(awk -F ',' '{print $2}' <<< "${flag}")
                    final=""
                    for rm in ${OUT}; do
                        [[ ${REMOVE} =~ ${rm} ]] || final+=" ${rm}"
                    done
                    OUT=${final}
                fi
            fi
        else
            add="${flag#*=}"
            OUT+=" ${add//\"/} "
        fi
    done <<< "${CONFLIST}"
    echo "$OUT"
}

CFLAGS=$(extract_variables "${RECIPE_CFLAGS}")
OECONFS=$(extract_variables "${OECONF_EXTRAS}")

echo "export CFLAGS=\"${CFLAGS}\"" >> build.env
echo "export LDFLAGS=\"${LDFLAGS}\"" >> build.env

enable=1
for oeconf in ${OECONFS}; do
    echo "export ${oeconf%%=*}=${enable}" >> build.env
done
