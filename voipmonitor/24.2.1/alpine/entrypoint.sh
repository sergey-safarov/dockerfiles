#!/bin/sh

CONFIG="${CONFIG:-/etc/voipmonitor.conf}"

get_config_token() {
  cat ${CONFIG} | grep -E "^cloud_token\s*=\s*\S+" | sed -E -e 's/cloud_token\s*=\s*//' -e 's/\s+.*//'
}

get_sensor_id() {
  cat ${CONFIG} | grep -E "id_sensor\s*=\s*\S+" | sed -E -e 's/id_sensor\s*=\s*//' -e 's/\s+.*//'
}

if [ -z "${TOKEN}" ]; then
  TOKEN=$(get_config_token)
fi

if [ -z "${SENSOR_ID}" ]; then
  SENSOR_ID=$(get_sensor_id)
fi

if [ "${TOKEN}" == "xxxxxxxxxxxxxxxxxxxxxx" ]; then
  echo "TOKEN environment variable not configured. Please specify '-e TOKEN=value option'"
  exit 1
fi

if [ -z "${SENSOR_ID}" ]; then
  SENSOR_ID=0
fi

sed -e "s/.*cloud_token.*/cloud_token = ${TOKEN}/" ${CONFIG} > /tmp/runtime.conf

exec /usr/local/sbin/voipmonitor -k --config-file /tmp/runtime.conf --id-sensor=${SENSOR_ID}

