#!/bin/sh

set -e

if [ -z "${API_URL}" ]; then
    echo "container expect configured API_URL environment variable. Without this you not be able login to monster-ui"
    exit 1
fi

LASTCHAR=$(echo -n "${API_URL}" | tail -c 1)
if [ "${LASTCHAR}" != "/" ]; then
    API_URL=${API_URL}/
fi

sed -e "s|http://monster.ui/|${API_URL}|" \
    -i /var/www/monster-ui-dev/js/config.js

if [ ! -z "${UPSTREAM_URL}" ]; then
    sed -e "s|http://kazoo-app.kazoo|${UPSTREAM_URL}|" \
        -i /etc/nginx/sites-available/monster-ui.conf
fi

if [ ! -z "${WEBRTC_URL}" ]; then
    sed -e "s|http://kazoo-app-ws.kazoo|${WEBRTC_URL}|" \
        -i /etc/nginx/sites-available/monster-ui.conf
fi

if [ "${DEVEL_MODE}" = "true" ]; then
    echo "enabled not minified monster-ui"
    sed -e "s|root /var/www/monster-ui-prod|root /var/www/monster-ui-dev|" \
        -i /etc/nginx/sites-available/monster-ui.conf
fi

if [ -z "${CERT_FILE}" -o -z "${KEY_FILE}" ]; then
    HTTPS_ENABLED=false
    echo 'Environment variable ${CERT_FILE} or ${KEY_FILE} is empty. Will be used only HTTP port'
else
    HTTPS_ENABLED=true
    sed -e "s|fullchain.pem|${CERT_FILE}|" \
        -e "s|privkey.pem|${KEY_FILE}|" \
        -e "s|^# | |" \
        -i /etc/nginx/sites-available/monster-ui.conf
fi

if [ "${HTTPS_FORCE}" = "true" ]; then
    sed -e -e "s|^## | |" \
        -i /etc/nginx/sites-available/monster-ui.conf
fi

if [ ! -z "${CERTBOT_URL}" ]; then
    echo "Used CERTBOT_URL=${CERTBOT_URL}"
    sed -e "s|http://169.254.254.254|${CERTBOT_URL}|" \
        -i /etc/nginx/sites-available/monster-ui.conf
fi

if [ "${HIDE_POWERED}" = "true" ]; then
    sed -E -e "s/(\s+)(companyName)/\1hide_powered: true,\n\1\2/" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${LANGUAGE}" ]; then
    sed -E -e "s/(\s+)(companyName)/\1language: '${LANGUAGE}',\n\1\2/" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${LOGO_PATH}" ]; then
    sed -E -e "s|(\s+)(companyName)|\1logoPath: '${LOGO_PATH}',\n\1\2|" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${FAVICON_PATH}" ]; then
    sed -E -e "s|(\s+)(companyName)|\1faviconPath: '${FAVICON_PATH}',\n\1\2|" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${COUNTRY_CODE}" ]; then
    sed -E -e "s/(\s+)(companyName)/\1countryCode: '${COUNTRY_CODE}',\n\1\2/" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${REALM_SUFFIX}" ]; then
    sed -E -e "s/(\s+)(companyName)/\1realm_suffix: '${REALM_SUFFIX}',\n\1\2/" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${COMPANY_NAME}" ]; then
    sed -e "s|companyName: '2600Hz'|companyName: '${COMPANY_NAME}'|" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${APPLICATION_TITLE}" ]; then
    sed -e "s|applicationTitle: 'Monster UI'|applicationTitle: '${APPLICATION_TITLE}'|" \
        -i /var/www/monster-ui-dev/js/config.js
fi

if [ ! -z "${CALL_REPORT_EMAIL}" ]; then
    sed -e "s|callReportEmail: 'support@2600hz.com'|callReportEmail: '${CALL_REPORT_EMAIL}'|" \
        -i /var/www/monster-ui-dev/js/config.js
fi

cp -f /var/www/monster-ui-dev/js/config.js /var/www/monster-ui-prod/js/config.js

exec nginx -g 'daemon off;'
