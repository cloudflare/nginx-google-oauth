#!/bin/bash

PORT=${PORT:-80}

sed "s/%port%/${PORT}/" -i /etc/nginx/sites-available/default

if [ -z "${NGO_CLIENT_ID}" ]; then
  echo "NGO_CLIENT_ID is not set"
  exit 1
fi

if [ -z "${NGO_CLIENT_SECRET}" ]; then
  echo "NGO_CLIENT_SECRET is not set"
  exit 1
fi

if [ -z "${NGO_TOKEN_SECRET}" ]; then
  echo "NGO_TOKEN_SECRET is not set"
  exit 1
fi

# Define some defaults
NGO_CALLBACK_HOST=${NGO_CALLBACK_HOST-\$\{host\}}
NGO_CALLBACK_SCHEME=${NGO_CALLBACK_SCHEME:-https}
NGO_CALLBACK_URI=${NGO_CALLBACK_URI-/_oauth}
NGO_EMAIL_AS_USER=${NGO_EMAIL_AS_USER:-true}
NGO_EXTRA_VALIDITY=${NGO_EXTRA_VALIDITY:-0}
NGO_USER=${NGO_USER:-unknown}

# Default/demo location for nginx
echo "# Default location, supply your own via -e LOCATIONS=...
location / {
  root /etc/nginx/demo;
}
" > /tmp/nginx-locations.conf

# Overwrite user supplied locations
if [ "${LOCATIONS}" ]; then
  echo "#
# Generated /tmp/nginx-locations.conf
#
${LOCATIONS}" > /tmp/nginx-locations.conf
fi

# Write config file
sed "s/%NGO_BLACKLIST%/${BLACKLIST}/"                      -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_CALLBACK_HOST%/${NGO_CALLBACK_HOST-\$host}/" -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_CALLBACK_SCHEME%/${NGO_CALLBACK_SCHEME}/"    -i /etc/nginx/sites-available/default && \
  sed "s|%NGO_CALLBACK_URI%|${NGO_CALLBACK_URI}|"          -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_CLIENT_ID%/${NGO_CLIENT_ID}/"                -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_CLIENT_SECRET%/${NGO_CLIENT_SECRET}/"        -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_DOMAIN%/${NGO_DOMAIN}/"                      -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_EMAIL_AS_USER%/${NGO_EMAIL_AS_USER}/"        -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_EXTRA_VALIDITY%/${NGO_EXTRA_VALIDITY}/"      -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_SECURE_COOKIES%/${NGO_SECURE_COOKIES}/"      -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_TOKEN_SECRET%/${NGO_TOKEN_SECRET}/"          -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_USER%/${NGO_USER}/"                          -i /etc/nginx/sites-available/default && \
  sed "s/%NGO_WHITELIST%/${NGO_WHITELIST}/"                -i /etc/nginx/sites-available/default


# Help people spot problems
if [ $DEBUG ]; then
  cat -n /etc/nginx/sites-available/default
  cat -n /tmp/nginx-locations.conf
fi

exec nginx -g "daemon off;" -c /etc/nginx/nginx.conf
