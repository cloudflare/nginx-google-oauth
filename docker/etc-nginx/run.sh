#!/bin/sh -e

PORT=${PORT:-80}
RESOLVER=${RESOLVER:-8.8.8.8}
NGO_SERVER_NAME=${NGO_SERVER_NAME}
NGO_SERVER_PORT=${NGO_SERVER_PORT}

sed "s/%port%/${PORT}/" -i /etc/nginx/sites-available/default
sed "s/%resolver%/${RESOLVER}/" -i /etc/nginx/sites-available/default
sed "s/%server_name%/${NGO_SERVER_NAME}/" -i /etc/nginx/snippets/demo-locations.conf
sed "s/%server_port%/${NGO_SERVER_PORT}/" -i /etc/nginx/snippets/demo-locations.conf

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
export NGO_CALLBACK_SCHEME=${NGO_CALLBACK_SCHEME:-https}
export NGO_CALLBACK_URI=${NGO_CALLBACK_URI-/_oauth}
export NGO_SIGNOUT_URI=${NGO_SIGNOUT_URI-/_signout}
export NGO_EMAIL_AS_USER=${NGO_EMAIL_AS_USER:-true}
export NGO_EXTRA_VALIDITY=${NGO_EXTRA_VALIDITY:-0}
export NGO_USER=${NGO_USER:-unknown}

# Overwrite user supplied locations
if [ "${LOCATIONS}" ]; then
  echo "${LOCATIONS}" > /etc/nginx/snippets/demo-locations.conf
fi

# Help people spot problems
if [ "${DEBUG}" ]; then
  echo "## /etc/nginx/sites-available/default ##"
  cat -n /etc/nginx/sites-available/default
  echo "## /etc/nginx/snippets/demo-locations.conf ##"
  cat -n /etc/nginx/snippets/demo-locations.conf
  echo "## environment ##"
  env | grep '^\(NGO_.*\|LOCATIONS\|PORT\)=' | sort -n | cat -n
fi

exec nginx -g "daemon off;" -c /etc/nginx/nginx.conf
