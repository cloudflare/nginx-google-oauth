#!/bin/sh -e

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

NGO_CALLBACK_SCHEME=${NGO_CALLBACK_SCHEME:-https}
NGO_EXTRA_VALIDITY=${NGO_EXTRA_VALIDITY:-0}

sed "s/%client_id%/${NGO_CLIENT_ID}/"             -i /etc/nginx/sites-available/default
sed "s/%client_secret%/${NGO_CLIENT_SECRET}/"     -i /etc/nginx/sites-available/default
sed "s/%token_secret%/${NGO_TOKEN_SECRET}/"       -i /etc/nginx/sites-available/default
sed "s/%callback_scheme%/${NGO_CALLBACK_SCHEME}/" -i /etc/nginx/sites-available/default
sed "s/%extra_validity%/${NGO_EXTRA_VALIDITY}/"   -i /etc/nginx/sites-available/default

exec nginx -g "daemon off;" -c /etc/nginx/nginx.conf
