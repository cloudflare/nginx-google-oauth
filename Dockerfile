# debian:jessie
FROM debian@sha256:a9c958be96d7d40df920e7041608f2f017af81800ca5ad23e327bc402626b58e

RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx-extras lua-cjson git ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    git clone -c transfer.fsckobjects=true https://github.com/pintsized/lua-resty-http.git /tmp/lua-resty-http && \
    cd /tmp/lua-resty-http && \
    # https://github.com/pintsized/lua-resty-http/releases/tag/v0.07 v0.07
    git checkout 69695416d408f9cfdaae1ca47650ee4523667c3d && \
    mkdir -p /etc/nginx/lua && \
    cp -aR /tmp/lua-resty-http/lib/resty /etc/nginx/lua/resty && \
    rm -rf /tmp/lua-resty-http

COPY ./access.lua /etc/nginx/lua/nginx-google-oauth/access.lua
COPY ./docker/server.conf /etc/nginx/sites-available/default
COPY ./docker/demo /etc/nginx/demo
COPY ./docker/run.sh /run.sh

ENTRYPOINT ["/run.sh"]
