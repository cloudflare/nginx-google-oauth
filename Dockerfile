# debian:jessie at 2016-06-02T10:27:00Z
FROM debian@sha256:2ca1d757fce75accad6ff84339c3327c7aa96ad6e7b7d6fdde22b2a537fac703

RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx-extras lua-cjson git ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    git clone -c transfer.fsckobjects=true https://github.com/pintsized/lua-resty-http.git /tmp/lua-resty-http && \
    cd /tmp/lua-resty-http && \
    # https://github.com/pintsized/lua-resty-http/releases/tag/v0.07 v0.07
    git checkout 69695416d408f9cfdaae1ca47650ee4523667c3d && \
    mkdir -p /etc/nginx/lua && \
    cp -aR /tmp/lua-resty-http/lib/resty /etc/nginx/lua/resty && \
    rm -rf /tmp/lua-resty-http && \
    mkdir /etc/nginx/http.conf.d && \
    sed 's%http {%include /etc/nginx/http.conf.d/*.conf;\n\nhttp {%' -i /etc/nginx/nginx.conf

COPY ./access.lua /etc/nginx/lua/nginx-google-oauth/access.lua
COPY ./docker/etc-nginx /etc/nginx

ENTRYPOINT ["/etc/nginx/run.sh"]
