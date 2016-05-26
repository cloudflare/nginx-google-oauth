# nginx-google-oauth

Lua module to add Google OAuth to nginx. It is based on great work
from [Agora Games](https://github.com/agoragames/nginx-google-oauth).

Fast forward to the [docker image](#Docker image) section to try it out.

## Installation

You can copy `access.lua` to your nginx configurations, or clone the
repository. Your installation of nginx must already be built with Lua
support, and you will need the following modules:

* [cjson](http://www.kyne.com.au/~mark/software/lua-cjson.php)
* [resty.http](https://github.com/pintsized/lua-resty-http)

## Configuration

Add the access controls in your configuration. Because OAuth tickets will be
included in cookies (and you are presumably protecting something very
important), it is strongly recommended that you use SSL.

```
server {
  server_name supersecret.net;

  listen 443 ssl;

  ssl_certificate /etc/nginx/certs/supersecret.net.pem;
  ssl_certificate_key /etc/nginx/certs/supersecret.net.key;

  set $ngo_client_id "abc-def.apps.googleusercontent.com";
  set $ngo_client_secret "abcdefg-123-xyz";
  set $ngo_token_secret "a very long randomish string";
  set $ngo_secure_cookies "true";

  access_by_lua_file "/etc/nginx/lua/nginx-google-oauth/access.lua";
}
```

The access controls can be configured using nginx variables. The supported
variables are:

- **$ngo_client_id** This is the client id key.
- **$ngo_client_secret** This is the client secret.
- **$ngo_token_secret** The key used to encrypt the session token stored
  in the user cookie.  Should be long & unguessable.
- **$ngo_domain** The domain to use for validating users when not using
  white- or blacklists.
- **$ngo_callback_scheme** The scheme for the callback URL,
  defaults to that of the request (e.g. `https`).
- **$ngo_callback_host** The host for the callback, defaults to first entry
  in the ``server_name`` list (e.g `supersecret.net`).
- **$ngo_callback_uri** The URI for the callback, defaults to `/_oauth`.
- **$ngo_ngo_signout_uri** The URI for sign-out endpoint.
- **$ngo_extra_validity** Time in seconds to add to token validity period.
- **$ngo_whitelist** Optional list of authorized email addresses.
- **$ngo_blacklist** Optional list of unauthorized email addresses.
- **$ngo_secure_cookies** If defined, will ensure that cookies can only
  be transferred over a secure connection.
- **$ngo_user** If set, will be populated with the OAuth username
  returned from Google (portion left of '@' in email).
- **$ngo_email_as_user** If set and `$ngo_user` is defined, username
  returned will be full email address.

## Available endpoints

### `/_signout`

Default sign-out URI, can be changed with `$ngo_signout_uri` variable. It clears
cookies and does redirect to the `/` location of your domain.

### `/_token.json`

Endpoint that reports your OAuth token in a JSON object:

```json
{
  "email": "foo@example.com",
  "token": "abc..xyz",
  "expires": 1445455680
}
```

### `/_token.txt`

Endpoint that reports your OAuth token in text format:

```
email: foo@example.com
token: abc..xyz
expires: 1445455680
```

### `/_token.curl`

Endpoint that reports your OAuth token as `curl` arguments for header auth:

```
-H "OauthEmail: foo@example.com" -H "OauthAccessToken: abc..xyz" -H "OauthExpires: 1445455680"
```

You can add it to your `curl` command to make it work with OAuth.

## Authentication

Any request to nginx can be authenticated in two ways: with headers and with
cookies. When you open your site in a web browser, it sends you to Google
to obtain OAuth token and these are set as cookies. Users don't have to do
anything special, it just works seamlessly.

If you are willing to protect a domain that is used by automatic CLI tools,
it is problematic to use cookies from your browser. Instead, you can can use
any of endpoints described in the previous section to obtain tokens and pass
them to your tools.

An example would be a `curl` command that you might use to refresh local
currency rates:

```
curl -s https://example.com/rates.json > ~/currency-rates.json
```

Now if you enabled OAuth on `example.com`, this command would not work anymore,
resulting in 301 redirect to OAuth from Google. To make it work, you'll have
to go to `https://example.com/_token.curl`, copy header arguments for curl
and paste them into your command:

```
curl -s $HEADER_ARGS https://example.com/rates.json > ~/currency-rates.json
```

## Extended token validity

OAuth token from Google are short-lived, but this is not always convenient if
you want to put something frequently used behind OAuth. In this case, you can
extend token validity by `$ngo_extra_validity` seconds. An good example would
be some site you use at work. Setting `$ngo_extra_validity` to `43200` (12h)
means that you only have to authorize on it once a day with a standard 8 hour
or less work day.

Token validity can be shortened with negative values as well.

## Configuring OAuth access

Visit https://console.developers.google.com. If you're signed in to multiple
Google accounts, be sure to switch to the one which you want to host the OAuth
credentials (usually your company's Apps domain). This should match
``$ngo_domain`` (e.g. `yourcompany.com`).

From the dashboard, create a new project. After selecting that project, search
for "Credentials" in the search box. Make sure to fill "OAuth consent screen"
section first. Then create "OAuth client ID": select "Web application", fill
the name of your app, skip "Authorized JavaScript origins" and fill
"Authorized redirect URIs" (e.g. `https://example.com/_oauth`).

After completing the form you will be presented with the Client ID and
Client Secret which you can use to configure `$ngo_client_id` and
`$ngo_client_secret` respectively.

Since you can have unlimited OAuth client IDs in one app, but number of apps
is limited, it makes sense to reuse the same app.

## Username variable

`$ngo_user` can be used in any place where you could use variable in nginx,
this includes:

* Logging
* Passing params to external FastCGI/UWSGI scripts
* Headers for upstream servers
* Lua scripts
* etc.

### Docker image

You have to [obtain tokens](#Configuring OAuth access) first.

There is a pre-built image: `cloudflare/nginx-google-oauth`. If you are
hacking on this project, you might want to rebuild the image yourself.

To make it work locally, add a record to DNS or to `/etc/hosts`, pointing
to the ip of your docker daemon, we use `ngo.lol` here. Make sure to add
`http://ngo.lol/_oauth` as an "Authorized redirect URIs" in Google console.

Docker image has the following env variables for configuration:

* `DEBUG`: if set, prints the generated nginx configuation on container start
* `LOCATIONS` can contain `location` directives that will be injected into the
  nginx configuration on container start. If not set, a demo page is served
  under `location / {...}`
* `NGO_BLACKLIST` is the value of `$ngo_blacklist`.
* `NGO_CALLBACK_HOST` is the value of `$ngo_callback_host`.
* `NGO_CALLBACK_SCHEME` is the value of `$ngo_callback_scheme`.
* `NGO_CALLBACK_SCHEME` is the value of `$ngo_callback_scheme`, required.
* `NGO_CALLBACK_URI` is the value of `$ngo_callback_uri`.
* `NGO_CLIENT_ID` is the value of `$ngo_client_id`, required.
* `NGO_CLIENT_SECRET` is the value of `$ngo_client_secret`, required.
* `NGO_DOMAIN` is the value of `$ngo_domain`.
* `NGO_EMAIL_AS_USER` is the value of `$ngo_email_as_user`
* `NGO_EXTRA_VALIDITY` is the value of `$ngo_extra_validity`, required.
* `NGO_SECURE_COOKIES` is the value of `$ngo_secure_cookies`
* `NGO_TOKEN_SECRET` is the value of `$ngo_token_secret`, required.
* `NGO_USER` is the value of `$ngo_user`.
* `NGO_WHITELIST` is the value of `$ngo_whitelist`.
* `PORT` is the port for nginx to listen on, defaults to `80`.

Run the image:

```
docker run --rm -it --net host \
  -e DEBUG=1 \
  -e NGO_CALLBACK_SCHEME=http \
  -e NGO_CLIENT_ID="client id from google" \
  -e NGO_CLIENT_SECRET="client secret from google" \
  -e NGO_TOKEN_SECRET="random token secret" \
  cloudflare/nginx-google-oauth:1.0
```

Then open your browser at http://ngo.lol and you should get Google OAuth screen.

## Copyright

* Copyright 2015-2016 CloudFlare
* Copyright 2014-2015 Aaron Westendorf

## License

MIT
