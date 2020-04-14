-- Copyright 2015-2020 Cloudflare
-- Copyright 2014-2015 Aaron Westendorf

local json = require("cjson")
local http = require("resty.http")

local uri         = ngx.var.uri
local uri_args    = ngx.req.get_uri_args()
local scheme      = ngx.var.scheme

local client_id         = ngx.var.ngo_client_id
local client_secret     = ngx.var.ngo_client_secret
local token_secret      = ngx.var.ngo_token_secret
local domain            = ngx.var.ngo_domain
local cb_scheme         = ngx.var.ngo_callback_scheme or scheme
local cb_server_name    = ngx.var.ngo_callback_host or ngx.var.server_name
local cb_uri            = ngx.var.ngo_callback_uri or "/_oauth"
local cb_url            = cb_scheme .. "://" .. cb_server_name .. cb_uri
local redirect_url      = cb_scheme .. "://" .. cb_server_name .. ngx.var.request_uri
local signout_uri       = ngx.var.ngo_signout_uri or "/_signout"
local extra_validity    = tonumber(ngx.var.ngo_extra_validity or "0")
local whitelist         = ngx.var.ngo_whitelist or ""
local blacklist         = ngx.var.ngo_blacklist or ""
local secure_cookies    = ngx.var.ngo_secure_cookies == "true" or false
local http_only_cookies = ngx.var.ngo_http_only_cookies == "true" or false
local set_user          = ngx.var.ngo_user or false
local email_as_user     = ngx.var.ngo_email_as_user == "true" or false
local cookie_domain     = ngx.var.ngo_cookie_domain or ""
local ignore_uri        = ngx.var.ngo_ignore_uri or ""

if whitelist:len() == 0 then
  whitelist = nil
end

if blacklist:len() == 0 then
  blacklist = nil
end

local function handle_token_uris(email, token, expires)
  if uri == "/_token.json" then
    ngx.header["Content-type"] = "application/json"
    ngx.say(json.encode({
      email   = email,
      token   = token,
      expires = expires,
    }))
    ngx.exit(ngx.OK)
  end

  if uri == "/_token.txt" then
    ngx.header["Content-type"] = "text/plain"
    ngx.say("email: " .. email .. "\n" .. "token: " .. token .. "\n" .. "expires: " .. expires .. "\n")
    ngx.exit(ngx.OK)
  end

  if uri == "/_token.curl" then
    ngx.header["Content-type"] = "text/plain"
    ngx.say("-H \"OauthEmail: " .. email .. "\" -H \"OauthAccessToken: " .. token .. "\" -H \"OauthExpires: " .. expires .. "\"\n")
    ngx.exit(ngx.OK)
  end
end

local function check_domain(email)
  local oauth_domain = email:match("[^@]+@(.+)")
  -- if domain is configured, check it, if it isn't, reject request because whitelist was already checked
  if domain and (domain:len() ~= 0) then
    if not string.find(" " .. domain .. " ", " " .. oauth_domain .. " ", 1, true) then
      ngx.log(ngx.ERR, email .. " is not on " .. domain .. " nor in the whitelist")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  else
    ngx.log(ngx.ERR, email .. " is not in the whitelist and no domain is specified")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

local function on_auth(email, token, expires)
  if blacklist then
    -- blacklisted user is always rejected
    if string.find(" " .. blacklist .. " ", " " .. email .. " ", 1, true) then
      ngx.log(ngx.ERR, email .. " is in blacklist")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end

  if whitelist then
    -- if whitelisted, no need to check if it's a valid domain
    if not string.find(" " .. whitelist .. " ", " " .. email .. " ", 1, true) then
      check_domain(email)
    end
  else
    -- empty whitelist, lets check if it's a valid domain
    check_domain(email)
  end

  if set_user then
    if email_as_user then
      ngx.var.ngo_user = email
    else
      ngx.var.ngo_user = email:match("([^@]+)@.+")
    end
  end

  handle_token_uris(email, token, expires)
end

local function request_access_token(code)
  local request = http.new()

  request:set_timeout(7000)

  local res, err = request:request_uri("https://accounts.google.com/o/oauth2/token", {
    method = "POST",
    body = ngx.encode_args({
      code          = code,
      client_id     = client_id,
      client_secret = client_secret,
      redirect_uri  = cb_url,
      grant_type    = "authorization_code",
    }),
    headers = {
      ["Content-type"] = "application/x-www-form-urlencoded"
    },
    ssl_verify = true,
  })
  if not res then
    return nil, (err or "auth token request failed: " .. (err or "unknown reason"))
  end

  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from https://accounts.google.com/o/oauth2/token: " .. res.body
  end

  return json.decode(res.body)
end

local function request_profile(token)
  local request = http.new()

  request:set_timeout(7000)

  local res, err = request:request_uri("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers = {
      ["Authorization"] = "Bearer " .. token,
    },
    ssl_verify = true,
  })
  if not res then
    return nil, "auth info request failed: " .. (err or "unknown reason")
  end

  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from https://www.googleapis.com/oauth2/v2/userinfo"
  end

  return json.decode(res.body)
end

local function is_authorized()
  if uri:sub(1, #ignore_uri) == ignore_uri then
    return true
  end

  local headers = ngx.req.get_headers()

  local expires = tonumber(ngx.var.cookie_OauthExpires) or 0
  local email   = ngx.unescape_uri(ngx.var.cookie_OauthEmail or "")
  local token   = ngx.unescape_uri(ngx.var.cookie_OauthAccessToken or "")

  if expires == 0 and headers["oauthexpires"] then
    expires = tonumber(headers["oauthexpires"])
  end

  if email:len() == 0 and headers["oauthemail"] then
    email = headers["oauthemail"]
  end

  if token:len() == 0 and headers["oauthaccesstoken"] then
    token = headers["oauthaccesstoken"]
  end

  local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, cb_server_name .. email .. expires))

  if token == expected_token and expires and expires > ngx.time() - extra_validity then
    on_auth(email, expected_token, expires)
    return true
  else
    return false
  end
end

local function redirect_to_auth()
  -- google seems to accept space separated domain list in the login_hint, so use this undocumented feature.
  return ngx.redirect("https://accounts.google.com/o/oauth2/auth?" .. ngx.encode_args({
    client_id     = client_id,
    scope         = "email",
    response_type = "code",
    redirect_uri  = cb_url,
    state         = redirect_url,
    login_hint    = domain,
  }))
end

local function authorize()
  if uri ~= cb_uri then
    return redirect_to_auth()
  end

  if uri_args["error"] then
    ngx.log(ngx.ERR, "received " .. uri_args["error"] .. " from https://accounts.google.com/o/oauth2/auth")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local token, token_err = request_access_token(uri_args["code"])
  if not token then
    ngx.log(ngx.ERR, "got error during access token request: " .. token_err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local profile, profile_err = request_profile(token["access_token"])
  if not profile then
    ngx.log(ngx.ERR, "got error during profile request: " .. profile_err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local expires      = ngx.time() + token["expires_in"]
  local cookie_tail  = ";version=1;path=/;Max-Age=" .. extra_validity + token["expires_in"]
  if secure_cookies then
    cookie_tail = cookie_tail .. ";secure"
  end
  if http_only_cookies then
    cookie_tail = cookie_tail .. ";httponly"
  end
  if cookie_domain ~= "" then
    cookie_tail = cookie_tail .. ";Domain=" .. cookie_domain
  end

  local email      = profile["email"]
  local user_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, cb_server_name .. email .. expires))

  on_auth(email, user_token, expires)

  ngx.header["Set-Cookie"] = {
    "OauthEmail="       .. ngx.escape_uri(email) .. cookie_tail,
    "OauthAccessToken=" .. ngx.escape_uri(user_token) .. cookie_tail,
    "OauthExpires="     .. expires .. cookie_tail,
  }

  return ngx.redirect(uri_args["state"])
end

local function handle_signout()
  if uri == signout_uri then
    ngx.header["Set-Cookie"] = "OauthAccessToken==deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
    return ngx.redirect("/")
  end
end

handle_signout()

if not is_authorized() then
  authorize()
end

-- if already authenticated, but still receives a /_oauth request, redirect to the correct destination
if uri == "/_oauth" then
  return ngx.redirect(uri_args["state"])
end
