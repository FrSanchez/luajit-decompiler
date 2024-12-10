local ngx_var = ngx.var
local ngx_now = ngx.now
local ngx_update_time = ngx.update_time
local md5_bin = ngx.md5_bin
local fmt = string.format
local buffer = require("string.buffer")
local lrucache = require("resty.lrucache")
local kong = kong
local meta = require("kong.meta")
local constants = require("kong.constants")
local aws_config = require("resty.aws.config")
local VIA_HEADER = constants.HEADERS.VIA
local VIA_HEADER_VALUE = meta._NAME .. "/" .. meta._VERSION
local request_util = require("kong.plugins.aws-lambda.request-util")
local build_request_payload = request_util.build_request_payload
local extract_proxy_response = request_util.extract_proxy_response
local remove_array_mt_for_empty_table = request_util.remove_array_mt_for_empty_table
local aws = require("resty.aws")
local AWS_GLOBAL_CONFIG, AWS_REGION = nil
AWS_REGION = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
local AWS, LAMBDA_SERVICE_CACHE = nil

local function get_now()
	ngx_update_time()

	return ngx_now() * 1000
end

local function initialize()
	LAMBDA_SERVICE_CACHE = lrucache.new(1000)
	AWS_GLOBAL_CONFIG = aws_config.global
	AWS = aws()
	initialize = nil
end

local build_cache_key = nil
local SERVICE_RELATED_FIELD = {
	"timeout",
	"keepalive",
	"aws_key",
	"aws_secret",
	"aws_assume_role_arn",
	"aws_role_session_name",
	"aws_region",
	"host",
	"port",
	"disable_https",
	"proxy_url",
	"aws_imds_protocol_version"
}

function build_cache_key(conf)
	local cache_key_buffer = buffer.new(100):reset()

	for _, field in ipairs(SERVICE_RELATED_FIELD) do
		local v = conf[field]

		if v then
			cache_key_buffer:putf("%s=%s;", field, v)
		end
	end

	return md5_bin(cache_key_buffer:get())
end

local AWSLambdaHandler = {
	PRIORITY = 750,
	VERSION = meta.core_version,
	access = function (self, conf)
		local kong_wait_time_start = get_now()

		if initialize then
			initialize()
		end

		local region = conf.aws_region or AWS_REGION

		if not region then
			return error("no region specified")
		end

		local host = conf.host or fmt("lambda.%s.amazonaws.com", region)
		local port = conf.port or 443
		local scheme = conf.disable_https and "http" or "https"
		local endpoint = fmt("%s://%s", scheme, host)
		local cache_key = build_cache_key(conf)
		local lambda_service = LAMBDA_SERVICE_CACHE:get(cache_key)

		if not lambda_service then
			local credentials = AWS.config.credentials

			if conf.aws_key then
				local creds = AWS:Credentials({
					accessKeyId = conf.aws_key,
					secretAccessKey = conf.aws_secret
				})
				credentials = creds
			elseif conf.proxy_url and AWS_GLOBAL_CONFIG.AWS_WEB_IDENTITY_TOKEN_FILE and AWS_GLOBAL_CONFIG.AWS_ROLE_ARN then
				local creds = AWS:TokenFileWebIdentityCredentials()
				creds.sts = AWS:STS({
					ssl_verify = false,
					region = region,
					stsRegionalEndpoints = AWS_GLOBAL_CONFIG.sts_regional_endpoints,
					http_proxy = conf.proxy_url,
					https_proxy = conf.proxy_url
				})
				credentials = creds
			end

			if conf.aws_assume_role_arn then
				local sts, err = AWS:STS({
					ssl_verify = false,
					credentials = credentials,
					region = region,
					stsRegionalEndpoints = AWS_GLOBAL_CONFIG.sts_regional_endpoints,
					http_proxy = conf.proxy_url,
					https_proxy = conf.proxy_url
				})

				if not sts then
					return error(fmt("unable to create AWS STS (%s)", err))
				end

				local sts_creds = AWS:ChainableTemporaryCredentials({
					params = {
						RoleArn = conf.aws_assume_role_arn,
						RoleSessionName = conf.aws_role_session_name
					},
					sts = sts
				})
				credentials = sts_creds
			end

			lambda_service = AWS:Lambda({
				ssl_verify = false,
				credentials = credentials,
				region = region,
				endpoint = endpoint,
				port = port,
				timeout = conf.timeout,
				keepalive_idle_timeout = conf.keepalive,
				http_proxy = conf.proxy_url,
				https_proxy = conf.proxy_url
			})

			LAMBDA_SERVICE_CACHE:set(cache_key, lambda_service)
		end

		local upstream_body_json = build_request_payload(conf)
		local res, err = lambda_service:invoke({
			FunctionName = conf.function_name,
			InvocationType = conf.invocation_type,
			LogType = conf.log_type,
			Payload = upstream_body_json,
			Qualifier = conf.qualifier
		})
		local ctx = ngx.ctx
		local lambda_wait_time_total = get_now() - kong_wait_time_start
		ctx.KONG_WAITING_TIME = lambda_wait_time_total
		kong.ctx.plugin.waiting_time = lambda_wait_time_total

		if err then
			return error(err)
		end

		local content = res.body

		if res.status >= 400 then
			return error(content.Message)
		end

		local headers = res.headers
		headers["Content-Length"] = nil

		if ngx_var.http2 then
			headers.Connection = nil
			headers["Keep-Alive"] = nil
			headers["Proxy-Connection"] = nil
			headers.Upgrade = nil
			headers["Transfer-Encoding"] = nil
		end

		local status = nil

		if conf.is_proxy_integration then
			local proxy_response, err = extract_proxy_response(content)

			if not proxy_response then
				kong.log.err(err)

				return kong.response.exit(502, {
					message = "Bad Gateway",
					error = "could not JSON decode Lambda " .. "function response: " .. err
				})
			end

			status = proxy_response.status_code
			headers = kong.table.merge(headers, proxy_response.headers)
			content = proxy_response.body
		end

		status = status or (not conf.unhandled_status or headers["X-Amz-Function-Error"] ~= "Unhandled" or conf.unhandled_status) and res.status
		headers = kong.table.merge(headers)

		if kong.configuration.enabled_headers[VIA_HEADER] then
			headers[VIA_HEADER] = VIA_HEADER_VALUE
		end

		if conf.empty_arrays_mode == "legacy" then
			local ct = headers["Content-Type"]

			if ct and ct:lower():match("application/.*json") then
				content = remove_array_mt_for_empty_table(content)
			end
		end

		return kong.response.exit(status, content, headers)
	end,
	header_filter = function (self, conf)
		local ctx = ngx.ctx

		if ctx.KONG_RESPONSE_LATENCY then
			ctx.KONG_RESPONSE_LATENCY = ctx.KONG_RESPONSE_LATENCY - (kong.ctx.plugin.waiting_time or 0)
		end
	end
}

return AWSLambdaHandler
