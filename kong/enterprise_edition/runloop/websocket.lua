local ws_proxy = require("kong.enterprise_edition.runloop.websocket.proxy")
local balancer = require("kong.runloop.balancer")
local pdk = require("kong.enterprise_edition.pdk.private.websocket")
local cert_utils = require("kong.enterprise_edition.cert_utils")
local balancers = require("kong.runloop.balancer.balancers")
local const = require("kong.constants")
local kong_global = require("kong.global")
local tracing = require("kong.tracing")
local runloop = require("kong.runloop.handler")
local new_tab = require("table.new")
local nkeys = require("table.nkeys")
local time_ns = require("kong.tools.utils").time_ns

local function NOOP()
end

local PHASES = kong_global.phases
local WEBSOCKET = const.WEBSOCKET
local STATUS = WEBSOCKET.STATUS
local CLIENT_MAX_DEFAULT = WEBSOCKET.DEFAULT_CLIENT_MAX_PAYLOAD
local UPSTREAM_MAX_DEFAULT = WEBSOCKET.DEFAULT_UPSTREAM_MAX_PAYLOAD
local RECV_TIMEOUT = 5000
local SEND_TIMEOUT = 5000
local JANITOR_TIMEOUT = 5
local WS_EXTENSIONS = const.WEBSOCKET.HEADERS.EXTENSIONS
local MAX_REQ_HEADERS = 100
local ngx = ngx
local var = ngx.var
local req_get_headers = ngx.req.get_headers
local kong = kong
local type = type
local pcall = pcall
local ipairs = ipairs
local pairs = pairs
local fmt = string.format
local load_certificate = cert_utils.load_certificate
local assert = assert
local get_balancer = balancers.get_balancer
local find = string.find
local spawn = ngx.thread.spawn
local kill = ngx.thread.kill
local exiting = ngx.worker.exiting
local sleep = ngx.sleep
local tonumber = tonumber
local update_time = ngx.update_time
local now = ngx.now
local log = ngx.log
local clear_header = ngx.req.clear_header
local concat = table.concat
local get_method = ngx.req.get_method

local function is_timeout(err)
	return type(err) == "string" and find(err, "timeout", 1, true)
end

local function response_status(res)
	if type(res) ~= "string" then
		return nil, "non-string response"
	end

	local status = tonumber(res:sub(10, 12)) or tonumber(res:sub(8, 10))

	if not status then
		return nil, "failed parsing HTTP response status"
	end

	return status
end

local function get_updated_now_ms()
	update_time()

	return now() * 1000
end

local function get_peer(ctx, opts, upstream_scheme)
	local trace = tracing.trace("balancer")
	ctx.KONG_PHASE = PHASES.balancer
	local now_ms = get_updated_now_ms()

	if not ctx.KONG_BALANCER_START then
		ctx.KONG_BALANCER_START = now_ms
	end

	local balancer_data = ctx.balancer_data
	local tries = balancer_data.tries
	local current_try = {}
	balancer_data.try_count = balancer_data.try_count + 1
	tries[balancer_data.try_count] = current_try
	current_try.balancer_start = now_ms
	current_try.balancer_start_ns = time_ns()

	if balancer_data.try_count > 1 then
		local previous_try = tries[balancer_data.try_count - 1]
		local balancer_instance = balancer_data.balancer

		if balancer_instance then
			if previous_try.state == "failed" then
				if previous_try.code == 504 then
					balancer_instance.report_timeout(balancer_data.balancer_handle)
				else
					balancer_instance.report_tcp_failure(balancer_data.balancer_handle)
				end
			else
				balancer_instance.report_http_status(balancer_data.balancer_handle, previous_try.code)
			end
		end

		local ok, err, errcode = balancer.execute(balancer_data, ctx, true)

		if not ok then
			log(ngx.ERR, "failed to retry the dns/balancer resolver for ", tostring(balancer_data.host), "' with: ", tostring(err))

			ctx.KONG_BALANCER_ENDED_AT = get_updated_now_ms()
			ctx.KONG_BALANCER_TIME = ctx.KONG_BALANCER_ENDED_AT - ctx.KONG_BALANCER_START
			ctx.KONG_PROXY_LATENCY = ctx.KONG_BALANCER_ENDED_AT - ctx.KONG_PROCESSING_START

			return ngx.exit(errcode)
		end
	end

	if not balancer_data.preserve_host then
		local new_upstream_host = balancer_data.hostname
		local port = balancer_data.port

		if port ~= 80 and port ~= 443 or port == 80 and upstream_scheme ~= "ws" or port == 443 and upstream_scheme ~= "wss" then
			new_upstream_host = new_upstream_host .. ":" .. port
		end

		if new_upstream_host ~= opts.host then
			opts.host = new_upstream_host
		end
	end

	if upstream_scheme == "wss" then
		local server_name = opts.host
		local pos = server_name:find(":")

		if pos then
			server_name = server_name:sub(1, pos - 1)
		end

		opts.server_name = server_name
	end

	current_try.ip = balancer_data.ip
	current_try.port = balancer_data.port

	log(ngx.DEBUG, "setting address (try ", balancer_data.try_count, "): ", balancer_data.ip, ":", balancer_data.port)

	ctx.KONG_BALANCER_ENDED_AT = get_updated_now_ms()
	ctx.KONG_BALANCER_TIME = ctx.KONG_BALANCER_ENDED_AT - ctx.KONG_BALANCER_START
	local try_latency = ctx.KONG_BALANCER_ENDED_AT - current_try.balancer_start
	current_try.balancer_latency = try_latency
	current_try.balancer_latency_ns = time_ns() - current_try.balancer_start_ns
	ctx.KONG_PROXY_LATENCY = ctx.KONG_BALANCER_ENDED_AT - ctx.KONG_PROCESSING_START

	trace:finish()

	return current_try
end

local set_response_headers = nil

if ngx.config.subsystem == "http" then
	local add_header = require("ngx.resp").add_header
	local skipped_headers = {
		["proxy-authenticate"] = true,
		["keep-alive"] = true,
		["content-length"] = true,
		connection = true,
		upgrade = true,
		["transfer-encoding"] = true,
		trailers = true,
		te = true,
		["proxy-authorization"] = true
	}
	local ext_header = WS_EXTENSIONS:lower()

	function set_response_headers(ctx, res)
		local seen_status_line = false

		for line in res:gmatch("([^\r\n]+)") do
			if seen_status_line then
				local name, value = line:match("^([^:]+):%s*(.+)")
				local norm_name = name:lower()

				if name and value then
					if not skipped_headers[norm_name] then
						add_header(name, value)
					end

					if norm_name == ext_header then
						local ext = ctx.KONG_WEBSOCKET_EXTENSIONS_ACCEPTED

						if ext then
							value = {
								ext,
								value
							}
						end

						ctx.KONG_WEBSOCKET_EXTENSIONS_ACCEPTED = value
					end
				else
					kong.log.warn("invalid header line in WS handshake response: ", "'", line, "'")
				end
			else
				seen_status_line = true
			end
		end
	end
end

local prepare_req_headers = nil
local sec_ws_key = WEBSOCKET.HEADERS.KEY:lower()
local sec_ws_ext = WEBSOCKET.HEADERS.EXTENSIONS:lower()
local sec_ws_ver = WEBSOCKET.HEADERS.VERSION:lower()
local managed = {
	host = true,
	["x-real-ip"] = true,
	["x-forwarded-proto"] = true,
	connection = true,
	["x-forwarded-port"] = true,
	["x-forwarded-path"] = true,
	["x-forwarded-host"] = true,
	["x-forwarded-for"] = true,
	origin = true,
	["x-forwarded-prefix"] = true,
	upgrade = true,
	[sec_ws_ext] = true,
	[sec_ws_key] = true,
	[sec_ws_ver] = true
}
local forwarded = {
	{
		"X-Forwarded-For",
		"upstream_x_forwarded_for"
	},
	{
		"X-Forwarded-Host",
		"upstream_x_forwarded_host"
	},
	{
		"X-Forwarded-Path",
		"upstream_x_forwarded_path"
	},
	{
		"X-Forwarded-Port",
		"upstream_x_forwarded_port"
	},
	{
		"X-Forwarded-Prefix",
		"upstream_x_forwarded_prefix"
	},
	{
		"X-Forwarded-Proto",
		"upstream_x_forwarded_proto"
	},
	{
		"X-Real-IP",
		"upstream_x_forwarded_for"
	}
}

function prepare_req_headers()
	local req_headers, err = req_get_headers(MAX_REQ_HEADERS, true)

	if err == "truncated" then
		kong.log.warn("client sent more than ", MAX_REQ_HEADERS, " headers. ", "Not all headers will be forwarded upstream")
	end

	local headers = new_tab(nkeys(req_headers), 0)
	local n = 0

	for name, value in pairs(req_headers) do
		if not managed[name:lower()] then
			if type(value) == "table" then
				for _, item in ipairs(value) do
					n = n + 1
					headers[n] = name .. ": " .. item
				end
			else
				n = n + 1
				headers[n] = name .. ": " .. value
			end
		end
	end

	for _, xf in ipairs(forwarded) do
		local name = xf[1]
		local src = xf[2]
		local value = var[src]

		if value then
			n = n + 1
			headers[n] = name .. ": " .. value
		end
	end

	return headers
end

local function janitor(proxy, ctx)
	local t = ctx.KONG_WEBSOCKET_JANITOR_TIMEOUT or JANITOR_TIMEOUT

	while not exiting() do
		sleep(t)
	end

	ngx.log(ngx.INFO, "NGINX is exiting, closing proxy...")

	local status = STATUS.GOING_AWAY

	proxy:close(status.CODE, status.REASON, status.CODE, status.REASON)

	return true
end

local function has_proxy_plugins(ctx)
	local plugins_iterator = runloop.get_plugins_iterator()
	local iterator = plugins_iterator:get_collected_iterator("ws_client_frame", ctx)
	iterator = iterator or plugins_iterator:get_collected_iterator("ws_upstream_frame", ctx)

	return iterator ~= nil
end

local on_frame = nil
local set_named_ctx = kong_global.set_named_ctx
local set_namespaced_log = kong_global.set_namespaced_log
local reset_log = kong_global.reset_log
local get_state = pdk.get_state
local co_running = coroutine.running

local function send_close(proxy, initiator, state)
	local client_status, upstream_status, client_reason, upstream_reason = nil

	if initiator == "client" then
		client_status = state.status
		client_reason = state.data
		upstream_status = state.peer_status
		upstream_reason = state.peer_data
	else
		upstream_status = state.status
		upstream_reason = state.data
		client_status = state.peer_status
		client_reason = state.peer_data
	end

	proxy:close(client_status, client_reason, upstream_status, upstream_reason)
end

function on_frame(proxy, sender, typ, data, fin, code)
	local ctx = ngx.ctx
	local state = get_state(ctx, sender)

	assert(fin, "unexpected continuation frame/fragment")

	state.type = typ
	state.data = data
	state.status = code
	state.drop = nil
	state.peer_status = nil
	state.peer_data = nil

	if state.closing then
		return
	end

	if not state.thread then
		state.thread = co_running()
	end

	local phase = sender == "client" and "ws_client_frame" or "ws_upstream_frame"
	local plugins_iterator = runloop.get_plugins_iterator()
	local iterator, plugins = plugins_iterator:get_collected_iterator(phase, ctx)

	if iterator then
		for _, plugin, conf in iterator, plugins, 0 do
			local handler = plugin.handler
			local fn = handler[phase]

			set_named_ctx(kong, "plugin", handler, ctx)
			set_namespaced_log(kong, phase, ctx)

			local ok, err = pcall(fn, handler, conf, state.type, state.data, state.status)

			reset_log(kong, ctx)

			if not ok then
				kong.log.err("plugin handler (", plugin.name, ") threw an error: ", err)

				state.status = STATUS.SERVER_ERROR.CODE
				state.peer_status = STATUS.SERVER_ERROR.CODE
				state.data = STATUS.SERVER_ERROR.REASON
				state.peer_data = STATUS.SERVER_ERROR.REASON
				state.closing = true
				state.drop = true
			end

			if state.closing or state.drop then
				break
			end
		end
	end

	if state.closing then
		send_close(proxy, sender, state)

		return
	end

	if state.drop then
		return
	end

	if state.type == "close" then
		state.closing = true
	end

	return state.data, state.status
end

local function set_client_cert(ctx, opts)
	local balancer_data = ctx.balancer_data
	local client_cert = ctx.service.client_certificate

	if not client_cert then
		local _, upstream = get_balancer(balancer_data)
		client_cert = upstream and upstream.client_certificate
	end

	if client_cert then
		local cert, key, err = load_certificate(client_cert.id)

		if not cert then
			kong.log.err("failed loading certificate for service: ", err)

			return kong.response.error(500)
		end

		opts.client_cert = cert
		opts.client_priv_key = key
	end
end

local function handshake_error(reason)
	local err = "Cannot complete WebSocket handshake: " .. reason

	return kong.response.exit(400, err)
end

return {
	handlers = {
		ws_handshake = {
			before = NOOP,
			after = function (ctx)
				local headers, err = req_get_headers(MAX_REQ_HEADERS)

				if err == "truncated" then
					kong.log.warn("Client sent more than ", MAX_REQ_HEADERS, " headers. ", "WebSocket handshake validation may fail")
				elseif not headers then
					kong.log.err("Failed reading client request headers: ", err)

					return kong.response.exit(500)
				end

				if get_method() ~= "GET" then
					return handshake_error("invalid request method")
				end

				local connection = headers.connection

				if not connection or type(connection) ~= "string" or not connection:lower():find("upgrade", nil, true) then
					return handshake_error("invalid/missing 'Connection' header")
				end

				local upgrade = headers.upgrade

				if not upgrade or type(upgrade) ~= "string" or not upgrade:lower():find("websocket", nil, true) then
					return handshake_error("invalid/missing 'Upgrade' header")
				end

				local ws_key = headers["sec-websocket-key"]

				if not ws_key or type(ws_key) ~= "string" then
					return handshake_error("invalid/missing 'Sec-WebSocket-Key' header")
				end

				local ws_version = headers["sec-websocket-version"]

				if not ws_version or type(ws_version) ~= "string" or ws_version ~= "13" then
					return handshake_error("invalid/missing 'Sec-WebSocket-Version' header")
				end

				local extensions = headers["sec-websocket-extensions"]

				if extensions then
					ctx.KONG_WEBSOCKET_EXTENSIONS_REQUESTED = extensions

					if type(extensions) == "table" then
						extensions = concat(extensions, ", ")
					end

					kong.log.debug("WebSocket client requested unsupported extensions ", "(", extensions, "). ", "Clearing the ", WS_EXTENSIONS, " request header")
					clear_header(WS_EXTENSIONS)
				end

				runloop.access.after(ctx)
			end
		},
		ws_proxy = {
			before = function (ctx)
				local service = ctx.service
				local tries = (service.retries or 0) + 1
				local frame_handler = nil

				if has_proxy_plugins(ctx) then
					frame_handler = on_frame
				else
					kong.log.debug("service ", service.id, " has no WS plugins active")
				end

				local proxy, err = ws_proxy.new({
					aggregate_fragments = true,
					debug = ctx.KONG_WEBSOCKET_DEBUG,
					recv_timeout = ctx.KONG_WEBSOCKET_RECV_TIMEOUT or RECV_TIMEOUT,
					send_timeout = ctx.KONG_WEBSOCKET_SEND_TIMEOUT or SEND_TIMEOUT,
					connect_timeout = ctx.KONG_WEBSOCKET_CONNECT_TIMEOUT or service.connect_timeout,
					on_frame = frame_handler,
					lingering_time = ctx.KONG_WEBSOCKET_LINGERING_TIME,
					lingering_timeout = ctx.KONG_WEBSOCKET_LINGERING_TIMEOUT,
					client_max_frame_size = ctx.KONG_WEBSOCKET_CLIENT_MAX_PAYLOAD_SIZE or CLIENT_MAX_DEFAULT,
					upstream_max_frame_size = ctx.KONG_WEBSOCKET_UPSTREAM_MAX_PAYLOAD_SIZE or UPSTREAM_MAX_DEFAULT
				})

				if not proxy then
					kong.log.err("couldn't create proxy instance: ", err)

					return kong.response.error(500)
				end

				local opts = {
					ssl_verify = service.tls_verify,
					headers = prepare_req_headers(),
					origin = var.http_origin,
					host = var.upstream_host
				}

				set_client_cert(ctx, opts)

				local connected = false
				local response = nil
				local upstream_scheme = var.upstream_scheme
				local uri_template = fmt("%s://%%s:%%s%s", upstream_scheme, var.upstream_uri)
				local ok, status = nil

				for _ = 1, tries do
					local try = get_peer(ctx, opts, upstream_scheme)
					local uri = fmt(uri_template, try.ip, try.port)
					ok, err, response = proxy:connect_upstream(uri, opts)

					if ok then
						connected = true

						break
					elseif response then
						status, err = response_status(response)

						if status then
							set_response_headers(ctx, response)
						else
							status = 500

							kong.log.err("failed parsing response: ", err)
						end

						try.state = "next"
						try.code = status
						ngx.status = status

						return ngx.exit(0)
					else
						if is_timeout(err) then
							status = 504
						else
							status = 502
						end

						try.state = "failed"
						try.code = status

						kong.log.err("failed connecting to ", uri, ": ", err)
					end
				end

				if not connected then
					kong.log.err("exhausted retries trying to proxy WS")

					return ngx.exit(status or 502)
				end

				set_response_headers(ctx, response)

				if ctx.KONG_WEBSOCKET_EXTENSIONS_ACCEPTED then
					proxy:close_upstream(STATUS.PROTOCOL_ERROR.CODE, STATUS.PROTOCOL_ERROR.REASON)

					local ext = ctx.KONG_WEBSOCKET_EXTENSIONS_ACCEPTED

					if type(ext) == "table" then
						ext = concat(ext, ", ")
					end

					ext = tostring(ext)
					ctx.KONG_PHASE = PHASES.ws_handshake

					return kong.response.exit(501, "WebSocket upstream sent unsupported " .. WS_EXTENSIONS .. " (" .. ext .. ")")
				end

				ok, err = proxy:connect_client()

				if not ok then
					kong.log.err("failed handshaking client: ", err)

					return ngx.exit(500)
				end

				ctx.KONG_PHASE = PHASES.ws_proxy

				if frame_handler then
					pdk.init_state(ctx)
				end

				local janitor_thread = nil
				janitor_thread, err = spawn(janitor, proxy, ctx)

				if not janitor_thread then
					kong.log.err("failed to spawn janitor thread for proxy: ", err)
				end

				ok, err = proxy:execute()

				if not ok then
					kong.log.err("proxy execution terminated abnormally: ", err)
				end

				kill(janitor_thread)
			end,
			after = NOOP
		},
		ws_close = {
			before = runloop.log.before,
			after = runloop.log.after
		}
	}
}
