local private = require("kong.enterprise_edition.pdk.private.websocket")
local phase_checker = require("kong.pdk.private.phases")
local const = require("kong.enterprise_edition.constants")
local get_state = private.get_state
local check_phase = phase_checker.check
local type = type
local ngx = ngx
local co_running = coroutine.running
local MAX_PAYLOAD_SIZE = const.WEBSOCKET.MAX_PAYLOAD_SIZE
local ws_proxy = phase_checker.new(phase_checker.phases.ws_proxy)
local ws_handshake = phase_checker.new(phase_checker.phases.ws_handshake)

local function ws_proxy_method(role, fn)
	local ns = "kong.websocket." .. role

	return function (...)
		check_phase(ws_proxy)

		local ctx = ngx.ctx
		local state = get_state(ctx, role)

		if state.thread ~= co_running() then
			error("calling " .. ns .. " method from the wrong thread", 2)
		end

		return fn(state, ...)
	end
end

local function ws_handshake_method(role, fn)
	return function (...)
		check_phase(ws_handshake)

		return fn(ngx.ctx, role, ...)
	end
end

local function set_max_payload_size(ctx, role, size)
	if type(size) ~= "number" then
		error("`size` must be a number", 2)
	elseif MAX_PAYLOAD_SIZE < size then
		error("`size` must be <= " .. tostring(MAX_PAYLOAD_SIZE), 2)
	elseif size < 0 then
		error("`size` must be >= 0", 2)
	end

	local key = role == "client" and "KONG_WEBSOCKET_CLIENT_MAX_PAYLOAD_SIZE" or "KONG_WEBSOCKET_UPSTREAM_MAX_PAYLOAD_SIZE"

	if size == 0 then
		size = nil
	end

	ctx[key] = size
end

local function get_frame(state)
	return state.data, state.type, state.status
end

local function set_frame_data(state, data)
	if type(data) ~= "string" then
		error("frame payload must be a string", 2)
	end

	state.data = data
end

local function set_status(state, code)
	if type(code) ~= "number" then
		error("status code must be an integer", 2)
	end

	if state.type ~= "close" then
		error("cannot override status code of non-close frame", 2)
	end

	state.status = code
end

local function drop_frame(state)
	if state.type == "close" then
		error("cannot drop a close frame", 2)
	end

	state.drop = true
end

local function close(state, status, message, peer_status, peer_message)
	local role = state.role
	local peer = nil

	if role == "client" then
		peer = "upstream"
	else
		peer = "client"
	end

	if status ~= nil then
		if type(status) ~= "number" then
			error(role .. " status must be nil or a number", 2)
		end

		state.status = status
	end

	if message ~= nil then
		if type(message) ~= "string" then
			error(role .. " message must be nil or a string", 2)
		end

		state.data = message
	end

	if peer_status ~= nil then
		if type(peer_status) ~= "number" then
			error(peer .. " status must be nil or a number", 2)
		end

		state.peer_status = peer_status
	end

	if peer_message ~= nil then
		if type(peer_message) ~= "string" then
			error(peer .. " message must be nil or a string", 2)
		end

		state.peer_data = peer_message
	end

	state.drop = true
	state.closing = true
end

local function new()
	local pdk = {
		client = {
			get_frame = ws_proxy_method("client", get_frame),
			set_frame_data = ws_proxy_method("client", set_frame_data),
			set_status = ws_proxy_method("client", set_status),
			drop_frame = ws_proxy_method("client", drop_frame),
			close = ws_proxy_method("client", close),
			set_max_payload_size = ws_handshake_method("client", set_max_payload_size)
		},
		upstream = {
			get_frame = ws_proxy_method("upstream", get_frame),
			set_frame_data = ws_proxy_method("upstream", set_frame_data),
			set_status = ws_proxy_method("upstream", set_status),
			drop_frame = ws_proxy_method("upstream", drop_frame),
			close = ws_proxy_method("upstream", close),
			set_max_payload_size = ws_handshake_method("upstream", set_max_payload_size)
		}
	}

	return pdk
end

return {
	new = new
}
