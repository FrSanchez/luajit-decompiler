local utils = require("kong.tools.utils")
local multipart = require("multipart")
local cjson = require("cjson.safe").new()
local pl_template = require("pl.template")
local sandbox = require("kong.tools.sandbox")
local json_navigator = require("kong.enterprise_edition.transformations.plugins.json_navigator")
local sub = string.sub
local gsub = string.gsub
local table_insert = table.insert
local get_uri_args = kong.request.get_query
local set_uri_args = kong.service.request.set_query
local clear_header = kong.service.request.clear_header
local get_header = kong.request.get_header
local set_header = kong.service.request.set_header
local get_headers = kong.request.get_headers
local set_headers = kong.service.request.set_headers
local set_method = kong.service.request.set_method
local get_raw_body = kong.request.get_raw_body
local set_raw_body = kong.service.request.set_raw_body
local set_path = kong.service.request.set_path
local encode_args = ngx.encode_args
local ngx_decode_args = ngx.decode_args
local type = type
local str_find = string.find
local pcall = pcall
local pairs = pairs
local error = error
local tostring = tostring
local rawset = rawset
local lua_enabled = sandbox.configuration.enabled
local sandbox_enabled = sandbox.configuration.sandbox_enabled
local navigate_and_apply = json_navigator.navigate_and_apply
local _M = {}
local template_cache = setmetatable({}, {
	__mode = "k"
})
local DEBUG = ngx.DEBUG
local CONTENT_LENGTH = "content-length"
local CONTENT_TYPE = "content-type"
local HOST = "host"
local JSON = "json"
local MULTI = "multi_part"
local ENCODED = "form_encoded"
local EMPTY = require("pl.tablex").readonly({})

cjson.decode_array_with_array_mt(true)

local function parse_json(body)
	if body then
		return cjson.decode(body)
	end
end

local function decode_args(body)
	if body then
		return ngx_decode_args(body)
	end

	return {}
end

local function get_content_type(content_type)
	if content_type == nil then
		return
	end

	if str_find(content_type:lower(), "application/json", nil, true) then
		return JSON
	elseif str_find(content_type:lower(), "multipart/form-data", nil, true) then
		return MULTI
	elseif str_find(content_type:lower(), "application/x-www-form-urlencoded", nil, true) then
		return ENCODED
	end
end

local function param_value(source_template, config_array, template_env)
	if not source_template or source_template == "" then
		return nil
	end

	if not lua_enabled then
		local expr = str_find(source_template, "%$%(.*%)")

		if expr then
			return nil, "loading of untrusted Lua code disabled because " .. "'untrusted_lua' config option is set to 'off'"
		end

		return source_template
	end

	local compiled_templates = template_cache[config_array]

	if not compiled_templates then
		compiled_templates = {}
		template_cache[config_array] = compiled_templates
	end

	local compiled_template = compiled_templates[source_template]

	if not compiled_template then
		compiled_template = pl_template.compile(source_template)
		compiled_templates[source_template] = compiled_template
	end

	return compiled_template:render(template_env)
end

local function iter(config_array, template_env)
	return function (config_array, i, previous_name, previous_value)
		i = i + 1
		local current_pair = config_array[i]

		if current_pair == nil then
			return nil
		end

		local current_name, current_value = current_pair:match("^([^:]+):*(.-)$")

		if current_value == "" then
			return i, current_name
		end

		local status, res, err = pcall(param_value, current_value, config_array, template_env)

		if not status then
			return error("[request-transformer-advanced] failed to render the template " .. tostring(current_value) .. ", error: the renderer " .. "encountered a value that was not coercable to a " .. "string (usually a table)")
		end

		if err then
			return error("[request-transformer-advanced] failed to render the template " .. tostring(current_value) .. ", error:" .. tostring(err))
		end

		kong.log.debug("[request-transformer-advanced] template `", current_value, "` rendered to `", res, "`")

		return i, current_name, res
	end, config_array, 0
end

local function append_value(current_value, value)
	local current_value_type = type(current_value)

	if current_value_type == "string" then
		return {
			current_value,
			value
		}
	elseif current_value_type == "table" then
		table_insert(current_value, value)

		return current_value
	else
		return {
			value
		}
	end
end

local function transform_headers(conf, template_env)
	local headers = get_headers()
	local headers_to_remove = {}
	headers.host = nil

	for _, name, value in iter(conf.remove.headers, template_env) do
		name = name:lower()

		if headers[name] then
			headers[name] = nil
			headers_to_remove[name] = true
		end
	end

	for _, old_name, new_name in iter(conf.rename.headers, template_env) do
		old_name = old_name:lower()
		local value = headers[old_name]

		if value then
			headers[new_name:lower()] = value
			headers[old_name] = nil
			headers_to_remove[old_name] = true
		end
	end

	for _, name, value in iter(conf.replace.headers, template_env) do
		name = name:lower()

		if headers[name] or name == HOST then
			headers[name] = value
		end
	end

	for _, name, value in iter(conf.add.headers, template_env) do
		if not headers[name] and name:lower() ~= HOST then
			headers[name] = value
		end
	end

	for _, name, value in iter(conf.append.headers, template_env) do
		local name_lc = name:lower()

		if name_lc ~= HOST and name ~= name_lc and headers[name] ~= nil then
			headers[name] = headers[name]
			headers[name_lc] = nil
		end

		headers[name] = append_value(headers[name], value)
	end

	for name, _ in pairs(headers_to_remove) do
		clear_header(name)
	end

	set_headers(headers)
end

local function transform_querystrings(conf, template_env)
	if #conf.remove.querystring <= 0 and #conf.rename.querystring <= 0 and #conf.replace.querystring <= 0 and #conf.add.querystring <= 0 and #conf.append.querystring <= 0 then
		return
	end

	local querystring = utils.cycle_aware_deep_copy(template_env.query_params)

	for _, name, value in iter(conf.remove.querystring, template_env) do
		querystring[name] = nil
	end

	for _, old_name, new_name in iter(conf.rename.querystring, template_env) do
		local value = querystring[old_name]
		querystring[new_name] = value
		querystring[old_name] = nil
	end

	for _, name, value in iter(conf.replace.querystring, template_env) do
		if querystring[name] then
			querystring[name] = value
		end
	end

	for _, name, value in iter(conf.add.querystring, template_env) do
		if not querystring[name] then
			querystring[name] = value
		end
	end

	for _, name, value in iter(conf.append.querystring, template_env) do
		querystring[name] = append_value(querystring[name], value)
	end

	set_uri_args(querystring)
end

local function toboolean(value)
	if value == "true" then
		return true
	else
		return false
	end
end

local function cast_value(value, value_type)
	if value_type == "number" then
		return tonumber(value)
	elseif value_type == "boolean" then
		return toboolean(value)
	else
		return value
	end
end

local function init_json_path(json, paths)
	if type(json) == "table" then
		for _, path in ipairs(paths or EMPTY) do
			if json[path] == nil then
				json[path] = {}
			end

			json = json[path]
		end
	end

	return json
end

local function transform_json_body(conf, body, content_length, template_env)
	local opts = {
		dots_in_keys = conf.dots_in_keys
	}
	local removed = false
	local renamed = false
	local replaced = false
	local added = false
	local appended = false
	local filtered = false
	local json_body = parse_json(body)

	if json_body == nil and content_length > 0 then
		return false, nil
	end

	if content_length > 0 and #conf.remove.body > 0 then
		for _, name, value in iter(conf.remove.body, template_env) do
			navigate_and_apply(json_body, name, function (o, p)
				o[p] = nil
			end, opts)

			removed = true
		end
	end

	if content_length > 0 and #conf.rename.body > 0 then
		for _, old_name, new_name in iter(conf.rename.body, template_env) do
			local v_array = {}

			navigate_and_apply(json_body, old_name, function (o, p)
				local v = o[p]

				table.insert(v_array, v)

				o[p] = nil
			end, opts)
			navigate_and_apply(json_body, new_name, function (o, p, ctx)
				local idx = 1

				if #v_array > 1 then
					idx = ctx.index or 1
				end

				o[p] = v_array[idx]
			end, opts)

			renamed = true
		end
	end

	if content_length > 0 and #conf.replace.body > 0 then
		for i, name, value in iter(conf.replace.body, template_env) do
			value = cjson.encode(value)

			if value and sub(value, 1, 1) == "\"" and sub(value, -1, -1) == "\"" then
				value = gsub(sub(value, 2, -2), "\\\"", "\"")
			end

			value = value and gsub(value, "\\/", "/")

			if conf.replace.json_types then
				local v_type = conf.replace.json_types[i]
				value = cast_value(value, v_type)
			end

			if value ~= nil then
				navigate_and_apply(json_body, name, function (o, p)
					if o[p] then
						o[p] = value
					end
				end, opts)

				replaced = true
			end
		end
	end

	json_body = json_body or {}

	if #conf.add.body > 0 then
		for i, name, value in iter(conf.add.body, template_env) do
			value = cjson.encode(value)

			if value and sub(value, 1, 1) == "\"" and sub(value, -1, -1) == "\"" then
				value = gsub(sub(value, 2, -2), "\\\"", "\"")
			end

			value = value and gsub(value, "\\/", "/")

			if conf.add.json_types then
				local v_type = conf.add.json_types[i]
				value = cast_value(value, v_type)
			end

			if value ~= nil then
				local opts = {
					create_inexistent_parent = true,
					dots_in_keys = conf.dots_in_keys
				}

				navigate_and_apply(json_body, name, function (o, p)
					if not o[p] then
						o[p] = value
					end
				end, opts)

				added = true
			end
		end
	end

	if #conf.append.body > 0 then
		for i, name, value in iter(conf.append.body, template_env) do
			value = cjson.encode(value)

			if value and sub(value, 1, 1) == "\"" and sub(value, -1, -1) == "\"" then
				value = gsub(sub(value, 2, -2), "\\\"", "\"")
			end

			value = value and gsub(value, "\\/", "/")

			if conf.append.json_types then
				local v_type = conf.append.json_types[i]
				value = cast_value(value, v_type)
			end

			if value ~= nil then
				navigate_and_apply(json_body, name, function (o, p)
					o[p] = append_value(o[p], value)
				end, opts)

				appended = true
			end
		end
	end

	if conf.allow.body and #conf.allow.body then
		local allowed_parameter = {}

		for _, name in iter(conf.allow.body, template_env) do
			navigate_and_apply(json_body, name, function (o, p, ctx)
				local parent = init_json_path(allowed_parameter, ctx.paths)
				parent[p] = o[p]
				filtered = true
			end, opts)
		end

		if filtered then
			json_body = allowed_parameter
		end
	end

	if removed or renamed or replaced or added or appended or filtered then
		return true, assert(cjson.encode(json_body))
	end
end

local function transform_url_encoded_body(conf, body, content_length, template_env)
	local renamed = false
	local removed = false
	local replaced = false
	local added = false
	local appended = false
	local filtered = false
	local parameters = decode_args(body)

	if content_length > 0 and #conf.remove.body > 0 then
		for _, name, value in iter(conf.remove.body, template_env) do
			parameters[name] = nil
			removed = true
		end
	end

	if content_length > 0 and #conf.rename.body > 0 then
		for _, old_name, new_name in iter(conf.rename.body, template_env) do
			local value = parameters[old_name]
			parameters[new_name] = value
			parameters[old_name] = nil
			renamed = true
		end
	end

	if content_length > 0 and #conf.replace.body > 0 then
		for _, name, value in iter(conf.replace.body, template_env) do
			if parameters[name] then
				parameters[name] = value
				replaced = true
			end
		end
	end

	if #conf.add.body > 0 then
		for _, name, value in iter(conf.add.body, template_env) do
			if parameters[name] == nil then
				parameters[name] = value
				added = true
			end
		end
	end

	if #conf.append.body > 0 then
		for _, name, value in iter(conf.append.body, template_env) do
			local old_value = parameters[name]
			parameters[name] = append_value(old_value, value)
			appended = true
		end
	end

	if conf.allow.body and #conf.allow.body then
		local allowed_parameter = {}

		for _, name in iter(conf.allow.body, template_env) do
			allowed_parameter[name] = parameters[name]
			filtered = true
		end

		if filtered then
			parameters = allowed_parameter
		end
	end

	if removed or renamed or replaced or added or appended or filtered then
		return true, encode_args(parameters)
	end
end

local function transform_multipart_body(conf, body, content_length, content_type_value, template_env)
	local removed = false
	local renamed = false
	local replaced = false
	local added = false
	local appended = false
	local filtered = false
	local parameters = multipart(body and body or "", content_type_value)

	if content_length > 0 and #conf.rename.body > 0 then
		for _, old_name, new_name in iter(conf.rename.body, template_env) do
			if parameters:get(old_name) then
				local value = parameters:get(old_name).value

				parameters:set_simple(new_name, value)
				parameters:delete(old_name)

				renamed = true
			end
		end
	end

	if content_length > 0 and #conf.remove.body > 0 then
		for _, name, value in iter(conf.remove.body, template_env) do
			parameters:delete(name)

			removed = true
		end
	end

	if content_length > 0 and #conf.replace.body > 0 then
		for _, name, value in iter(conf.replace.body, template_env) do
			if parameters:get(name) then
				parameters:delete(name)
				parameters:set_simple(name, value)

				replaced = true
			end
		end
	end

	if #conf.add.body > 0 then
		for _, name, value in iter(conf.add.body, template_env) do
			if not parameters:get(name) then
				parameters:set_simple(name, value)

				added = true
			end
		end
	end

	if conf.allow.body and #conf.allow.body > 0 then
		local allowed_parameter = multipart("", content_type_value)

		for _, name in iter(conf.allow.body, template_env) do
			allowed_parameter:set_simple(name, parameters:get(name))

			filtered = true
		end

		if filtered then
			parameters = allowed_parameter
		end
	end

	if removed or renamed or replaced or added or appended or filtered then
		return true, parameters:tostring()
	end
end

local function transform_body(conf, template_env)
	local content_type_value = get_header(CONTENT_TYPE)
	local content_type = get_content_type(content_type_value)

	if content_type == nil or #conf.rename.body < 1 and #conf.remove.body < 1 and #conf.replace.body < 1 and #conf.add.body < 1 and #conf.append.body < 1 and (conf.allow.body == nil or #conf.allow.body < 1) then
		return
	end

	local body, err = get_raw_body()

	if err then
		kong.log.warn(err)
	end

	local is_body_transformed = false
	local content_length = body and #body or 0

	if content_type == ENCODED then
		is_body_transformed, body = transform_url_encoded_body(conf, body, content_length, template_env)
	elseif content_type == MULTI then
		is_body_transformed, body = transform_multipart_body(conf, body, content_length, content_type_value, template_env)
	elseif content_type == JSON then
		is_body_transformed, body = transform_json_body(conf, body, content_length, template_env)
	end

	if is_body_transformed then
		set_raw_body(body)
		set_header(CONTENT_LENGTH, #body)
	end
end

local function transform_method(conf)
	if conf.http_method then
		set_method(conf.http_method:upper())

		if conf.http_method == "GET" or conf.http_method == "HEAD" or conf.http_method == "TRACE" then
			local content_type_value = get_header(CONTENT_TYPE)
			local content_type = get_content_type(content_type_value)

			if content_type == ENCODED then
				local body = get_raw_body()
				local parameters = decode_args(body)

				if type(parameters) == "table" and next(parameters) then
					local querystring = get_uri_args()

					for name, value in pairs(parameters) do
						if querystring[name] then
							if type(querystring[name]) == "table" then
								append_value(querystring[name], value)
							else
								querystring[name] = {
									querystring[name],
									value
								}
							end
						else
							querystring[name] = value
						end
					end

					set_uri_args(querystring)
				end
			end
		end
	end
end

local function transform_uri(conf, template_env)
	if conf.replace.uri then
		local status, res, err = pcall(param_value, conf.replace.uri, conf.replace, template_env)

		if not status then
			return error("[request-transformer-advanced] failed to render the template " .. tostring(conf.replace.uri) .. ", error: the renderer encountered a value that was not" .. " coercable to a string (usually a table)")
		end

		if err then
			error("[request-transformer-advanced] failed to render the template " .. tostring(conf.replace.uri) .. ", error:" .. err)
		end

		kong.log.debug(DEBUG, "[request-transformer-advanced] template `", conf.replace.uri, "` rendered to `", res, "`")

		if res then
			set_path(res)
		end
	end
end

function _M.execute(conf)
	local __meta_environment = {
		__index = function (self, key)
			local lazy_loaders = {
				headers = function (self)
					return get_headers() or EMPTY
				end,
				query_params = function (self)
					return get_uri_args() or EMPTY
				end,
				uri_captures = function (self)
					return (ngx.ctx.router_matches or EMPTY).uri_captures or EMPTY
				end,
				shared = function (self)
					return ((kong or EMPTY).ctx or EMPTY).shared or EMPTY
				end
			}
			local loader = lazy_loaders[key]

			if not loader then
				if lua_enabled and not sandbox_enabled then
					return _G[key]
				end

				return
			end

			local value = loader()

			rawset(self, key, value)

			return value
		end,
		__newindex = function (self)
			error("This environment is read-only.")
		end
	}
	local template_env = {}

	if lua_enabled and sandbox_enabled then
		template_env = utils.cycle_aware_deep_copy(sandbox.configuration.environment)
		template_env.type = type
	end

	setmetatable(template_env, __meta_environment)
	transform_uri(conf, template_env)
	transform_method(conf)
	transform_headers(conf, template_env)
	transform_body(conf, template_env)
	transform_querystrings(conf, template_env)
end

return _M
