local cjson = require("cjson.safe").new()
local lrucache = require("resty.lrucache")
local pl_tablex = require("pl.tablex")
local deserialize = require("resty.openapi3.deserializer")
local validators = require("kong.plugins.request-validator.validators")
local meta = require("kong.meta")
local mime_type = require("kong.tools.mime_type")
local nkeys = require("table.nkeys")
local EMPTY = pl_tablex.readonly({})
local DENY_BODY_MESSAGE = "request body doesn't conform to schema"
local DENY_BODY_MESSAGE_CT = "specified Content-Type is not allowed"
local DENY_PARAM_MESSAGE = "request param doesn't conform to schema"
local kong = kong
local json_decode = cjson.decode
local json_encode = cjson.encode
local ngx_req_read_body = ngx.req.read_body
local ngx_req_get_body_data = ngx.req.get_body_data
local req_get_headers = ngx.req.get_headers
local req_get_uri_args = ngx.req.get_uri_args
local ipairs = ipairs
local setmetatable = setmetatable
local ngx_null = ngx.null
local string_find = string.find
local fmt = string.format
local table_insert = table.insert
local lower = string.lower
local parse_mime_type = mime_type.parse_mime_type

cjson.decode_array_with_array_mt(true)

local content_type_allowed = nil
local conf_cache = setmetatable({}, {
	__mode = "k",
	__index = function (self, plugin_config)
		local conf = {
			lru = assert(lrucache.new(500)),
			parsed_list = {}
		}

		for _, content_type in ipairs(plugin_config.allowed_content_types or EMPTY) do
			local type, sub_type, params = parse_mime_type(content_type)

			table_insert(conf.parsed_list, {
				type = type,
				sub_type = sub_type,
				params = params
			})
		end

		self[plugin_config] = conf

		return conf
	end
})

function content_type_allowed(plugin_config, content_type)
	if not content_type then
		return false
	end

	local conf = conf_cache[plugin_config]
	local allowed = conf.lru:get(content_type)

	if allowed ~= nil then
		return allowed
	end

	allowed = false
	local type, sub_type, params = parse_mime_type(content_type)

	for _, parsed in ipairs(conf.parsed_list) do
		if (type == parsed.type or parsed.type == "*") and (sub_type == parsed.sub_type or parsed.sub_type == "*") then
			local params_match = true

			for key, value1 in pairs(parsed.params or EMPTY) do
				local value2 = (params or EMPTY)[key]

				if key == "charset" then
					value1 = lower(value1)
					value2 = value2 and lower(value2)
				end

				if value1 ~= value2 then
					params_match = false

					break
				end
			end

			local n1 = params and nkeys(params) or 0
			local n2 = parsed.params and nkeys(parsed.params) or 0

			if params_match and n1 == n2 then
				allowed = true

				break
			end
		end
	end

	conf.lru:set(content_type, allowed)

	return allowed
end

local template_environment = nil
local __meta_environment = {
	__index = function (self, key)
		local lazy_loaders = {
			header = function (self)
				return req_get_headers() or EMPTY
			end,
			query = function (self)
				return req_get_uri_args() or EMPTY
			end,
			path = function (self)
				return (ngx.ctx.router_matches or EMPTY).uri_captures or EMPTY
			end
		}
		local loader = lazy_loaders[key]

		if not loader then
			return
		end

		local value = loader()

		rawset(self, key, value)

		return value
	end,
	__new_index = function (self)
		error("This environment is read-only.")
	end
}
template_environment = setmetatable({}, __meta_environment)

local function clear_environment()
	rawset(template_environment, "header", nil)
	rawset(template_environment, "query", nil)
	rawset(template_environment, "path", nil)
end

local validator_cache = setmetatable({}, {
	__mode = "k",
	__index = function (self, plugin_config)
		local generator = require(validators[plugin_config.version]).generate
		local validator_func = assert(generator(plugin_config.body_schema))
		self[plugin_config] = validator_func

		return validator_func
	end
})
local validator_param_cache = setmetatable({}, {
	__mode = "k",
	__index = function (self, parameter)
		local generator = require(validators.draft4).generate
		local validator_func = assert(generator(parameter.schema, {
			coercion = true
		}))
		parameter.decoded_schema = assert(json_decode(parameter.schema))
		self[parameter] = validator_func

		return validator_func
	end
})

local function get_req_body_json()
	ngx_req_read_body()

	local body_data = ngx_req_get_body_data()

	if not body_data or #body_data == 0 then
		return {}
	end

	local body, err = json_decode(body_data)

	if err then
		return nil, "request body is not valid JSON"
	end

	return body
end

local function validate_required(location, parameter)
	if location == "query" and parameter.style == "deepObject" then
		return true
	end

	local value = template_environment[location][parameter.name]

	if parameter.required and value == nil then
		return false, "required parameter missing"
	end

	parameter.value = value

	return true
end

local validate_data = nil

local function validate_style_deepobject(location, parameter)
	local validator = validator_param_cache[parameter]
	local result, err = deserialize(parameter.style, parameter.decoded_schema.type, parameter.explode, parameter.name, template_environment[location], location)

	if err == "not found" and not parameter.required then
		return true
	end

	if err or not result then
		return false, err
	end

	return validator(result)
end

local tables_allowed = {
	object = true,
	array = true
}

function validate_data(location, parameter)
	if location == "query" and parameter.style == "deepObject" then
		return validate_style_deepobject(location, parameter)
	end

	if not parameter.value or parameter.style == ngx_null then
		return true
	end

	local validator = validator_param_cache[parameter]

	if type(parameter.value) ~= "table" or tables_allowed[parameter.decoded_schema.type] then
		local result, err = deserialize(parameter.style, parameter.decoded_schema.type, parameter.explode, parameter.value, nil, parameter["in"])

		if err or not result then
			return false, err
		end

		local ok, err = validator(result)

		return ok, err, result
	end

	for _, value in ipairs(parameter.value) do
		local result, err = deserialize(parameter.style, parameter.decoded_schema.type, parameter.explode, value, nil, parameter["in"])

		if err or not result then
			return false, err
		end

		local ok, err = validator(result)

		if not ok then
			return ok, err, result
		end
	end

	return true, nil, parameter.value
end

local function validate_parameters(location, parameter)
	local ok, err, data = validate_required(location, parameter)

	if not ok then
		return false, err, data
	end

	ok, err, data = validate_data(location, parameter)

	if not ok then
		return false, err, data
	end

	return true
end

local RequestValidator = {
	PRIORITY = 999,
	VERSION = meta.core_version
}

local function error_handler(msg, data)
	local msg_table = {
		message = msg,
		data = data
	}
	kong.ctx.plugin.failure_message = msg_table

	return kong.response.exit(400, msg_table)
end

function RequestValidator:access(conf)
	clear_environment()

	for _, parameter in ipairs(conf.parameter_schema or EMPTY) do
		local ok, err, data = validate_parameters(parameter["in"], parameter)

		if not ok then
			if err and conf.verbose_response then
				local message = fmt("%s '%s' validation failed, [error] %s", parameter["in"], parameter.name, err)

				return error_handler(message, data)
			else
				return error_handler(DENY_PARAM_MESSAGE)
			end
		end
	end

	if conf.body_schema then
		local content_type = kong.request.get_header("content-type")

		if not content_type_allowed(conf, content_type) then
			if conf.verbose_response then
				return error_handler(DENY_BODY_MESSAGE_CT)
			else
				return error_handler(DENY_BODY_MESSAGE)
			end
		end

		if not string_find(content_type, "application/json") then
			return
		end

		local validator = validator_cache[conf]
		local body, err = get_req_body_json()

		if not body then
			return error_handler(err)
		end

		local ok, err = validator(body)

		if not ok then
			if err and conf.verbose_response then
				return error_handler(err)
			else
				return error_handler(DENY_BODY_MESSAGE)
			end
		end
	end
end

function RequestValidator:log(conf)
	local msg_table = kong.ctx.plugin.failure_message

	if msg_table then
		local log_msg = json_encode(msg_table)

		kong.log.debug("validation failed: ", log_msg)
	end
end

return RequestValidator
