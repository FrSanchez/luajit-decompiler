local utils = require("kong.tools.utils")
local cjson = require("cjson")
local tostring = tostring
local type = type
local ngx = ngx
local SERVICE_IDS = {
	portal = "00000000-0000-0000-0000-000000000000",
	admin = "00000000-0000-0000-0000-000000000001"
}
local loaded_plugins_map = {}
local admin_plugin_models = {}
local PHASES, set_named_ctx = nil

local function apply_plugin(plugin, phase, opts)
	local ctx = ngx.ctx
	ctx.KONG_PHASE = PHASES[phase]

	set_named_ctx(kong, "plugin", plugin.config)

	local res, err = plugin.handler[phase](plugin.handler, plugin.config, opts.exit_handler)

	if err then
		return nil, err
	end

	ctx.KONG_PHASE = PHASES.admin_api

	return res or true
end

local function prepare_plugin(opts)
	local model, err = nil
	local plugin = loaded_plugins_map[opts.name]

	if not plugin then
		return nil, "plugin: " .. opts.name .. " not found."
	end

	local fields = {
		name = opts.name,
		service = {
			id = SERVICE_IDS[opts.api_type]
		},
		config = utils.cycle_aware_deep_copy(opts.config) or {}
	}

	if opts.api_type == "admin" then
		model = admin_plugin_models[opts.name]
	end

	if not model then
		local plugins_entity = opts.db.plugins
		model, err = plugins_entity.schema:process_auto_fields(fields, "insert")

		if not model then
			local err_t = plugins_entity.errors:schema_violation(err)

			return nil, tostring(err_t), err_t
		end

		if type(model.config) == "string" then
			model.config = cjson.decode(model.config)
		end

		local ok, errors = plugins_entity.schema:validate_insert(model)

		if not ok then
			local err_t = plugins_entity.errors:schema_violation(errors)

			return nil, tostring(err_t), err_t
		end

		for k, v in pairs(model.config) do
			if type(v) == "userdata" then
				model.config[k] = nil
			end
		end

		if opts.name == "cors" and model.config and model.config.origins then
			local origins = model.config.origins

			for k, v in ipairs(origins) do
				model.config.origins[k] = ngx.re.gsub(origins[k], ":443$", "")
				model.config.origins[k] = ngx.re.gsub(origins[k], ":80$", "")
			end
		end

		if opts.api_type == "admin" then
			admin_plugin_models[opts.name] = model
		end
	end

	return {
		handler = plugin.handler,
		config = model.config
	}
end

local function validate(opts)
	if type(opts) ~= "table" then
		return nil, "invoke_plugin validate: opts must be a table"
	end

	local plugin = loaded_plugins_map[opts.name]

	if not plugin then
		return nil, "plugin: " .. opts.name .. " not found."
	end

	local config = {}

	if type(opts.config) == "string" then
		config = cjson.decode(opts.config)
	elseif type(opts.config) == "table" then
		config = utils.cycle_aware_deep_copy(opts.config)
	end

	local fields = {
		name = opts.name,
		service = {
			id = SERVICE_IDS[opts.api_type]
		},
		config = config
	}
	local plugins_entity = opts.db.plugins
	local model, err = plugins_entity.schema:process_auto_fields(fields, "insert")

	if not model then
		return nil, err
	end

	local ok, err = plugins_entity.schema:validate_insert(model)

	if not ok then
		return nil, err
	end

	return true
end

local function prepare_and_invoke(opts)
	if opts.validate_only then
		return validate(opts)
	end

	local prepared_plugin, err = prepare_plugin(opts)

	if not prepared_plugin then
		return nil, err
	end

	local res, err = nil

	for _, phase in ipairs(opts.phases) do
		res, err = apply_plugin(prepared_plugin, phase, opts)

		if not res then
			return nil, err
		end
	end

	return res
end

local function set_phase(phase)
	ngx.ctx.KONG_PHASE = phase
end

return {
	new = function (opts)
		for _, plugin in ipairs(opts.loaded_plugins) do
			loaded_plugins_map[plugin.name] = plugin
		end

		local kong_global = opts.kong_global
		PHASES = kong_global.phases
		set_phase = set_phase
		set_named_ctx = kong_global.set_named_ctx

		return setmetatable({
			prepare_plugin = prepare_plugin
		}, {
			__call = function (_, ...)
				return prepare_and_invoke(...)
			end
		})
	end
}
