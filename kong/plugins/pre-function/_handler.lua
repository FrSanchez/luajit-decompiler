local resty_mlcache = require("kong.resty.mlcache")
local sandbox = require("kong.tools.sandbox")
local kong_meta = require("kong.meta")
local config_cache = nil

local function no_op()
end

local shm_name = "kong_db_cache"
local cache_name = "serverless_" .. shm_name
local cache = resty_mlcache.new(cache_name, shm_name, {
	lru_size = 10000
})
local sandbox_kong = setmetatable({
	cache = cache,
	configuration = kong.configuration.remove_sensitive()
}, {
	__index = kong
})
local sandbox_opts = {
	env = {
		kong = sandbox_kong,
		ngx = ngx
	}
}

local function compile_phase_array(phase_funcs)
	if not phase_funcs or #phase_funcs == 0 then
		return no_op
	else
		local compiled = {}

		for i, func_string in ipairs(phase_funcs) do
			local func = assert(sandbox.sandbox(func_string, sandbox_opts))
			local first_run_complete = false

			compiled[i] = function ()
				if not first_run_complete then
					first_run_complete = true
					local result = func()

					if type(result) == "function" then
						func = result
						compiled[i] = func

						func()
					end

					compiled[i] = func
				else
					compiled[i] = func

					func()
				end
			end
		end

		return function ()
			for _, f in ipairs(compiled) do
				f()
			end
		end
	end
end

local phases = {
	"certificate",
	"rewrite",
	"access",
	"header_filter",
	"body_filter",
	"log",
	"ws_client_frame",
	"ws_upstream_frame",
	"ws_handshake",
	"ws_close"
}
config_cache = setmetatable({}, {
	__mode = "k",
	__index = function (self, config)
		local runtime_funcs = {}

		for _, phase in ipairs(phases) do
			local func = compile_phase_array(config[phase])
			runtime_funcs[phase] = func
		end

		self[config] = runtime_funcs

		return runtime_funcs
	end
})

return function (priority)
	local ServerlessFunction = {
		PRIORITY = priority,
		VERSION = kong_meta.core_version,
		certificate = function (self, config)
			config_cache[config].certificate()
		end,
		rewrite = function (self, config)
			config_cache[config].rewrite()
		end,
		access = function (self, config)
			config_cache[config].access()
		end,
		header_filter = function (self, config)
			config_cache[config].header_filter()
		end,
		body_filter = function (self, config)
			config_cache[config].body_filter()
		end,
		log = function (self, config)
			config_cache[config].log()
		end,
		ws_handshake = function (self, config)
			config_cache[config].ws_handshake()
		end,
		ws_client_frame = function (self, config)
			config_cache[config].ws_client_frame()
		end,
		ws_upstream_frame = function (self, config)
			config_cache[config].ws_upstream_frame()
		end,
		ws_close = function (self, config)
			config_cache[config].ws_close()
		end
	}

	return ServerlessFunction
end
