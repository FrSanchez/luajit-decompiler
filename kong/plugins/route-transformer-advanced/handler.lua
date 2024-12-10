local pl_template = require("pl.template")
local pl_tablex = require("pl.tablex")
local set_path = kong.service.request.set_path
local req_get_headers = ngx.req.get_headers
local req_get_uri_args = ngx.req.get_uri_args
local meta = require("kong.meta")
local error = error
local rawset = rawset
local template_environment = nil
local EMPTY = pl_tablex.readonly({})
local __meta_environment = {
	__index = function (self, key)
		local lazy_loaders = {
			headers = function (self)
				return req_get_headers() or EMPTY
			end,
			query_params = function (self)
				return req_get_uri_args() or EMPTY
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
	rawset(template_environment, "headers", nil)
	rawset(template_environment, "query_params", nil)
	rawset(template_environment, "uri_captures", nil)
	rawset(template_environment, "shared", nil)
end

local plugin = {
	PRIORITY = 780,
	VERSION = meta.core_version
}
local conf_cache = setmetatable({}, {
	__mode = "k",
	__index = function (self, conf)
		local funcs = {}

		if conf.path then
			local tmpl = assert(pl_template.compile(conf.path))

			funcs[#funcs + 1] = function (env)
				if conf.escape_path then
					set_path(assert(tmpl:render(env)))
				else
					ngx.var.upstream_uri = assert(tmpl:render(env))
				end
			end
		end

		if conf.host then
			local tmpl = assert(pl_template.compile(conf.host))

			funcs[#funcs + 1] = function (env)
				ngx.ctx.balancer_data.host = assert(tmpl:render(env))
			end
		end

		if conf.port then
			local tmpl = assert(pl_template.compile(conf.port))

			funcs[#funcs + 1] = function (env)
				ngx.ctx.balancer_data.port = assert(tonumber(assert(tmpl:render(env))))
			end
		end

		return funcs
	end
})

function plugin:access(conf)
	local funcs = conf_cache[conf]

	clear_environment()

	for _, func in ipairs(funcs) do
		func(template_environment)
	end
end

return plugin
