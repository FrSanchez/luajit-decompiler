local dereference = require("kong.enterprise_edition.openapi.plugins.swagger-parser.dereference")
local options = require("kong.enterprise_edition.openapi.plugins.swagger-parser.options")
local cjson = require("cjson.safe").new()
local lyaml = require("lyaml")
local type = type
local pcall = pcall
local fmt = string.format
local tab_sort = table.sort
local pairs = pairs
local _M = {
	dereference = function (spec, opts)
		opts = options.resolve_options(opts)

		return dereference.resolve(spec, opts)
	end,
	parse = function (spec_str, opts)
		spec_str = ngx.unescape_uri(spec_str)
		local parsed_spec, decode_err = cjson.decode(spec_str)

		if decode_err then
			local pok = nil
			pok, parsed_spec = pcall(lyaml.load, spec_str)

			if not pok or type(parsed_spec) ~= "table" then
				return nil, fmt("api specification is neither valid json ('%s') nor valid yaml ('%s')", decode_err, parsed_spec)
			end
		end

		opts = options.resolve_options(opts)
		local deferenced_schema, err = dereference.resolve(parsed_spec, opts)

		if err then
			return nil, err
		end

		options.apply(deferenced_schema, opts)

		if deferenced_schema.paths then
			local sorted_paths = {}
			local n = 0

			for path in pairs(deferenced_schema.paths) do
				n = n + 1
				sorted_paths[n] = path
			end

			tab_sort(sorted_paths)

			deferenced_schema.sorted_paths = sorted_paths
		end

		local spec = {
			version = 2,
			spec = deferenced_schema
		}

		if parsed_spec.openapi then
			spec.version = 3
		end

		return spec, nil
	end
}

return _M
