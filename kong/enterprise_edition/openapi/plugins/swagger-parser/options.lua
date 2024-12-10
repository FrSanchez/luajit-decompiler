local pl_tablex = require("pl.tablex")
local socket_url = require("socket.url")
local type = type
local pairs = pairs
local string_byte = string.byte
local string_sub = string.sub
local deepcopy = pl_tablex.deepcopy
local SLASH_BYTE = string_byte("/")
local EMPTY_T = {}
local DEFAULT_OPTIONS = {
	resolve_base_path = false,
	dereference = {
		circular = false
	}
}

local function merge(opts, customize_opts)
	for k, v in pairs(opts) do
		if type(v) == "table" and type(customize_opts[k]) == "table" then
			merge(v, customize_opts[k])
		elseif customize_opts[k] ~= nil then
			opts[k] = customize_opts[k]
		end
	end

	return opts
end

local function resolve_options(opts)
	local default_options = deepcopy(DEFAULT_OPTIONS)

	return merge(default_options, opts or EMPTY_T)
end

local function get_base_path(spec)
	local base_path = "/"

	if spec.openapi then
		if spec.servers and #spec.servers == 1 and spec.servers[1].url then
			local url = spec.servers[1].url

			if string_byte(url, 1) == SLASH_BYTE then
				base_path = url
			else
				local parsed_url = socket_url.parse(url)

				if parsed_url and parsed_url.path and string_byte(parsed_url.path, 1) == SLASH_BYTE then
					base_path = parsed_url.path
				end
			end
		end
	elseif spec.basePath and string_byte(spec.basePath, 1) == SLASH_BYTE then
		base_path = spec.basePath
	end

	return base_path
end

local function remove_trailing_slashes(path)
	local idx = nil

	for i = #path, 1, -1 do
		if string_byte(path, i) ~= SLASH_BYTE then
			break
		end

		idx = i
	end

	if idx then
		path = string_sub(path, 1, idx - 1)
	end

	return path
end

local function resolve_paths(spec)
	local base_path = get_base_path(spec)

	if base_path == "/" or not spec.paths then
		return
	end

	local paths = {}
	base_path = remove_trailing_slashes(base_path)

	for path, path_spec in pairs(spec.paths) do
		if string_byte(path, 1) ~= SLASH_BYTE then
			path = "/" .. path
		end

		local resolved_path = base_path .. path
		paths[resolved_path] = path_spec
	end

	spec.paths = paths
end

local function apply(spec, options)
	if options.resolve_base_path == true then
		resolve_paths(spec)
	end
end

return {
	apply = apply,
	resolve_options = resolve_options
}
