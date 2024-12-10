local split = require("pl.stringx").split
local utils = require("kong.tools.utils")
local clone = require("table.clone")
local type = type
local pairs = pairs
local byte = string.byte
local sub = string.sub
local _M = {}

local function is_ref(obj)
	return type(obj) == "table" and obj["$ref"]
end

local function has_ref(schema)
	if is_ref(schema) then
		return true
	end

	if type(schema) == "table" then
		for _, value in pairs(schema) do
			if has_ref(value) then
				return true
			end
		end
	end

	return false
end

local function by_ref(obj, ref)
	if type(ref) ~= "string" then
		return nil, "invalid ref: ref must be a string"
	end

	if byte(ref) ~= byte("/") then
		return nil, "invalid ref: " .. ref
	end

	if ref == "/" then
		return obj
	end

	local segments = split(sub(ref, 2), "/")

	for i = 1, #segments do
		local segment = segments[i]

		if obj[segment] == nil then
			return nil, "invalid ref: " .. segment
		end

		obj = obj[segment]
	end

	return obj
end

local function is_circular(refs, schema)
	local visited = {}

	while is_ref(schema) do
		local ref = schema["$ref"]

		if visited[ref] then
			return true
		end

		visited[ref] = true
		ref = sub(ref, 2)
		schema = by_ref(refs, ref)
	end

	return false
end

local reference_mt = {
	is_ref = function (self)
		return true
	end
}

local function resolve_ref(spec, schema, opts, parent_ref)
	if type(schema) ~= "table" then
		return schema
	end

	for key, value in pairs(schema) do
		if key == "schema" and opts.dereference.circular then
			if has_ref(value) then
				setmetatable(value, {
					__index = reference_mt,
					refs = {
						definitions = spec.definitions,
						components = spec.components
					}
				})

				if is_circular(spec, value) then
					return nil, "recursion detected in schema dereferencing: " .. value["$ref"]
				end
			end
		else
			local curr_parent_ref = clone(parent_ref)

			while is_ref(value) do
				local ref = value["$ref"]

				if byte(ref, 1) ~= byte("#") then
					return nil, "only local references are supported, not " .. ref
				end

				if curr_parent_ref[ref] then
					return nil, "recursion detected in schema dereferencing"
				end

				curr_parent_ref[ref] = true
				local ref_target, err = by_ref(spec, sub(ref, 2))

				if not ref_target then
					return nil, "failed dereferencing schema: " .. err
				end

				value = utils.cycle_aware_deep_copy(ref_target)
				schema[key] = value
			end

			if type(value) == "table" then
				local ok, err = resolve_ref(spec, value, opts, curr_parent_ref)

				if not ok then
					return nil, err
				end
			end
		end
	end

	return schema
end

function _M.resolve(spec, opts)
	local resolved_paths, err = resolve_ref(spec, spec.paths, opts, {})

	if err then
		return nil, err
	end

	spec.paths = resolved_paths

	return spec
end

return _M
