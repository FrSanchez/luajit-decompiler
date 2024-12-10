local ngx_re = require("ngx.re")
local tablex = require("pl.tablex")
local table_insert = table.insert
local table_remove = table.remove
local type = type
local ipairs = ipairs
local tonumber = tonumber
local null = ngx.null
local EMPTY = tablex.readonly({})
local _M = {}

local function is_present(str)
	return str and str ~= "" and str ~= null
end

local function _navigate_and_apply(ctx, json, path, fn, opts)
	local head, index, tail = nil

	if opts.dots_in_keys then
		head = path
	else
		local res = ngx_re.split(path, "(?:\\[([\\d|\\*]*)\\])?\\.", "jo", nil, 2)

		if res then
			head = res[1]

			if res[2] and res[3] then
				index = res[2]
				tail = res[3]
			else
				tail = res[2]
			end
		end
	end

	if type(json) == "table" then
		if index == "*" then
			local array = json
			local head_visit = false

			if is_present(head) then
				table_insert(ctx.paths, head)

				array = json[head]
				head_visit = true
			end

			for k, v in ipairs(array or EMPTY) do
				if type(v) == "table" then
					table_insert(ctx.paths, k)

					ctx.index = k

					_navigate_and_apply(ctx, v, tail, fn, opts)

					ctx.index = nil

					table_remove(ctx.paths)
				end
			end

			if head_visit then
				table_remove(ctx.paths)
			end
		elseif is_present(index) then
			index = tonumber(index)
			local element = json
			local head_visit = false

			if is_present(head) and type(json[head]) == "table" then
				table_insert(ctx.paths, head)

				element = json[head]
				head_visit = true
			end

			element = element[index]

			table_insert(ctx.paths, index)

			ctx.index = index

			_navigate_and_apply(ctx, element, tail, fn, opts)

			ctx.index = nil

			table_remove(ctx.paths)

			if head_visit then
				table_remove(ctx.paths)
			end
		elseif is_present(tail) then
			if opts.create_inexistent_parent and json[head] == nil then
				json[head] = {}
			end

			table_insert(ctx.paths, head)
			_navigate_and_apply(ctx, json[head], tail, fn, opts)
			table_remove(ctx.paths)
		elseif is_present(head) then
			fn(json, head, ctx)
		end
	end
end

function _M.navigate_and_apply(json, path, fn, opts)
	opts = opts or EMPTY
	local ctx = {
		paths = {}
	}

	return _navigate_and_apply(ctx, json, path, fn, opts)
end

return _M
