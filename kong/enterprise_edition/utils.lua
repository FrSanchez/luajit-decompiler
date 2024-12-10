local cjson = require("cjson")
local http = require("resty.http")
local utils = require("kong.tools.utils")
local ee_jwt = require("kong.enterprise_edition.jwt")
local enums = require("kong.enterprise_edition.dao.enums")
local lower = string.lower
local time = ngx.time
local tablex_sort = require("pl.tablex").sort
local _M = {
	validate_email = function (str)
		if str == nil then
			return nil, "missing"
		end

		if type(str) ~= "string" then
			return nil, "must be a string"
		end

		local at = str:find("@")

		if not at then
			return nil, "missing '@' symbol"
		end

		local last_at = str:find("[^%@]+$")

		if not last_at then
			return nil, "missing domain"
		end

		local local_part = str:sub(1, last_at - 2)

		if local_part == nil or local_part == "" then
			return nil, "missing local-part"
		end

		local domain_part = str:sub(last_at, #str)

		if domain_part == nil or domain_part == "" then
			return nil, "missing domain"
		end

		if #local_part > 64 then
			return nil, "local-part over 64 characters"
		end

		if #domain_part > 253 then
			return nil, "domain over 253 characters"
		end

		local quotes = local_part:find("[\"]")

		if type(quotes) == "number" and quotes > 1 then
			return nil, "local-part invalid quotes"
		end

		if local_part:find("%@+") and quotes == nil then
			return nil, "local-part invalid '@' character"
		end

		if not domain_part:find("%.") then
			return nil, "domain missing '.' character"
		end

		if domain_part:find("%.%.") then
			return nil, "domain cannot contain consecutive '.'"
		end

		if local_part:find("%.%.") then
			return nil, "local-part cannot contain consecutive '.'"
		end

		if not str:match("[%w]*[%p]*%@+[%w]*[%.]?[%w]*") then
			return nil, "invalid format"
		end

		return true
	end,
	check_case = function (value, consumer_t)
		if consumer_t.type ~= enums.CONSUMERS.TYPE.ADMIN then
			return true
		end

		if consumer_t.email and consumer_t.email ~= lower(consumer_t.email) then
			return false, "'email' must be lower case"
		end

		return true
	end,
	validate_reset_jwt = function (token_param)
		local jwt, err = ee_jwt.parse_JWT(token_param)

		if err then
			return nil, ee_jwt.INVALID_JWT
		end

		if not jwt.header or jwt.header.typ ~= "JWT" or jwt.header.alg ~= "HS256" then
			return nil, ee_jwt.INVALID_JWT
		end

		if not jwt.claims or not jwt.claims.exp then
			return nil, ee_jwt.INVALID_JWT
		end

		if jwt.claims.exp <= time() then
			return nil, ee_jwt.EXPIRED_JWT
		end

		if not jwt.claims.id then
			return nil, ee_jwt.INVALID_JWT
		end

		return jwt
	end
}

local function lookup(t, k)
	local ok = k

	if type(k) ~= "string" then
		return t[k], k
	else
		k = k:lower()
	end

	for key, value in pairs(t) do
		if tostring(key):lower() == k then
			return value, key
		end
	end

	return nil, ok
end

local function as_body(data, opts)
	local body = ""
	local headers = opts.headers or {}
	local content_type, content_type_name = lookup(headers, "Content-Type")
	content_type = content_type or ""
	local t_body_table = type(data) == "table"

	if string.find(content_type, "application/json") and t_body_table then
		body = cjson.encode(data)
	elseif string.find(content_type, "www-form-urlencoded", nil, true) and t_body_table then
		body = utils.encode_args(data, true, opts.no_array_indexes)
	elseif string.find(content_type, "multipart/form-data", nil, true) and t_body_table then
		local form = data
		local boundary = "8fd84e9444e3946c"

		for k, v in pairs(form) do
			body = body .. "--" .. boundary .. "\r\nContent-Disposition: form-data; name=\"" .. k .. "\"\r\n\r\n" .. tostring(v) .. "\r\n"
		end

		if body ~= "" then
			body = body .. "--" .. boundary .. "--\r\n"
		end

		if not content_type:find("boundary=") then
			headers[content_type_name] = content_type .. "; boundary=" .. boundary
		end
	end

	return body
end

function _M.request(url, opts)
	local opts = opts or {}
	local method = opts.method or "GET"
	local headers = opts.headers or {}
	local body = opts.body or nil
	local data = opts.data or nil

	if method == "GET" and data then
		url = url .. "?" .. utils.encode_args(data)
	elseif (method == "POST" or method == "PUT" or method == "PATCH") and (data and not body or #body == 0) then
		if not lookup(headers, "content-type") then
			headers["Content-Type"] = "multipart/form-data"
		end

		body = as_body(data, {
			headers = headers
		})
	end

	if opts.sign_with and body then
		local sign_header = opts.sign_header or "X-Kong-Signature"
		local alg, hmac = opts.sign_with(body)
		headers[sign_header] = alg .. "=" .. hmac
	end

	local client = http.new()
	local params = {
		method = method,
		body = body,
		headers = headers,
		ssl_verify = opts.ssl_verify or false
	}

	return client:request_uri(url, params)
end

local function normalize_table(data)
	local hash = nil

	for k, v in tablex_sort(data) do
		if type(v) == "table" then
			v = normalize_table(v)
		end

		if v and type(v) == "string" then
			hash = hash and hash .. ":" .. k .. ":" .. v or k .. ":" .. v
		else
			hash = hash and hash .. ":" .. k or k
		end
	end

	return hash
end

_M.normalize_table = normalize_table

return _M
