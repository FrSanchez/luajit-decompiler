local openssl_hmac = require("resty.openssl.hmac")
local cjson = require("cjson.safe")
local pl_string = require("pl.stringx")
local string_rep = string.rep
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64
local concat = table.concat
local _M = {
	INVALID_JWT = "Invalid JWT",
	EXPIRED_JWT = "Expired JWT"
}
local algs = {
	HS256 = function (data, secret)
		return openssl_hmac.new(secret, "sha256"):final(data)
	end
}

local function b64_encode(input)
	local result = encode_base64(input)
	result = result:gsub("+", "-"):gsub("/", "_"):gsub("=", "")

	return result
end

local function b64_decode(input)
	local remainder = #input % 4

	if remainder > 0 then
		local padlen = 4 - remainder
		input = input .. string_rep("=", padlen)
	end

	input = input:gsub("-", "+"):gsub("_", "/")

	return decode_base64(input)
end

function _M.verify_signature(jwt, secret)
	local signing_func = algs[jwt.header.alg]

	if not signing_func then
		return nil, "invalid alg"
	end

	return jwt.signature == signing_func(jwt.header_64 .. "." .. jwt.claims_64, secret)
end

function _M.generate_JWT(claims, secret, alg)
	local header = {
		typ = "JWT",
		alg = alg or "HS256"
	}
	local signing_func = algs[header.alg]

	if not signing_func then
		return nil, "invalid alg"
	end

	local segments = {
		b64_encode(cjson.encode(header)),
		b64_encode(cjson.encode(claims))
	}
	local data = table_concat(segments, ".")
	local signature = signing_func(data, secret)

	return data .. "." .. b64_encode(signature)
end

function _M.parse_JWT(jwt)
	if type(jwt) ~= "string" or jwt == "" then
		return nil, _M.INVALID_JWT
	end

	local header_64, claims_64, signature_64 = unpack(pl_string.split(jwt, "."))
	local header, err = cjson.decode(b64_decode(header_64))

	if err then
		return nil, _M.INVALID_JWT
	end

	local claims, err = cjson.decode(b64_decode(claims_64))

	if err then
		return nil, _M.INVALID_JWT
	end

	local signature = b64_decode(signature_64)

	return {
		header = header,
		claims = claims,
		signature = signature,
		header_64 = header_64,
		claims_64 = claims_64,
		signature_64 = signature_64
	}
end

function _M.find_claim(payload, search)
	if type(payload) ~= "table" then
		return nil
	end

	local search_t = type(search)
	local t = payload

	if search_t == "string" then
		if not t[search] then
			return nil
		end

		t = t[search]
	elseif search_t == "table" then
		for _, claim in ipairs(search) do
			if not t[claim] then
				return nil
			end

			t = t[claim]
		end
	else
		return nil
	end

	if type(t) == "table" then
		return concat(t, " ")
	end

	return tostring(t)
end

return _M
