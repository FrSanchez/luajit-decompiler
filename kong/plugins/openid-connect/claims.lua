local type = type
local ipairs = ipairs
local concat = table.concat
local tostring = tostring
local tonumber = tonumber
local floor = math.floor

local function find_claim(token, search, no_transform)
	if type(token) ~= "table" then
		return nil
	end

	local search_t = type(search)
	local t = token

	if search_t == "string" then
		if t[search] then
			t = t[search]
		else
			local search_n = tonumber(search, 10)

			if search_n and floor(search_n) == search_n and t[search_n] then
				t = t[search_n]
			else
				return nil
			end
		end
	elseif search_t == "table" then
		for _, claim in ipairs(search) do
			if t[claim] then
				t = t[claim]
			else
				local claim_n = tonumber(claim, 10)

				if claim_n and floor(claim_n) == claim_n and t[claim_n] then
					t = t[claim_n]
				else
					return nil
				end
			end
		end
	else
		return nil
	end

	if no_transform then
		return t
	end

	if type(t) == "table" then
		return concat(t, " ")
	end

	return tostring(t)
end

local function token_is_expired(exp, now)
	if type(now) ~= "number" then
		return true, "now must be a number"
	end

	if type(exp) ~= "number" then
		return true, "exp must be a number"
	end

	if exp < 0 then
		return true, "exp must be greater than 0"
	end

	if now < 0 then
		return true, "now must be greater than 0"
	end

	if now < exp then
		return false
	end

	return true, "token has expired"
end

local function get_exp(access_token, tokens_encoded, now, exp_default)
	if access_token and type(access_token) == "table" then
		local exp = nil

		if type(access_token.payload) == "table" and access_token.payload.exp then
			exp = tonumber(access_token.payload.exp, 10)

			if exp then
				return exp
			end
		end

		exp = tonumber(access_token.exp)

		if exp then
			return exp
		end
	end

	if tokens_encoded and type(tokens_encoded) == "table" and tokens_encoded.expires_in then
		local expires_in = tonumber(tokens_encoded.expires_in, 10)

		if expires_in then
			if expires_in == 0 then
				return 0
			end

			return now + expires_in
		end
	end

	return exp_default
end

return {
	find = find_claim,
	exp = get_exp,
	token_is_expired = token_is_expired
}
