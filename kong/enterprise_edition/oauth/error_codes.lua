local fmt = string.format
local concat = table.concat
local insert = table.insert
local INVALID_TOKEN = "invalid_token"
local INVALID_REQUEST = "invalid_request"
local INSUFFICIENT_SCOPE = "insufficient_scope"
local HTTP_BAD_REQUEST = 400
local HTTP_UNAUTHORIZED = 401
local HTTP_FORBIDDEN = 403
local Error = {
	new = function (self, e)
		e = e or {}
		local obj = {
			status_code = e.status_code or 500,
			error_code = e.error_code or nil,
			error_description = e.error_description or nil,
			message = e.message or "internal server error",
			log = e.log_msg or e.message,
			expose_error_code = e.expose_error_code or false
		}

		setmetatable(obj, self)

		return obj
	end,
	expose_error = function (self)
		if self.expose_error_code and self.error_code then
			return true
		end

		return false
	end,
	build_auth_header = function (self, host)
		local header = {}
		local hostname = host or "kong"
		local www_bearer_realm = fmt("Bearer realm=\"%s\"", hostname)

		insert(header, www_bearer_realm)

		if self:expose_error() then
			insert(header, fmt("error=\"%s\"", self.error_code))

			if self.error_description then
				insert(header, fmt("error_description=\"%s\"", self.error_description))
			end
		end

		local headers = {
			["WWW-Authenticate"] = concat(header, ", ")
		}

		return headers
	end
}
local ForbiddenError = {}

setmetatable(ForbiddenError, {
	__index = Error
})

function ForbiddenError:new(e)
	e.status_code = HTTP_FORBIDDEN
	e.error_code = INSUFFICIENT_SCOPE
	e.message = e.message or "Forbidden"
	local obj = Error:new(e)

	setmetatable(obj, self)

	self.__index = self

	return obj
end

local UnauthorizedError = {}

setmetatable(UnauthorizedError, {
	__index = Error
})

function UnauthorizedError:new(e)
	e.status_code = HTTP_UNAUTHORIZED
	e.error_code = INVALID_TOKEN
	e.message = e.message or "Unauthorized"
	local obj = Error:new(e)

	setmetatable(obj, self)

	self.__index = self

	return obj
end

local BadRequestError = {}

setmetatable(BadRequestError, {
	__index = Error
})

function BadRequestError:new(e)
	e.status_code = HTTP_BAD_REQUEST
	e.error_code = INVALID_REQUEST
	e.message = e.mesasge or "Bad Request"
	local obj = Error:new(e)

	setmetatable(obj, self)

	self.__index = self

	return obj
end

return {
	UnauthorizedError = UnauthorizedError,
	ForbiddenError = ForbiddenError,
	BadRequestError = BadRequestError,
	INSUFFICIENT_SCOPE = INSUFFICIENT_SCOPE,
	INVALID_REQUEST = INVALID_REQUEST,
	INVALID_TOKEN = INVALID_TOKEN
}
