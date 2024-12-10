local ffi = require("ffi")
local ngx = ngx

ffi.cdef([[
  typedef enum {
    ERROR_NO_ERROR = 0,
    ERROR_LICENSE_PATH_NOT_SET,
    ERROR_INTERNAL_ERROR,
    ERROR_OPEN_LICENSE_FILE,
    ERROR_READ_LICENSE_FILE,
    ERROR_INVALID_LICENSE_JSON,
    ERROR_INVALID_LICENSE_FORMAT,
    ERROR_VALIDATION_PASS,
    ERROR_VALIDATION_FAIL,
    ERROR_LICENSE_EXPIRED,
    ERROR_INVALID_EXPIRATION_DATE,
    ERROR_GRACE_PERIOD,
  } validation_error_t;

  validation_error_t validate_kong_license_data(const char* license);
]])

local liblicense_utils_loaded, liblicense_utils = pcall(ffi.load, "license_utils")
local _M = {}

local function license_validation_can_proceed()
	local dist_constants = require("kong.enterprise_edition.distributions_constants")

	if dist_constants.release and not liblicense_utils_loaded then
		return false
	end

	return true
end

local function validation_error_to_string(error)
	if error == "ERROR_NO_ERROR" then
		return "no error"
	elseif error == "ERROR_LICENSE_PATH_NOT_SET" then
		return "license path environment variable not set"
	elseif error == "ERROR_INTERNAL_ERROR" then
		return "internal error"
	elseif error == "ERROR_OPEN_LICENSE_FILE" then
		return "error opening license file"
	elseif error == "ERROR_READ_LICENSE_FILE" then
		return "error reading license file"
	elseif error == "ERROR_INVALID_LICENSE_JSON" then
		return "could not decode license json"
	elseif error == "ERROR_INVALID_LICENSE_FORMAT" then
		return "invalid license format"
	elseif error == "ERROR_VALIDATION_PASS" then
		return "validation passed"
	elseif error == "ERROR_VALIDATION_FAIL" then
		return "validation failed"
	elseif error == "ERROR_LICENSE_EXPIRED" then
		return "license expired"
	elseif error == "ERROR_INVALID_EXPIRATION_DATE" then
		return "invalid license expiration date"
	elseif error == "ERROR_GRACE_PERIOD" then
		return "license in grace period; contact support@konghq.com"
	end

	return "UNKNOWN ERROR"
end

local function validate_kong_license(license)
	if liblicense_utils_loaded then
		local error = liblicense_utils.validate_kong_license_data(license)

		ngx.log(ngx.DEBUG, "Using liblicense_utils shared library: ", validation_error_to_string(error))

		return error
	else
		local validation_can_proceed = license_validation_can_proceed()

		if not validation_can_proceed then
			return "ERROR_INTERNAL_ERROR"
		end

		local invalid_errors = {
			invalid_expiration_date = "ERROR_INVALID_EXPIRATION_DATE",
			license_expired = "ERROR_LICENSE_EXPIRED",
			validation_fail = "ERROR_VALIDATION_FAIL",
			invalid_license_format = "ERROR_INVALID_LICENSE_FORMAT",
			invalid_license_json = "ERROR_INVALID_LICENSE_JSON",
			read_license_file = "ERROR_READ_LICENSE_FILE",
			open_license_file = "ERROR_OPEN_LICENSE_FILE",
			internal_error = "ERROR_INTERNAL_ERROR",
			license_path_not_set = "ERROR_LICENSE_PATH_NOT_SET",
			no_error = "ERROR_NO_ERROR",
			grace_period = "ERROR_GRACE_PERIOD"
		}
		local passed_in_variable_name = debug.getlocal(2, 1)
		local error = invalid_errors[passed_in_variable_name] or "ERROR_VALIDATION_PASS"

		ngx.log(ngx.WARN, "Using development (e.g. not a release) license validation: ", error)

		return error
	end
end

_M.license_validation_can_proceed = license_validation_can_proceed
_M.validation_error_to_string = validation_error_to_string
_M.validate_kong_license = validate_kong_license

return _M
