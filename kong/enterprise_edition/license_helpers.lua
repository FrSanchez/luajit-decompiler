local cjson = require("cjson.safe")
local pl_path = require("pl.path")
local log = require("kong.cmd.utils.log")
local dist_constants = require("kong.enterprise_edition.distributions_constants")
local license_utils = require("kong.enterprise_edition.license_utils")
local base64 = require("ngx.base64")
local hooks = require("kong.hooks")
local sha256_hex = require("kong.tools.utils").sha256_hex
local ee_constants = require("kong.enterprise_edition.constants")
local timer_at = ngx.timer.at
local split = require("kong.tools.utils").split
local re_find = ngx.re.find
local kong_dict = ngx.shared.kong
local ceil = math.ceil
local min = math.min
local DAY = 86400
local PLEASE_CONTACT_STR = "Please contact <support@konghq.com> to renew your license."
local GRACE_PERIOD_DAYS = 30
local IS_EXCEEDS_GRACE_PERIOD = false
local WARNING_NOTICE_DAYS = 90
local ERROR_NOTICE_DAYS = 30
local ERROR_NOTICE_DAYS_KONNECT = 16
local LICENSE_NOTIFICATION_INTERVAL = DAY
local LICENSE_NOTIFICATION_LOCK_KEY = "events:license"
local decode_base64 = ngx.decode_base64
local decode_base64url = base64.decode_base64url
local EMPTY = setmetatable({}, {
	__newindex = function ()
		error("The 'EMPTY' table is read-only")
	end
})
local _M = {}
local DEFAULT_KONG_LICENSE_PATH = "/etc/kong/license.json"

local function decode_base64_str(str)
	if type(str) == "string" then
		return decode_base64(str) or decode_base64url(str) or nil, "base64 decoding failed: invalid input"
	else
		return nil, "base64 decoding failed: not a string"
	end
end

function _M.filter_latest_license(lic_iter)
	local license = nil

	for l in lic_iter, nil,  do
		if not license or license.updated_at < l.updated_at then
			license = l
		end
	end

	return license or nil
end

function _M.decode_license(str)
	if not str or str == "" then
		return nil
	end

	local license, err = cjson.decode(str)

	if err then
		ngx.log(ngx.ERR, "[license-helpers] could not decode license JSON: " .. err)

		return nil
	end

	return license
end

local function get_license_string()
	local license_data_env = os.getenv("KONG_LICENSE_DATA")
	license_data_env = decode_base64_str(license_data_env) or license_data_env

	if license_data_env then
		ngx.log(ngx.DEBUG, "[license-helpers] loaded license from KONG_LICENSE_DATA")

		return license_data_env
	end

	local license_path = nil

	if pl_path.exists(DEFAULT_KONG_LICENSE_PATH) then
		ngx.log(ngx.DEBUG, "[license-helpers] loaded license from default Kong license path")

		license_path = DEFAULT_KONG_LICENSE_PATH
	else
		license_path = os.getenv("KONG_LICENSE_PATH")

		if not license_path then
			if kong and kong.db and kong.db.licenses then
				local license = _M.filter_latest_license(kong.db.licenses:each())

				if license then
					ngx.log(ngx.INFO, "[license-helpers] loaded license from database; using license id: ", license.id)

					return license.payload
				end
			end

			ngx.log(ngx.DEBUG, "[license-helpers] KONG_LICENSE_PATH is not set")

			return nil
		end
	end

	local license_file = io.open(license_path, "r")

	if not license_file then
		ngx.log(ngx.NOTICE, "[license-helpers] could not open license file")

		return nil
	end

	local license_data = license_file:read("*a")

	if not license_data then
		ngx.log(ngx.NOTICE, "[license-helpers] could not read license file contents")

		return nil
	end

	license_file:close()
	ngx.log(ngx.DEBUG, "[license-helpers] loaded license from KONG_LICENSE_PATH")

	return license_data
end

local function license_expiration_time(license)
	local expiration_date = license and license.license and license.license.payload and license.license.payload.license_expiration_date

	if not expiration_date or not re_find(expiration_date, "^\\d{4}-\\d{2}-\\d{2}$") then
		return
	end

	local date_t = split(expiration_date, "-")
	local ok, res = pcall(os.time, {
		year = tonumber(date_t[1]),
		month = tonumber(date_t[2]),
		day = tonumber(date_t[3])
	})

	if ok then
		return res
	end

	return nil
end

function _M.read_license_info()
	local license_data = get_license_string()

	if kong and kong.configuration and kong.configuration.fips then
		hooks.run_hook("fips:kong:validate", _M.get_type(license_data and cjson.decode(license_data) or {}))
	end

	if not license_data or license_data == "" then
		ngx.log(ngx.NOTICE, "[license-helpers] could not decode license JSON: No license found")

		return nil
	end

	local vault = kong and kong.vault

	if vault and vault.is_reference(license_data) then
		local deref, err = vault.get(license_data)

		if deref then
			license_data = deref
		else
			if err then
				ngx.log(ngx.ERR, "[license-helpers] unable to resolve reference ", license_data, " (", err, ")")
			else
				ngx.log(ngx.ERR, "[license-helpers] unable to resolve reference ", license_data)
			end

			return nil
		end
	end

	if not _M.is_valid_license(license_data) then
		return nil
	end

	return _M.decode_license(license_data)
end

function _M.get_type(lic)
	local expiration_time = license_expiration_time(lic)
	local l_type = nil

	if not expiration_time then
		l_type = "free"
	elseif expiration_time < ngx.time() then
		l_type = "full_expired"
	else
		l_type = "full"
	end

	return l_type
end

function _M.get_featureset(l_type)
	local lic = nil

	if not kong or not kong.license then
		lic = _M.read_license_info()
	else
		lic = kong.license
	end

	l_type = l_type or _M.get_type(lic)

	return dist_constants.featureset[l_type]
end

local function get_lock(key, exptime)
	local ok, err = kong_dict:safe_add(key, true, exptime - 0.001)

	if not ok and err ~= "exists" then
		log(ngx.WARN, "could not get lock from 'kong' shm: ", err)
	end

	return ok
end

local function log_license_state_konnect(expiration_time, now)
	if expiration_time < now + ERROR_NOTICE_DAYS_KONNECT * DAY then
		ngx.log(ngx.ERR, string.format("The Kong Enterprise license will expire on %s. " .. PLEASE_CONTACT_STR, os.date("%Y-%m-%d", expiration_time)))
	end
end

local function is_exceeds_grace_period()
	return IS_EXCEEDS_GRACE_PERIOD
end

_M.is_exceeds_grace_period = is_exceeds_grace_period

local function log_license_state(expiration_time, now, konnect_mode)
	if expiration_time < now then
		if now < expiration_time + GRACE_PERIOD_DAYS * DAY then
			IS_EXCEEDS_GRACE_PERIOD = true

			ngx.log(ngx.CRIT, string.format("Your license is expired. You have %d days left in the renewal grace period. " .. PLEASE_CONTACT_STR, GRACE_PERIOD_DAYS - min(ceil((now - expiration_time) / DAY), GRACE_PERIOD_DAYS)))

			return
		end

		IS_EXCEEDS_GRACE_PERIOD = false

		ngx.log(ngx.CRIT, string.format("The Kong Enterprise license expired on %s. " .. PLEASE_CONTACT_STR, os.date("%Y-%m-%d", expiration_time)))

		return
	end

	if konnect_mode then
		return log_license_state_konnect(expiration_time, now)
	end

	if expiration_time < now + ERROR_NOTICE_DAYS * DAY then
		ngx.log(ngx.ERR, string.format("The Kong Enterprise license will expire on %s. " .. PLEASE_CONTACT_STR, os.date("%Y-%m-%d", expiration_time)))
	elseif expiration_time < now + WARNING_NOTICE_DAYS * DAY then
		ngx.log(ngx.WARN, string.format("The Kong Enterprise license will expire on %s. " .. PLEASE_CONTACT_STR, os.date("%Y-%m-%d", expiration_time)))
	end
end

_M.log_license_state = log_license_state

local function license_notification_handler(premature, expiration_time, konnect_mode)
	if premature then
		return
	end

	timer_at(LICENSE_NOTIFICATION_INTERVAL, license_notification_handler, expiration_time, konnect_mode)

	local now = ngx.time()

	if expiration_time < now then
		kong.licensing:update_featureset()
	end

	if not get_lock(LICENSE_NOTIFICATION_LOCK_KEY, LICENSE_NOTIFICATION_INTERVAL) then
		return
	end

	log_license_state(expiration_time, now, konnect_mode)
end

local function report_expired_license(konnect_mode)
	local expiration_time = license_expiration_time(kong.license)

	if expiration_time then
		timer_at(0, license_notification_handler, expiration_time, konnect_mode)
	end
end

_M.report_expired_license = report_expired_license

function _M:license_can_proceed()
	local method = ngx.req.get_method()
	local route = self.route_name
	local allow = kong.licensing.allow_admin_api or EMPTY
	local deny = kong.licensing.deny_admin_api or EMPTY

	if route == "default_route" then
		return
	end

	if deny[route] and (deny[route][method] or deny[route]["*"]) and (not allow[route] or not allow[route][method] and not allow[route]["*"]) then
		return kong.response.exit(403, {
			message = "Enterprise license missing or expired"
		})
	end

	if not license_utils.license_validation_can_proceed() and method ~= "GET" then
		local msg = "license library cannot be loaded"

		ngx.log(ngx.ERR, msg)

		return kong.response.exit(400, {
			message = msg
		})
	end
end

local function validate_kong_license(license)
	return license_utils.validate_kong_license(license)
end

local function is_valid_license(license)
	local result = validate_kong_license(license)

	if result == "ERROR_VALIDATION_PASS" or result == "ERROR_GRACE_PERIOD" or result == "ERROR_LICENSE_EXPIRED" then
		if result ~= "ERROR_VALIDATION_PASS" then
			local message = "The license being added is expired"

			if result == "ERROR_LICENSE_EXPIRED" then
				message = message .. "; some functionality may not be available"
			end

			ngx.log(ngx.WARN, message)
		end

		return true, cjson.decode(license)
	end

	return false, "Unable to validate license: " .. license_utils.validation_error_to_string(result)
end

local function check_portal_and_vitals_allowed(portal_and_vitals_key)
	local license_info = _M.read_license_info()

	if not license_info or not license_info.license or not license_info.license.payload then
		return false
	end

	local license_key = license_info.license.payload.license_key

	if license_key and portal_and_vitals_key then
		local PORTAL_VITALS_SECRET_KEY = "6ZTggSLSREF853ArkiLm94AewPoOEU"
		local gen_str = license_key .. PORTAL_VITALS_SECRET_KEY
		local key = sha256_hex(gen_str)

		if key == portal_and_vitals_key then
			return true
		end
	end

	return false
end

local function portal_and_vitals_allowed()
	local key = kong and kong.configuration and kong.configuration.portal_and_vitals_key
	local allowed, err = kong.cache:get(ee_constants.PORTAL_VITALS_ALLOWED_CACHE_KEY, nil, check_portal_and_vitals_allowed, key)

	if err then
		ngx.log(ngx.ERR, "error occurred while retrieving portal/vitals allowed status from cache", err)

		return false
	end

	if allowed == false then
		if key then
			ngx.log(ngx.ERR, "portal_and_vitals_key is invalid. please contact your support representative.")
		else
			ngx.log(ngx.ERR, "portal and vitals are deprecated")
		end
	end

	return allowed
end

_M.validate_kong_license = validate_kong_license
_M.is_valid_license = is_valid_license
_M.check_portal_and_vitals_allowed = check_portal_and_vitals_allowed
_M.portal_and_vitals_allowed = portal_and_vitals_allowed

return _M
