local passwdqc = require("resty.passwdqc")
local basicauth_crypto = require("kong.plugins.basic-auth.crypto")
local kong = kong
local null = ngx.null
local _M = {}
local LOGIN_ATTEMPTS_TTL = 604800
local LOGIN_ATTEMPTS_IP = "127.0.0.1"
local PASSWD_COMPLEXITY_PRESET = {
	min_8 = {
		min = "disabled,disabled,8,8,8"
	},
	min_12 = {
		min = "disabled,disabled,12,12,12"
	},
	min_20 = {
		min = "disabled,disabled,20,20,20"
	}
}

function _M.check_password_complexity(new_pass, old_pass, opts)
	opts = PASSWD_COMPLEXITY_PRESET[opts["kong-preset"]] or opts

	return passwdqc.check(new_pass, old_pass, opts)
end

function _M.plugin_res_handler(plugin_res, entity, max)
	if type(plugin_res) == "table" and plugin_res.status == 401 then
		local _, err = _M.unauthorized_login_attempt(entity, max)

		if err then
			kong.response.exit(500, {
				message = "An unexpected error occurred"
			})
		end

		kong.response.exit(plugin_res.status, {
			message = plugin_res.message
		})
	end

	local _, err = _M.successful_login_attempt(entity, max)

	if err then
		kong.response.exit(500, {
			message = "An unexpected error occurred"
		})
	end
end

function _M.unauthorized_login_attempt(entity, max)
	if max == 0 then
		return
	end

	local login_attempts = kong.db.login_attempts
	local consumer = entity.consumer
	local attempt, err = login_attempts:select({
		consumer = consumer
	})

	if err then
		kong.log.err("error fetching login_attempts", err)

		return nil, err
	end

	if not attempt then
		local _, err = login_attempts:insert({
			consumer = consumer,
			attempts = {
				[LOGIN_ATTEMPTS_IP] = 1
			}
		}, {
			ttl = LOGIN_ATTEMPTS_TTL
		})

		if err then
			kong.log.err("error inserting login_attempts", err)

			return nil, err
		end

		return
	end

	attempt.attempts[LOGIN_ATTEMPTS_IP] = (attempt.attempts[LOGIN_ATTEMPTS_IP] or 0) + 1
	local _, err = login_attempts:update({
		consumer = consumer
	}, {
		attempts = attempt.attempts
	})

	if err then
		kong.log.err("error updating login_attempts", err)

		return nil, err
	end

	if max <= attempt.attempts[LOGIN_ATTEMPTS_IP] then
		local user = entity.username or entity.email

		kong.log.warn("Unauthorized: login attempts exceed max for user " .. user)
	end
end

function _M.successful_login_attempt(entity, max)
	if max == 0 then
		return
	end

	local login_attempts = kong.db.login_attempts
	local consumer = entity.consumer
	local attempt, err = login_attempts:select({
		consumer = consumer
	})

	if err then
		kong.log.err("error fetching login_attempts", err)

		return nil, err
	end

	if not attempt or not attempt.attempts[LOGIN_ATTEMPTS_IP] then
		return
	end

	if max <= attempt.attempts[LOGIN_ATTEMPTS_IP] then
		local user = entity.username or entity.email

		kong.log.warn("Authorized: login attempts exceed max for user " .. user)
		kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	local _, err = login_attempts:delete({
		consumer = consumer
	})

	if err then
		kong.log.err("error updating login_attempts", err)

		return nil, err
	end
end

function _M.reset_attempts(consumer)
	local _, err = kong.db.login_attempts:delete({
		consumer = consumer
	})

	if err then
		kong.log.err("error resetting attempts", err)

		return nil, err
	end
end

function _M.verify_password(user, old_password, new_password)
	if not old_password then
		return nil, "Must include old_password"
	end

	if not new_password or new_password == old_password then
		return nil, "Passwords cannot be the same"
	end

	local creds, err = kong.db.basicauth_credentials:page_for_consumer(user.consumer, nil, , {
		workspace = null
	})

	if err then
		return nil, , err
	end

	if creds[1] then
		local digest, err = basicauth_crypto.hash(creds[1].consumer.id, old_password)

		if err then
			kong.log.err(err)

			return nil, , err
		end

		local valid = creds[1].password == digest

		if not valid then
			return nil, "Old password is invalid"
		end

		return creds[1]
	end

	return nil, "Bad request"
end

return _M
