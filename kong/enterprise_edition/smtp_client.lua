local mail = require("resty.mail")
local enterprise_utils = require("kong.enterprise_edition.utils")
local pl_tablex = require("pl.tablex")
local log = ngx.log
local INFO = ngx.INFO
local _M = {}
local mt = {
	__index = _M
}
_M.INVALID_EMAIL = "Invalid email"
_M.SEND_ERR = "Error sending email"
_M.LOG_PREFIX = "[smtp-client]"

function _M.new(conf, smtp_mock)
	conf = conf or {}
	local mailer, err = nil

	if smtp_mock then
		mailer = {
			send = function ()
				return true
			end
		}
	else
		mailer, err = mail.new(conf)

		if err then
			return nil, err
		end
	end

	local self = {
		mailer = mailer,
		smtp_mock = smtp_mock
	}

	return setmetatable(self, mt)
end

function _M.handle_res(res)
	local code = res.code
	res.code = nil

	if res.sent.count < 1 then
		return nil, {
			message = res,
			code = code or 500
		}
	end

	return res
end

function _M:send(emails, base_options, res)
	local res = res or self:init_email_res()
	local emails_to_send = {}
	local seen_emails = {}
	local sent = res.sent
	local error = res.error

	for _, email in ipairs(emails) do
		if not seen_emails[email] and not sent.emails[email] and not error.emails[email] then
			local ok, err = enterprise_utils.validate_email(email)

			if not ok then
				log(INFO, _M.LOG_PREFIX, _M.INVALID_EMAIL .. ": " .. email .. ": " .. err)

				error.emails[email] = _M.INVALID_EMAIL .. ": " .. err
				error.count = error.count + 1
			else
				table.insert(emails_to_send, email)
			end

			seen_emails[email] = true
		end
	end

	if next(emails_to_send) == nil then
		res.code = 400

		return res
	end

	local send_options = pl_tablex.union({
		to = emails_to_send
	}, base_options)
	local ok, err = self.mailer:send(send_options)

	for _, email in pairs(emails_to_send) do
		if not ok then
			log(INFO, _M.LOG_PREFIX, _M.SEND_ERR .. ": " .. email .. ": " .. err)

			error.emails[email] = _M.SEND_ERR
			error.count = error.count + 1
		else
			sent.emails[email] = true
			sent.count = sent.count + 1
		end
	end

	return res
end

function _M:init_email_res()
	local res = {
		sent = {
			count = 0,
			emails = {}
		},
		error = {
			count = 0,
			emails = {}
		}
	}

	if self.smtp_mock then
		res.smtp_mock = true
	end

	return res
end

function _M.new_smtp_client(conf)
	return _M.new({
		host = conf.smtp_host,
		port = conf.smtp_port,
		starttls = conf.smtp_starttls,
		ssl = conf.smtp_ssl,
		username = conf.smtp_username,
		password = conf.smtp_password,
		auth_type = conf.smtp_auth_type,
		domain = conf.smtp_domain,
		timeout_connect = conf.smtp_timeout_connect,
		timeout_send = conf.smtp_timeout_send,
		timeout_read = conf.smtp_timeout_read
	}, conf.smtp_mock)
end

return _M
