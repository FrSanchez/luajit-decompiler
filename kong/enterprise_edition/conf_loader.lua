local enterprise_utils = require("kong.enterprise_edition.utils")
local listeners = require("kong.conf_loader.listeners")
local log = require("kong.cmd.utils.log")
local try_decode_base64 = require("kong.tools.utils").try_decode_base64
local pl_stringx = require("pl.stringx")
local pl_path = require("pl.path")
local pl_file = require("pl.file")
local cjson = require("cjson.safe")
local openssl = require("resty.openssl")
local openssl_version = require("resty.openssl.version")
local openssl_x509 = require("resty.openssl.x509")
local openssl_pkey = require("resty.openssl.pkey")
local re_match = ngx.re.match
local concat = table.concat
local EE_PREFIX_PATHS = {
	nginx_portal_api_acc_logs = {
		"logs",
		"portal_api_access.log"
	},
	nginx_portal_api_err_logs = {
		"logs",
		"portal_api_error.log"
	},
	nginx_portal_gui_acc_logs = {
		"logs",
		"portal_gui_access.log"
	},
	nginx_portal_gui_err_logs = {
		"logs",
		"portal_gui_error.log"
	},
	portal_api_ssl_cert_default = {
		"ssl",
		"portal-api-kong-default.crt"
	},
	portal_api_ssl_cert_key_default = {
		"ssl",
		"portal-api-kong-default.key"
	},
	portal_gui_ssl_cert_default_ecdsa = {
		"ssl",
		"portal-gui-kong-default-ecdsa.crt"
	},
	portal_gui_ssl_cert_key_default_ecdsa = {
		"ssl",
		"portal-gui-kong-default-ecdsa.key"
	},
	portal_gui_ssl_cert_default = {
		"ssl",
		"portal-gui-kong-default.crt"
	},
	portal_gui_ssl_cert_key_default = {
		"ssl",
		"portal-gui-kong-default.key"
	},
	portal_api_ssl_cert_default_ecdsa = {
		"ssl",
		"portal-api-kong-default-ecdsa.crt"
	},
	portal_api_ssl_cert_key_default_ecdsa = {
		"ssl",
		"portal-api-kong-default-ecdsa.key"
	}
}
local EE_CONF_INFERENCES = {
	enforce_rbac = {
		enum = {
			"on",
			"off",
			"both",
			"entity"
		}
	},
	rbac_auth_header = {
		typ = "string"
	},
	vitals = {
		typ = "boolean"
	},
	vitals_flush_interval = {
		typ = "number"
	},
	vitals_delete_interval_pg = {
		typ = "number"
	},
	vitals_ttl_seconds = {
		typ = "number"
	},
	vitals_ttl_minutes = {
		typ = "number"
	},
	vitals_ttl_days = {
		typ = "number"
	},
	vitals_strategy = {
		typ = "string"
	},
	vitals_statsd_address = {
		typ = "string"
	},
	vitals_statsd_prefix = {
		typ = "string"
	},
	vitals_statsd_udp_packet_size = {
		typ = "number"
	},
	vitals_tsdb_address = {
		typ = "string"
	},
	vitals_tsdb_user = {
		typ = "string"
	},
	vitals_tsdb_password = {
		typ = "string"
	},
	vitals_prometheus_scrape_interval = {
		typ = "number"
	},
	analytics_flush_interval = {
		typ = "number"
	},
	analytics_buffer_size_limit = {
		typ = "number"
	},
	analytics_debug = {
		typ = "boolean"
	},
	konnect_mode = {
		typ = "boolean"
	},
	audit_log = {
		typ = "boolean"
	},
	audit_log_ignore_methods = {
		typ = "array"
	},
	audit_log_ignore_paths = {
		typ = "array"
	},
	audit_log_ignore_tables = {
		typ = "array"
	},
	audit_log_record_ttl = {
		typ = "number"
	},
	audit_log_signing_key = {
		typ = "string"
	},
	audit_log_payload_exclude = {
		typ = "array"
	},
	admin_gui_flags = {
		typ = "string"
	},
	admin_gui_auth = {
		typ = "string"
	},
	admin_gui_auth_conf = {
		typ = "string"
	},
	admin_gui_auth_header = {
		typ = "string"
	},
	admin_gui_auth_password_complexity = {
		typ = "string"
	},
	admin_gui_session_conf = {
		typ = "string"
	},
	admin_gui_auth_login_attempts = {
		typ = "number"
	},
	admin_emails_from = {
		typ = "string"
	},
	admin_emails_reply_to = {
		typ = "string"
	},
	admin_invitation_expiry = {
		typ = "number"
	},
	admin_gui_ssl_protocols = {
		typ = "string"
	},
	admin_api_uri = {
		typ = "string",
		alias = {
			replacement = "admin_gui_api_url"
		},
		deprecated = {
			replacement = "admin_gui_api_url"
		}
	},
	portal = {
		typ = "boolean"
	},
	portal_and_vitals_key = {
		typ = "string"
	},
	portal_is_legacy = {
		typ = "boolean"
	},
	portal_gui_listen = {
		typ = "array"
	},
	portal_gui_host = {
		typ = "string"
	},
	portal_gui_protocol = {
		typ = "string"
	},
	portal_cors_origins = {
		typ = "array"
	},
	portal_gui_use_subdomains = {
		typ = "boolean"
	},
	portal_session_conf = {
		typ = "string"
	},
	portal_gui_ssl_protocols = {
		typ = "string"
	},
	portal_gui_ssl_cert = {
		typ = "array"
	},
	portal_gui_ssl_cert_key = {
		typ = "array"
	},
	portal_api_access_log = {
		typ = "string"
	},
	portal_api_error_log = {
		typ = "string"
	},
	portal_api_listen = {
		typ = "array"
	},
	portal_api_url = {
		typ = "string"
	},
	portal_app_auth = {
		typ = "string"
	},
	portal_api_ssl_protocols = {
		typ = "string"
	},
	portal_api_ssl_cert = {
		typ = "array"
	},
	portal_api_ssl_cert_key = {
		typ = "array"
	},
	proxy_uri = {
		typ = "string"
	},
	portal_auth = {
		typ = "string"
	},
	portal_auth_password_complexity = {
		typ = "string"
	},
	portal_auth_conf = {
		typ = "string"
	},
	portal_auth_login_attempts = {
		typ = "number"
	},
	portal_token_exp = {
		typ = "number"
	},
	portal_auto_approve = {
		typ = "boolean"
	},
	portal_email_verification = {
		typ = "boolean"
	},
	portal_invite_email = {
		typ = "boolean"
	},
	portal_access_request_email = {
		typ = "boolean"
	},
	portal_approved_email = {
		typ = "boolean"
	},
	portal_reset_email = {
		typ = "boolean"
	},
	portal_reset_success_email = {
		typ = "boolean"
	},
	portal_application_request_email = {
		typ = "boolean"
	},
	portal_application_status_email = {
		typ = "boolean"
	},
	portal_emails_from = {
		typ = "string"
	},
	portal_emails_reply_to = {
		typ = "string"
	},
	portal_smtp_admin_emails = {
		typ = "array"
	},
	smtp_host = {
		typ = "string"
	},
	smtp_port = {
		typ = "number"
	},
	smtp_starttls = {
		typ = "boolean"
	},
	smtp_username = {
		typ = "string"
	},
	smtp_password = {
		typ = "string"
	},
	smtp_ssl = {
		typ = "boolean"
	},
	smtp_auth_type = {
		typ = "string"
	},
	smtp_domain = {
		typ = "string"
	},
	smtp_timeout_connect = {
		typ = "number"
	},
	smtp_timeout_send = {
		typ = "number"
	},
	smtp_timeout_read = {
		typ = "number"
	},
	smtp_admin_emails = {
		typ = "array"
	},
	smtp_mock = {
		typ = "boolean"
	},
	tracing = {
		typ = "boolean"
	},
	tracing_write_strategy = {
		enum = {
			"file",
			"file_raw",
			"tcp",
			"tls",
			"udp",
			"http"
		}
	},
	tracing_write_endpoint = {
		typ = "string"
	},
	tracing_time_threshold = {
		typ = "number"
	},
	tracing_types = {
		typ = "array"
	},
	tracing_debug_header = {
		typ = "string"
	},
	generate_trace_details = {
		typ = "boolean"
	},
	keyring_enabled = {
		typ = "boolean"
	},
	keyring_blob_path = {
		typ = "string"
	},
	keyring_public_key = {
		typ = "string"
	},
	keyring_private_key = {
		typ = "string"
	},
	keyring_recovery_public_key = {
		typ = "string"
	},
	keyring_strategy = {
		enum = {
			"cluster",
			"vault"
		}
	},
	keyring_vault_host = {
		typ = "string"
	},
	keyring_vault_mount = {
		typ = "string"
	},
	keyring_vault_path = {
		typ = "string"
	},
	keyring_vault_token = {
		typ = "string"
	},
	keyring_vault_auth_method = {
		enum = {
			"token",
			"kubernetes"
		}
	},
	keyring_vault_kube_role = {
		typ = "string"
	},
	keyring_vault_kube_api_token_file = {
		typ = "string"
	},
	event_hooks_enabled = {
		typ = "boolean"
	},
	route_validation_strategy = {
		enum = {
			"smart",
			"path",
			"off",
			"static"
		}
	},
	enforce_route_path_pattern = {
		typ = "string"
	},
	cluster_telemetry_listen = {
		typ = "array"
	},
	cluster_telemetry_server_name = {
		typ = "string"
	},
	cluster_telemetry_endpoint = {
		typ = "string"
	},
	admin_gui_header_txt = {
		typ = "string"
	},
	admin_gui_header_bg_color = {
		typ = "string"
	},
	admin_gui_header_txt_color = {
		typ = "string"
	},
	admin_gui_footer_txt = {
		typ = "string"
	},
	admin_gui_footer_bg_color = {
		typ = "string"
	},
	admin_gui_footer_txt_color = {
		typ = "string"
	},
	admin_gui_login_banner_title = {
		typ = "string"
	},
	admin_gui_login_banner_body = {
		typ = "string"
	},
	fips = {
		typ = "boolean"
	},
	pg_iam_auth = {
		typ = "boolean"
	},
	pg_ro_iam_auth = {
		typ = "boolean"
	}
}
local EE_CONF_SENSITIVE = {
	portal_auth_conf = true,
	portal_api_ssl_cert_key = true,
	admin_gui_session_conf = true,
	keyring_recovery_public_key = true,
	admin_gui_auth_header = true,
	admin_gui_auth_conf = true,
	keyring_private_key = true,
	vitals_tsdb_password = true,
	vault_hcv_token = true,
	portal_gui_ssl_cert_key = true,
	smtp_password = true,
	portal_session_conf = true
}

local function parse_option_flags(value, flags)
	assert(type(value) == "string")

	value = " " .. value .. " "
	local sanitized = ""
	local result = {}

	for _, flag in ipairs(flags) do
		local count = nil
		local patt = "%s" .. flag .. "%s"
		value, count = value:gsub(patt, " ")

		if count > 0 then
			result[flag] = true
			sanitized = sanitized .. " " .. flag
		else
			result[flag] = false
		end
	end

	return pl_stringx.strip(value), result, pl_stringx.strip(sanitized)
end

local function validate_admin_gui_authentication(conf, errors)
	if conf.admin_gui_auth then
		if conf.admin_gui_auth ~= "key-auth" and conf.admin_gui_auth ~= "basic-auth" and conf.admin_gui_auth ~= "ldap-auth-advanced" and conf.admin_gui_auth ~= "openid-connect" then
			errors[#errors + 1] = "admin_gui_auth must be 'key-auth', 'basic-auth', " .. "'ldap-auth-advanced', 'openid-connect' or not set"
		end

		if not conf.enforce_rbac or conf.enforce_rbac == "off" then
			errors[#errors + 1] = "enforce_rbac must be enabled when " .. "admin_gui_auth is enabled"
		end
	end

	if conf.admin_gui_auth_conf and conf.admin_gui_auth_conf ~= "" then
		if not conf.admin_gui_auth or conf.admin_gui_auth == "" then
			errors[#errors + 1] = "admin_gui_auth_conf is set with no admin_gui_auth"
		end

		local auth_config, err = cjson.decode(tostring(conf.admin_gui_auth_conf))

		if err then
			errors[#errors + 1] = "admin_gui_auth_conf must be valid json or not set: " .. err .. " - " .. conf.admin_gui_auth_conf
		else
			if conf.admin_gui_auth == "openid-connect" then
				if not auth_config.admin_claim then
					errors[#errors + 1] = "admin_gui_auth_conf must contains 'admin_claim' " .. "when admin_gui_auth='openid-connect'"
				end

				if auth_config.admin_claim and type(auth_config.admin_claim) ~= "string" then
					errors[#errors + 1] = "admin_claim must be a string"
				end

				if auth_config.admin_by and auth_config.admin_by ~= "username" then
					errors[#errors + 1] = "admin_by only supports value with 'username'"
				end

				if auth_config.authenticated_groups_claim and #auth_config.authenticated_groups_claim > 1 then
					errors[#errors + 1] = "authenticated_groups_claim only supports 1 claim"
				end

				if auth_config.admin_auto_create_rbac_token_disabled and type(auth_config.admin_auto_create_rbac_token_disabled) ~= "boolean" then
					errors[#errors + 1] = "admin_auto_create_rbac_token_disabled must be a boolean"
				end

				if auth_config.admin_auto_create and type(auth_config.admin_auto_create) ~= "boolean" then
					errors[#errors + 1] = "admin_auto_create must be boolean"
				end
			end

			conf.admin_gui_auth_conf = auth_config

			setmetatable(conf.admin_gui_auth_conf, {
				__tostring = function (v)
					return assert(cjson.encode(v))
				end
			})
		end
	end

	local keyword = "admin_gui_auth_password_complexity"

	if conf[keyword] and conf[keyword] ~= "" then
		if not conf.admin_gui_auth or conf.admin_gui_auth ~= "basic-auth" then
			errors[#errors + 1] = keyword .. " is set without basic-auth"
		end

		local auth_password_complexity, err = cjson.decode(tostring(conf[keyword]))

		if err then
			errors[#errors + 1] = keyword .. " must be valid json or not set: " .. err .. " - " .. conf[keyword]
		else
			conf[keyword] = auth_password_complexity

			setmetatable(conf[keyword], {
				__tostring = function (v)
					return assert(cjson.encode(v))
				end
			})
		end
	end
end

local function validate_admin_gui_session(conf, errors)
	if conf.admin_gui_session_conf then
		if not conf.admin_gui_auth or conf.admin_gui_auth == "" then
			errors[#errors + 1] = "admin_gui_session_conf is set with no admin_gui_auth"
		end

		local session_config, err = cjson.decode(tostring(conf.admin_gui_session_conf))

		if err then
			errors[#errors + 1] = "admin_gui_session_conf must be valid json or not set: " .. err .. " - " .. conf.admin_gui_session_conf
		else
			if not session_config.storage or session_config.storage == "" then
				session_config.storage = "kong"
			end

			conf.admin_gui_session_conf = session_config

			setmetatable(conf.admin_gui_session_conf, {
				__tostring = function (v)
					return assert(cjson.encode(v))
				end
			})
		end
	elseif conf.admin_gui_auth or conf.admin_gui_auth == "" then
		errors[#errors + 1] = "admin_gui_session_conf must be set when admin_gui_auth is enabled"
	end
end

local function validate_portal_cors_origins(conf, errors)
	for _, origin in ipairs(conf.portal_cors_origins) do
		if origin ~= "*" then
			local _, err = re_match("any string", origin)

			if err then
				errors[#errors + 1] = "portal_cors_origins: '" .. origin .. "' is not a valid regex"
			end
		end
	end
end

local function validate_portal_session(conf, errors)
	if conf.portal_session_conf then
		local session_config, err = cjson.decode(tostring(conf.portal_session_conf))

		if err then
			errors[#errors + 1] = "portal_session_conf must be valid json or not set: " .. err .. " - " .. conf.portal_session_conf
		else
			if type(session_config.secret) ~= "string" then
				errors[#errors + 1] = "portal_session_conf 'secret' must be type 'string'"
			end

			conf.portal_session_conf = session_config

			setmetatable(conf.portal_session_conf, {
				__tostring = function (v)
					return assert(cjson.encode(v))
				end
			})
		end
	elseif conf.portal_auth and conf.portal_auth ~= "" and conf.portal_auth ~= "openid-connect" then
		errors[#errors + 1] = "portal_session_conf is required when portal_auth is set to " .. conf.portal_auth
	end
end

local function validate_portal_auth_password_complexity(conf, errors)
	local keyword = "portal_auth_password_complexity"

	if conf[keyword] and conf[keyword] ~= "" then
		if not conf.portal_auth or conf.portal_auth ~= "basic-auth" then
			errors[#errors + 1] = keyword .. " is set without basic-auth"
		end

		local auth_password_complexity, err = cjson.decode(tostring(conf[keyword]))

		if err then
			errors[#errors + 1] = keyword .. " must be valid json or not set: " .. err .. " - " .. conf[keyword]
		else
			conf[keyword] = auth_password_complexity

			setmetatable(conf[keyword], {
				__tostring = function (v)
					return assert(cjson.encode(v))
				end
			})
		end
	end
end

local function validate_portal_app_auth(conf, errors)
	local portal_app_auth = conf.portal_app_auth

	if not portal_app_auth or portal_app_auth == "" then
		return
	end

	if portal_app_auth ~= "kong-oauth2" and portal_app_auth ~= "external-oauth2" then
		errors[#errors + 1] = "portal_app_auth must be not set or one of: kong-oauth2, external-oauth2"
	end
end

local function validate_ssl(prefix, conf, errors)
	local listen = conf[prefix .. "listen"]
	local ssl_enabled = (concat(listen, ",") .. " "):find("%sssl[%s,]") ~= nil

	if not ssl_enabled and prefix == "proxy_" then
		ssl_enabled = (concat(conf.stream_listen, ",") .. " "):find("%sssl[%s,]") ~= nil
	end

	if ssl_enabled then
		conf.ssl_enabled = true
		local ssl_cert = conf[prefix .. "ssl_cert"]
		local ssl_cert_key = conf[prefix .. "ssl_cert_key"]

		if #ssl_cert > 0 and #ssl_cert_key == 0 then
			errors[#errors + 1] = prefix .. "ssl_cert_key must be specified"
		elseif #ssl_cert_key > 0 and #ssl_cert == 0 then
			errors[#errors + 1] = prefix .. "ssl_cert must be specified"
		elseif #ssl_cert ~= #ssl_cert_key then
			errors[#errors + 1] = prefix .. "ssl_cert was specified " .. #ssl_cert .. " times while " .. prefix .. "ssl_cert_key was specified " .. #ssl_cert_key .. " times"
		end

		if ssl_cert then
			for i, cert in ipairs(ssl_cert) do
				if not pl_path.exists(cert) then
					cert = try_decode_base64(cert)
					ssl_cert[i] = cert
					local _, err = openssl_x509.new(cert)

					if err then
						errors[#errors + 1] = prefix .. "ssl_cert: failed loading certificate from " .. cert
					end
				end
			end

			conf[prefix .. "ssl_cert"] = ssl_cert
		end

		if ssl_cert_key then
			for i, cert_key in ipairs(ssl_cert_key) do
				if not pl_path.exists(cert_key) then
					cert_key = try_decode_base64(cert_key)
					ssl_cert_key[i] = cert_key
					local _, err = openssl_pkey.new(cert_key)

					if err then
						errors[#errors + 1] = prefix .. "ssl_cert_key: failed loading key from " .. cert_key
					end
				end
			end

			conf[prefix .. "ssl_cert_key"] = ssl_cert_key
		end
	end
end

local function validate_portal_ssl(conf, errors)
	validate_ssl("portal_api_", conf, errors)
	validate_ssl("portal_gui_", conf, errors)
end

local function validate_email(email, key, errors)
	local ok, err = enterprise_utils.validate_email(email)

	if not ok then
		errors[#errors + 1] = key .. " is invalid: " .. err
	end
end

local function validate_smtp_config(conf, errors)
	if conf.smtp_auth_type ~= nil then
		if conf.smtp_auth_type ~= "plain" and conf.smtp_auth_type ~= "login" then
			errors[#errors + 1] = "smtp_auth_type must be 'plain', 'login', or nil"
		end

		if conf.smtp_username == nil or conf.smtp_username == "" then
			errors[#errors + 1] = "smtp_username must be set when using smtp_auth_type"
		end

		if conf.smtp_password == nil or conf.smtp_password == "" then
			errors[#errors + 1] = "smtp_password must be set when using smtp_auth_type"
		end
	end
end

local function validate_portal_smtp_config(conf, errors)
	local portal_token_exp = conf.portal_token_exp

	if type(portal_token_exp) ~= "number" or portal_token_exp < 1 then
		errors[#errors + 1] = "portal_token_exp must be a positive number"
	end

	local smtp_admin_emails = conf.portal_smtp_admin_emails
	local smtp_admin_emails_error_key = "portal_smtp_admin_emails"

	if next(conf.portal_smtp_admin_emails) == nil then
		smtp_admin_emails = conf.smtp_admin_emails
		smtp_admin_emails_error_key = "smtp_admin_emails"
	end

	if conf.smtp_mock then
		if next(smtp_admin_emails) == nil then
			conf.smtp_admin_emails = {
				"admin@example.com"
			}
		end

		return
	end

	if not conf.admin_gui_url or conf.admin_gui_url == "" then
		errors[#errors + 1] = "admin_gui_url is required for portal"
	end

	validate_email(conf.portal_emails_from, "portal_emails_from", errors)
	validate_email(conf.portal_emails_reply_to, "portal_emails_reply_to", errors)
	validate_email(conf.portal_emails_from, "portal_emails_from", errors)

	if next(smtp_admin_emails) == nil then
		errors[#errors + 1] = "smtp_admin_emails or portal_smtp_admin_emails is required for portal"
	else
		for _, email in ipairs(smtp_admin_emails) do
			validate_email(email, smtp_admin_emails_error_key, errors)
		end
	end
end

local function validate_vitals_tsdb(conf, errors)
	if conf.vitals_strategy == "prometheus" or conf.vitals_strategy == "influxdb" then
		if not conf.vitals_tsdb_address then
			errors[#errors + 1] = "vitals_tsdb_address must be defined when " .. "vitals_strategy = \"prometheus\" or \"influxdb\""
		end

		if not conf.vitals_statsd_address and conf.vitals_strategy == "prometheus" then
			errors[#errors + 1] = "vitals_statsd_address must be defined " .. "when vitals_strategy is set to \"prometheus\""
		end
	elseif conf.vitals_strategy ~= "database" then
		errors[#errors + 1] = "vitals_strategy must be one of " .. "\"database\", \"prometheus\", or \"influxdb\""
	end

	if conf.vitals_tsdb_address then
		local host, port = nil
		host, port = conf.vitals_tsdb_address:match("(.+):([%d]+)$")
		port = tonumber(port)

		if not host or not port then
			errors[#errors + 1] = "vitals_tsdb_address must be of form: <ip>:<port>"
		else
			conf.vitals_tsdb_host = host
			conf.vitals_tsdb_port = port
		end
	end

	if conf.vitals_statsd_address then
		local host, port = nil
		local remainder, _, _ = parse_option_flags(conf.vitals_statsd_address, {
			"udp",
			"tcp"
		})

		if remainder then
			host, port = remainder:match("(.+):([%d]+)$")
			port = tonumber(port)

			if not host or not port then
				host = remainder:match("(unix:/.+)$")
			end
		end

		if not host then
			errors[#errors + 1] = "vitals_statsd_address must be of form: <ip>:<port> [udp|tcp]"
		end
	end

	if conf.vitals_statsd_udp_packet_size <= 0 or conf.vitals_statsd_udp_packet_size > 65507 then
		errors[#errors + 1] = "vitals_statsd_udp_packet_size must be an positive integer and no larger than 65507"
	end

	if conf.vitals_prometheus_scrape_interval <= 0 then
		errors[#errors + 1] = "vitals_prometheus_scrape_interval must be an positive integer"
	end

	return errors
end

local function validate_rsa(conf, conf_key, private, errors)
	local rsa_key = conf[conf_key]

	if rsa_key then
		local key_pem, err = nil

		if not pl_path.exists(rsa_key) then
			key_pem = try_decode_base64(rsa_key)
			conf[conf_key] = key_pem
		else
			key_pem, err = pl_file.read(rsa_key)
		end

		if err then
			errors[#errors + 1] = "failed to read " .. conf_key .. " file: " .. err
		else
			local pkey = nil
			pkey, err = openssl_pkey.new(key_pem)

			if err then
				errors[#errors + 1] = "failed to parse " .. conf_key .. "file: " .. err
			elseif pkey:is_private() and not private then
				errors[#errors + 1] = conf_key .. "file must be a public key"
			elseif not pkey:is_private() and private then
				errors[#errors + 1] = conf_key .. "file must be a private key"
			elseif pkey:get_key_type().sn ~= "rsaEncryption" then
				errors[#errors + 1] = conf_key .. "file must be a RSA key"
			end
		end
	end
end

local function validate_keyring(conf, errors)
	if conf.keyring_enabled then
		validate_rsa(conf, "keyring_recovery_public_key", false, errors)
		validate_rsa(conf, "keyring_public_key", false, errors)
		validate_rsa(conf, "keyring_private_key", true, errors)
	end
end

local function add_ee_required_plugins(conf)
	local seen_plugins = {}

	for _, plugin in ipairs(conf.plugins) do
		if plugin == "bundled" then
			return
		end

		seen_plugins[plugin] = true
	end

	local required_plugins = {
		"cors",
		"session"
	}

	if conf.admin_gui_auth and conf.admin_gui_auth ~= "" then
		required_plugins[#required_plugins + 1] = conf.admin_gui_auth
	end

	if conf.portal then
		required_plugins[#required_plugins + 1] = "basic-auth"
		required_plugins[#required_plugins + 1] = "key-auth"
	end

	for _, required_plugin in ipairs(required_plugins) do
		if not seen_plugins[required_plugin] then
			conf.plugins[#conf.plugins + 1] = required_plugin
		end
	end
end

local function validate_tracing(conf, errors)
	if conf.tracing and not conf.tracing_write_endpoint then
		errors[#errors + 1] = "'tracing_write_endpoint' must be defined when " .. "'tracing' is enabled"
	end
end

local function validate_route_path_pattern(conf, errors)
	local pattern = conf.enforce_route_path_pattern

	if conf.route_validation_strategy == "path" then
		if not pattern then
			errors[#errors + 1] = "'enforce_route_path_pattern'is required when" .. "'route_validation_strategy' is set to 'path'"

			return
		end

		if not string.match(pattern, "^/[%w%.%-%_~%/%%%$%(%)%*]*$") then
			errors[#errors + 1] = "invalid path pattern: '" .. pattern
		end
	end
end

local function validate_enforce_rbac(conf)
	if conf.enforce_rbac == "off" ~= not conf.admin_gui_auth then
		return nil, "RBAC authorization is " .. conf.enforce_rbac .. " and admin_gui_auth is '" .. tostring(conf.admin_gui_auth) .. "'"
	end

	return true
end

local function validate_fips(conf, errors)
	if not conf.fips then
		return
	end

	local licensing = require("kong.enterprise_edition.licensing")
	local license = licensing(conf)
	conf.ssl_cipher_suite = "fips"

	if conf.fips and license.l_type == "free" then
		ngx.log(ngx.WARN, "Kong is started without a valid license while FIPS mode is set. " .. "Kong will not operate in FIPS mode until a license is received from " .. "Control Plane. Please reach out to Kong if you are interested in " .. "using Kong FIPS compliant artifacts. ")
	else
		log.debug("enabling FIPS mode on %s (%s)", openssl_version.version_text, openssl_version.version(openssl_version.CFLAGS))

		local ok, err = openssl.set_fips_mode(true)

		if not ok or not openssl.get_fips_mode() then
			errors[#errors + 1] = "cannot enable FIPS mode: " .. (err or "nil")
		end
	end

	return errors
end

local function validate_postgres_iam_auth(conf, errors)
	if conf.pg_iam_auth then
		conf.pg_ssl = true
		conf.pg_ssl_required = true
	end

	if conf.pg_ssl and conf.pg_iam_auth and (conf.pg_ssl_cert or conf.pg_ssl_cert_key) then
		errors[#errors + 1] = "mTLS connection to postgres cannot be used " .. "when pg_iam_auth is enabled, so pg_ssl_cert " .. "and pg_ssl_cert_key must not be specified"
	end

	if conf.pg_ro_iam_auth then
		conf.pg_ro_ssl = true
		conf.pg_ro_ssl_required = true
	end

	if conf.pg_ro_iam_auth and conf.pg_ro_ssl and (conf.pg_ssl_cert or conf.pg_ssl_cert_key) then
		errors[#errors + 1] = "mTLS connection to postgres cannot be used " .. "when pg_ro_iam_auth is enabled, so pg_ssl_cert " .. "and pg_ssl_cert_key must not be specified"
	end
end

local function validate(conf, errors)
	validate_admin_gui_authentication(conf, errors)
	validate_admin_gui_session(conf, errors)

	if not conf.smtp_mock then
		validate_smtp_config(conf, errors)
	end

	if conf.portal then
		validate_portal_smtp_config(conf, errors)
		validate_portal_session(conf, errors)
		validate_portal_auth_password_complexity(conf, errors)
		validate_portal_app_auth(conf, errors)

		local portal_gui_host = conf.portal_gui_host

		if not portal_gui_host or portal_gui_host == "" then
			errors[#errors + 1] = "portal_gui_host is required for portal"
		end

		local portal_gui_protocol = conf.portal_gui_protocol

		if not portal_gui_protocol or portal_gui_protocol == "" then
			errors[#errors + 1] = "portal_gui_protocol is required for portal"
		end

		validate_portal_cors_origins(conf, errors)
	end

	validate_vitals_tsdb(conf, errors)
	add_ee_required_plugins(conf)
	validate_tracing(conf, errors)
	validate_route_path_pattern(conf, errors)

	if conf.portal then
		validate_portal_ssl(conf, errors)
	end

	if conf.portal_auth and conf.portal_auth_conf then
		conf.portal_auth_conf = string.gsub(conf.portal_auth_conf, "#", "\\#")
		local json, err = cjson.decode(tostring(conf.portal_auth_conf))

		if json then
			conf.portal_auth_conf = json

			setmetatable(conf.portal_auth_conf, {
				__tostring = function (v)
					return assert(cjson.encode(v))
				end
			})
		end

		if err then
			errors[#errors + 1] = "portal_auth_conf must be valid json: " .. err .. " - " .. conf.portal_auth_conf
		end
	end

	if conf.audit_log_signing_key then
		local k = pl_path.abspath(conf.audit_log_signing_key)
		local p, err = openssl_pkey.new(pl_file.read(k), {
			format = "PEM",
			type = "pr"
		})

		if not p then
			errors[#errors + 1] = "audit_log_signing_key: invalid RSA private key (" .. err .. ")"
		end

		conf.audit_log_signing_key = k
	end

	if conf.admin_gui_auth and not conf.admin_gui_url then
		log.warn("when admin_gui_auth is set, admin_gui_url is required")
	end

	local ssl_on = (table.concat(conf.admin_listen, ",") .. " "):find("%sssl[%s,]")

	if conf.enforce_rbac ~= "off" and not ssl_on then
		log.warn("RBAC authorization is enabled but Admin API calls will not be " .. "encrypted via SSL")
	end

	local ok, err = validate_enforce_rbac(conf)

	if not ok then
		log.warn(err)
	end

	if conf.role == "control_plane" and (#conf.cluster_telemetry_listen < 1 or pl_stringx.strip(conf.cluster_telemetry_listen[1]) == "off") then
		errors[#errors + 1] = "cluster_telemetry_listen must be specified when role = \"control_plane\""
	end

	validate_keyring(conf, errors)
	validate_fips(conf, errors)
	validate_postgres_iam_auth(conf, errors)

	if conf.role ~= "data_plane" and conf.route_validation_strategy == "static" and conf.database ~= "postgres" then
		errors[#errors + 1] = "static route_validation_strategy is currently " .. "only supported with a PostgreSQL database"
	end
end

local function load_ssl_cert_abs_paths(prefix, conf)
	local ssl_cert = conf[prefix .. "_cert"]
	local ssl_cert_key = conf[prefix .. "_cert_key"]

	if ssl_cert and ssl_cert_key then
		if type(ssl_cert) == "table" then
			for i, cert in ipairs(ssl_cert) do
				if pl_path.exists(cert) then
					ssl_cert[i] = pl_path.abspath(cert)
				end
			end
		elseif pl_path.exists(ssl_cert) then
			conf[prefix .. "_cert"] = pl_path.abspath(ssl_cert)
		end

		if type(ssl_cert_key) == "table" then
			for i, key in ipairs(ssl_cert_key) do
				if pl_path.exists(key) then
					ssl_cert_key[i] = pl_path.abspath(key)
				end
			end
		elseif pl_path.exists(ssl_cert_key) then
			conf[prefix .. "_cert_key"] = pl_path.abspath(ssl_cert_key)
		end
	end
end

local function load(conf)
	local ok, err = listeners.parse(conf, {
		{
			subsystem = "http",
			name = "cluster_telemetry_listen"
		}
	})

	if not ok then
		return nil, err
	end

	if conf.portal then
		ok, err = listeners.parse(conf, {
			{
				subsystem = "http",
				ssl_flag = "portal_gui_ssl_enabled",
				name = "portal_gui_listen"
			},
			{
				subsystem = "http",
				ssl_flag = "portal_api_ssl_enabled",
				name = "portal_api_listen"
			}
		})

		if not ok then
			return nil, err
		end

		load_ssl_cert_abs_paths("portal_api_ssl", conf)
		load_ssl_cert_abs_paths("portal_gui_ssl", conf)
	end

	conf.rbac = conf.enforce_rbac

	return true
end

local function add(dst, src)
	for k, v in pairs(src) do
		dst[k] = v
	end
end

return {
	EE_PREFIX_PATHS = EE_PREFIX_PATHS,
	EE_CONF_INFERENCES = EE_CONF_INFERENCES,
	EE_CONF_SENSITIVE = EE_CONF_SENSITIVE,
	validate = validate,
	load = load,
	add = add,
	validate_enforce_rbac = validate_enforce_rbac,
	validate_admin_gui_authentication = validate_admin_gui_authentication,
	validate_admin_gui_session = validate_admin_gui_session,
	validate_smtp_config = validate_smtp_config,
	validate_portal_smtp_config = validate_portal_smtp_config,
	validate_portal_cors_origins = validate_portal_cors_origins,
	validate_tracing = validate_tracing,
	validate_route_path_pattern = validate_route_path_pattern,
	validate_portal_app_auth = validate_portal_app_auth,
	validate_fips = validate_fips,
	validate_keyring = validate_keyring,
	validate_portal_ssl = validate_portal_ssl
}
