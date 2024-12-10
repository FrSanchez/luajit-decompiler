local app_helpers = require("lapis.application")
local endpoints = require("kong.api.endpoints")
local enums = require("kong.enterprise_edition.dao.enums")
local rbac = require("kong.rbac")
local workspaces = require("kong.workspaces")
local utils = require("kong.tools.utils")
local ee_utils = require("kong.enterprise_edition.utils")
local ee_jwt = require("kong.enterprise_edition.jwt")
local errors = require("kong.db.errors")
local entity = require("kong.db.schema.entity")
local ws_schema = require("kong.db.schema.entities.workspaces")
local fmt = string.format
local kong = kong
local log = ngx.log
local ERR = ngx.ERR
local DEBUG = ngx.DEBUG
local NOTICE = ngx.NOTICE
local unescape_uri = ngx.unescape_uri
local get_with_cache = rbac.get_with_cache
local _M = {}
local _log_prefix = "[api_helpers] "
_M.apis = {
	ADMIN = "admin",
	PORTAL = "portal"
}
local auth_whitelisted_uris = {
	["/auth"] = true,
	["/admins/password_resets"] = true,
	["/admins/register"] = true
}

local function find_admin_ignore_case(user_name)
	local admins, err = kong.db.admins:select_by_username_ignore_case(user_name)

	if err then
		log(DEBUG, _log_prefix, "Admin not found with user_name=" .. user_name)

		return nil, err
	end

	if #admins > 1 then
		local match_info = {}

		for _, match in pairs(admins) do
			table.insert(match_info, fmt("%s (id: %s)", match.username, match.id))
		end

		log(NOTICE, _log_prefix, fmt("Multiple Admins match '%s' case-insensitively: %s", user_name, table.concat(match_info, ", ")))
	end

	local admin = admins[1]

	if admin then
		admin, err = kong.db.admins:select({
			id = admin.id
		}, {
			skip_rbac = true
		})
	end

	return admin, err
end

function _M.get_consumer_status(consumer)
	local status = nil

	if consumer.type == enums.CONSUMERS.TYPE.DEVELOPER then
		local developer = kong.db.developers:select_by_email(consumer.email)
		status = developer.status
	end

	return {
		status = status,
		label = enums.CONSUMERS.STATUS_LABELS[status]
	}
end

function _M.retrieve_consumer(consumer_id)
	local consumer, err = kong.db.consumers:select({
		id = consumer_id
	}, {
		show_ws_id = true
	})

	if err then
		log(ERR, "error in retrieving consumer:" .. consumer_id, err)

		return nil, err
	end

	return consumer or nil
end

function _M.validate_admin(ignore_case, user_name, custom_id)
	if not user_name then
		local user_header = kong.configuration.admin_gui_auth_header
		local args = ngx.req.get_uri_args()
		user_name = args[user_header] or ngx.req.get_headers()[user_header]
	end

	if not user_name and not custom_id then
		return kong.response.exit(401, {
			message = "Invalid credentials. Token or User credentials required"
		})
	end

	local admin, err = nil

	if custom_id then
		admin, err = kong.db.admins:select_by_custom_id(custom_id, {
			skip_rbac = true
		})

		if err then
			log(ERR, _log_prefix, err)

			return nil, err
		end
	end

	if user_name then
		admin, err = kong.db.admins:select_by_username(user_name, {
			skip_rbac = true
		})

		if not admin and ignore_case then
			admin, err = find_admin_ignore_case(user_name)
		end

		if err then
			log(ERR, _log_prefix, err)

			return nil, err
		end
	end

	if not admin then
		log(DEBUG, _log_prefix, "Admin not found with user_name=" .. user_name or "nil" .. "or custom_id=" .. custom_id or "nil")

		return nil, err
	end

	return admin
end

function _M:authenticate(rbac_enabled, gui_auth)
	local ctx = ngx.ctx
	local invoke_plugin = kong.invoke_plugin

	if not gui_auth and not rbac_enabled then
		return
	end

	if auth_whitelisted_uris[ngx.var.uri] then
		return
	end

	if rbac_enabled and not gui_auth then
		return
	end

	local old_ws = ctx.workspace
	ctx.workspace = nil
	local gui_auth_conf = kong.configuration.admin_gui_auth_conf
	local by_username_ignore_case = gui_auth_conf and gui_auth_conf.by_username_ignore_case
	local admin, err = _M.validate_admin(by_username_ignore_case)

	if err then
		log(ERR, _log_prefix, err)

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	if not admin then
		log(DEBUG, _log_prefix, "Admin not found")

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	local consumer_id = admin.consumer.id
	local rbac_user_id = admin.rbac_user.id
	local rbac_user, err = rbac.get_user(rbac_user_id)

	if err then
		log(ERR, _log_prefix, err)

		return endpoints.handle_error(err)
	end

	if not rbac_user then
		log(DEBUG, _log_prefix, "no rbac_user found for name: " .. admin.username)

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	admin.rbac_user = rbac_user
	local _, err = rbac.get_rbac_user_info(rbac_user)

	if err then
		log(ERR, _log_prefix, err)

		return endpoints.handle_error(err)
	end

	_M.attach_consumer_and_workspaces(self, consumer_id)

	local session_conf = kong.configuration.admin_gui_session_conf
	local ok, err = invoke_plugin({
		name = "session",
		config = session_conf,
		phases = {
			"access"
		},
		api_type = _M.apis.ADMIN,
		db = kong.db
	})

	if not ok then
		log(ERR, _log_prefix, err)

		return endpoints.handle_error(err)
	end

	if not ctx.authenticated_consumer then
		log(DEBUG, _log_prefix, "no consumer mapped from plugin ", gui_auth)

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	if self.consumer and ctx.authenticated_consumer.id ~= self.consumer.id then
		log(DEBUG, _log_prefix, "authenticated consumer is not an admin")

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	local ok, err = invoke_plugin({
		name = "session",
		config = session_conf,
		phases = {
			"header_filter"
		},
		api_type = _M.apis.ADMIN,
		db = kong.db
	})

	if not ok then
		log(ERR, _log_prefix, err)

		return endpoints.handle_error(err)
	end

	self.consumer = ctx.authenticated_consumer

	if self.consumer.type ~= enums.CONSUMERS.TYPE.ADMIN then
		log(ERR, _log_prefix, "consumer ", self.consumer.id, " is not an admin")

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	if admin.status == enums.CONSUMERS.STATUS.INVITED then
		local _, err = kong.db.admins:update({
			id = admin.id
		}, {
			status = enums.CONSUMERS.STATUS.APPROVED
		}, {
			skip_rbac = true
		})

		if err then
			log(ERR, _log_prefix, "failed to approve admin: ", admin.id, ": ", err)

			return endpoints.handle_error(err)
		end

		admin.status = enums.CONSUMERS.STATUS.APPROVED
	end

	if admin.status ~= enums.CONSUMERS.STATUS.APPROVED then
		return kong.response.exit(401, _M.get_consumer_status(admin))
	end

	self.rbac_user = rbac_user
	self.groups = ctx.authenticated_groups
	self.admin = admin
	ctx.workspace = old_ws
	ngx.ctx.rbac = nil
end

function _M:attach_consumer_and_workspaces(consumer_id)
	local workspace = _M.attach_workspaces(self, consumer_id)
	ngx.ctx.workspace = workspace.id

	_M.attach_consumer(self, consumer_id)
end

function _M:attach_consumer(consumer_id)
	local cache_key = kong.db.consumers:cache_key(consumer_id)
	local consumer, err = kong.cache:get(cache_key, nil, _M.retrieve_consumer, consumer_id)

	if err or not consumer then
		log(ERR, _log_prefix, "failed to get consumer:", consumer_id, ": ", err)

		return endpoints.handle_error()
	end

	self.consumer = consumer
end

function _M:attach_workspaces_roles(roles)
	if not roles then
		return
	end

	for _, role in ipairs(roles) do
		local rbac_role, err = get_with_cache("rbac_roles", role.id, ngx.null)

		if err then
			kong.log.err("Error fetching role: ", role.id, ": ", err)

			return endpoints.handle_error()
		end

		if not self.workspaces_hash[rbac_role.ws_id] then
			local ws, err = workspaces.select_workspace_by_id_with_cache(rbac_role.ws_id)

			if err then
				kong.log.err("Error fetching workspace for role: ", role.id, ": ", err)

				return endpoints.handle_error()
			end

			table.insert(self.workspaces, ws)

			self.workspaces_hash[ws.id] = ws
		end
	end
end

function _M:attach_workspaces(consumer_id)
	local consumer, ws, err = nil
	consumer, err = get_with_cache("consumers", consumer_id, ngx.null)

	if not consumer or err then
		log(ERR, _log_prefix, "Error fetching consumer with consumer_id: ", consumer_id, ": ", err)

		return endpoints.handle_error()
	end

	ws, err = workspaces.select_workspace_by_id_with_cache(consumer.ws_id)

	if not ws or err then
		log(ERR, "no workspace found for consumer_id: ", consumer_id, ": ", err)

		return endpoints.handle_error()
	end

	self.workspaces = {
		ws
	}
	self.workspaces_hash = {
		[ws.id] = ws
	}

	return {
		id = ws.id,
		name = ws.name
	}
end

function _M:validate_jwt(db, helpers, token_optional)
	local reset_secrets = db.consumer_reset_secrets

	if token_optional then
		return
	end

	if not self.params.token or self.params.token == "" then
		return kong.response.exit(400, {
			message = "token is required"
		})
	end

	local jwt, err = ee_utils.validate_reset_jwt(self.params.token)

	if err then
		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	local reset_secret = nil

	for secret, err in reset_secrets:each_for_consumer({
		id = jwt.claims.id
	}) do
		if err then
			log(ERR, _log_prefix, err)

			return kong.response.exit(401, {
				message = "Unauthorized"
			})
		end

		if not reset_secret and secret.status == enums.TOKENS.STATUS.PENDING then
			reset_secret = secret
		end
	end

	if not reset_secret then
		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	local ok, _ = ee_jwt.verify_signature(jwt, reset_secret.secret)

	if not ok then
		log(ERR, _log_prefix, "JWT signature is invalid")

		return kong.response.exit(401, {
			message = "Unauthorized"
		})
	end

	self.reset_secret_id = reset_secret.id
	self.consumer_id = jwt.claims.id
end

function _M:validate_email(dao_factory, helpers)
	local ok, err = ee_utils.validate_email(self.params.email)

	if not ok then
		return kong.response.exit(400, {
			message = "Invalid email: " .. err
		})
	end
end

function _M.validate_password(password)
	local config = kong.configuration.admin_gui_auth_password_complexity
	local ee_auth_helpers = require("kong.enterprise_edition.auth_helpers")

	if not password or password == "" then
		return kong.response.exit(400, {
			message = "password is required"
		})
	end

	if config then
		local _, err = ee_auth_helpers.check_password_complexity(password, nil, config)

		if err then
			return kong.response.exit(400, {
				message = "Invalid password: " .. err
			})
		end
	end
end

function _M:routes_consumers_before(params, is_collection)
	if params.type then
		return kong.response.exit(400, {
			message = "Invalid parameter: 'type'"
		})
	end

	if is_collection then
		return true
	end

	if kong.request.get_method() == "PUT" then
		return
	end

	if kong.request.get_method() == "DELETE" then
		return
	end

	local consumer, _, err_t = endpoints.select_entity(self, kong.db, kong.db.consumers.schema)

	if err_t then
		return endpoints.handle_error(err_t)
	end

	if not consumer then
		return kong.response.exit(404, {
			message = "Not found"
		})
	end

	if consumer.type ~= enums.CONSUMERS.TYPE.PROXY then
		return kong.response.exit(404, {
			message = "Not Found"
		})
	end

	return consumer
end

function _M.splatify_entity_route(entity, routes)
	local entity_pattern = "/" .. entity .. "/:" .. entity
	local entity_endpoint = routes[entity_pattern]

	if not entity_endpoint then
		log(ERR, _log_prefix, "entity endpoint: " .. entity_pattern .. "not found")

		return
	end

	local route = {
		schema = entity_endpoint.schema,
		methods = entity_endpoint.methods
	}
	local before = route.methods.before or function ()
	end

	function route.methods:before(db, helpers)
		if self.params.splat then
			self.params[entity] = self.params.splat
			self.params.splat = nil
		end

		before(self, db, helpers)
	end

	routes["/" .. entity .. "/*"] = route
end

local function validate_workspace_name(name)
	local Workspaces = assert(entity.new(ws_schema))

	return Workspaces:validate({
		name = name,
		config = {},
		meta = {}
	})
end

function _M.set_cors_headers(origins, api_type)
	local invoke_plugin = kong.invoke_plugin
	local cors_conf = {
		credentials = true,
		origins = origins,
		methods = {
			"GET",
			"PUT",
			"PATCH",
			"DELETE",
			"POST"
		}
	}

	return invoke_plugin({
		name = "cors",
		config = cors_conf,
		phases = {
			"access",
			"header_filter"
		},
		api_type = api_type,
		db = kong.db
	})
end

function _M:before_filter()
	local req_id = utils.random_string()
	ngx.ctx.admin_api = {
		req_id = req_id
	}
	ngx.header["X-Kong-Admin-Request-ID"] = req_id
	ngx.ctx.admin_api_request = true
	ngx.ctx.rbac = nil

	workspaces.set_workspace(nil)

	local ws_name = workspaces.DEFAULT_WORKSPACE

	if self.params.workspace_name then
		ws_name = unescape_uri(self.params.workspace_name)
		local ok, err = validate_workspace_name(ws_name)

		if not ok then
			return kong.response.exit(400, errors:invalid_unique("name", err.name))
		end
	end

	local workspace, err = workspaces.select_workspace_by_name_with_cache(ws_name)

	if err then
		ngx.log(ngx.ERR, err)

		return kong.response.exit(500, {
			message = err
		})
	end

	if not workspace then
		kong.response.exit(404, {
			message = fmt("Workspace '%s' not found", ws_name)
		})
	end

	workspaces.set_workspace(workspace)

	self.params.workspace_name = nil
	local ok, err = _M.set_cors_headers({
		kong.configuration.admin_gui_origin or "*"
	}, _M.apis.ADMIN)

	if not ok then
		return app_helpers.yield_error(err)
	end

	local rbac_auth_header = kong.configuration.rbac_auth_header
	local rbac_token = ngx.req.get_headers()[rbac_auth_header]

	if not rbac_token then
		_M.authenticate(self, kong.configuration.enforce_rbac ~= "off", kong.configuration.admin_gui_auth)
	end

	rbac.validate_user(self.rbac_user)
	rbac.validate_endpoint(self.route_name, ngx.var.uri, self.rbac_user)
end

return _M
