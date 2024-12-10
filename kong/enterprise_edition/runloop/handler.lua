local file_helpers = require("kong.portal.file_helpers")
local workspaces = require("kong.workspaces")
local tracing = require("kong.tracing")
local utils = require("kong.tools.utils")
local handler = {}
local log = ngx.log
local ERR = ngx.ERR
local DEBUG = ngx.DEBUG
local unpack = unpack

function handler.register_events()
	local kong = kong
	local worker_events = kong.worker_events
	local cluster_events = kong.cluster_events

	if kong.configuration.audit_log then
		log(DEBUG, "register audit log events handler")

		local audit_log = require("kong.enterprise_edition.audit_log")

		worker_events.register(audit_log.dao_audit_handler, "dao:crud")
	end

	worker_events.register(function (data)
		kong.cache:invalidate("rbac_user_token_ident:" .. data.entity.user_token_ident)

		if data.old_entity and data.old_entity.user_token_ident then
			kong.cache:invalidate("rbac_user_token_ident:" .. data.old_entity.user_token_ident)
		end
	end, "crud", "rbac_users")

	local function invalidate_cache(entity_name, id)
		local cache_key = kong.db[entity_name]:cache_key(id)

		kong.cache:invalidate(cache_key)
	end

	worker_events.register(function (data)
		workspaces.set_workspace(data.workspace)
		invalidate_cache("rbac_role_endpoints", data.entity.id)
		invalidate_cache("rbac_role_entities", data.entity.id)
	end, "crud", "rbac_roles:delete")

	local function rbac_role_relations_invalidate(data)
		workspaces.set_workspace(data.workspace)
		invalidate_cache(data.schema.name, data.entity.role.id)

		if data.old_entity then
			invalidate_cache(data.schema.name, data.old_entity.role.id)
		end
	end

	worker_events.register(rbac_role_relations_invalidate, "crud", "rbac_role_endpoints")
	worker_events.register(rbac_role_relations_invalidate, "crud", "rbac_role_entities")
	worker_events.register(function (data)
		invalidate_cache("workspaces", data.entity.id)
	end, "crud", "workspaces:update", "workspaces:delete")
	worker_events.register(function (data)
		workspaces.set_workspace(data.workspace)

		local file = data.entity

		if file_helpers.is_config_path(file.path) or file_helpers.is_content_path(file.path) or file_helpers.is_spec_path(file.path) then
			local workspace = workspaces.get_workspace()
			local cache_key = "portal_router-" .. workspace.name .. ":version"
			local cache_val = tostring(ngx.now()) .. file.checksum
			local ok, err = worker_events.post("portal", "router", {
				cache_key = cache_key,
				cache_val = cache_val
			})

			if not ok then
				log(ERR, "failed broadcasting portal:router event to workers: ", err)
			end

			local cluster_key = cache_key .. "|" .. cache_val
			ok, err = cluster_events:broadcast("portal:router", cluster_key)

			if not ok then
				log(ERR, "failed broadcasting portal:router event to cluster: ", err)
			end
		end
	end, "crud", "files")
	cluster_events:subscribe("portal:router", function (data)
		local cache_key, cache_val = unpack(utils.split(data, "|"))
		local ok, err = worker_events.post("portal", "router", {
			cache_key = cache_key,
			cache_val = cache_val
		})

		if not ok then
			log(ERR, "failed broadcasting portal:router event to workers: ", err)
		end
	end)
	worker_events.register(function (data)
		kong.portal_router.set_version(data.cache_key, data.cache_val)
	end, "portal", "router")
end

function handler.new_router(router)
	tracing.wrap_router(router)

	return router
end

return handler
