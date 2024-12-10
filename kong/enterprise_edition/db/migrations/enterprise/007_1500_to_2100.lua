local operations = require("kong.enterprise_edition.db.migrations.operations.1500_to_2100")
local log = require("kong.cmd.utils.log")
local ee_core_entities = {
	{
		primary_key = "id",
		name = "rbac_users",
		uniques = {
			"name"
		},
		fks = {}
	},
	{
		primary_key = "id",
		name = "rbac_roles",
		uniques = {
			"name"
		},
		fks = {}
	},
	{
		primary_key = "id",
		name = "files",
		uniques = {
			"path"
		},
		fks = {}
	},
	{
		primary_key = "id",
		name = "developers",
		uniques = {
			"email",
			"custom_id"
		},
		fks = {
			{
				reference = "consumers",
				name = "consumer"
			},
			{
				reference = "rbac_users",
				name = "rbac_user"
			}
		}
	},
	{
		primary_key = "id",
		name = "document_objects",
		uniques = {
			"path"
		},
		fks = {
			{
				reference = "services",
				name = "service"
			}
		}
	},
	{
		primary_key = "id",
		name = "applications",
		uniques = {},
		fks = {
			{
				reference = "consumers",
				name = "consumer"
			},
			{
				reference = "developers",
				name = "developer"
			}
		}
	},
	{
		primary_key = "id",
		name = "application_instances",
		uniques = {
			"composite_id"
		},
		fks = {
			{
				reference = "applications",
				name = "application"
			},
			{
				reference = "services",
				name = "service"
			}
		}
	}
}
local ce_core_entities = {
	{
		primary_key = "id",
		name = "upstreams",
		uniques = {
			"name"
		},
		fks = {}
	},
	{
		primary_key = "id",
		name = "targets",
		uniques = {},
		fks = {
			{
				on_delete = "cascade",
				name = "upstream",
				reference = "upstreams"
			}
		}
	},
	{
		primary_key = "id",
		name = "consumers",
		uniques = {
			"username",
			"custom_id"
		},
		fks = {}
	},
	{
		primary_key = "id",
		name = "certificates",
		uniques = {},
		fks = {}
	},
	{
		primary_key = "id",
		name = "snis",
		uniques = {},
		fks = {
			{
				reference = "certificates",
				name = "certificate"
			}
		}
	},
	{
		primary_key = "id",
		name = "services",
		uniques = {
			"name"
		},
		fks = {
			{
				reference = "certificates",
				name = "client_certificate"
			}
		}
	},
	{
		primary_key = "id",
		name = "routes",
		uniques = {
			"name"
		},
		fks = {
			{
				reference = "services",
				name = "service"
			}
		}
	},
	{
		primary_key = "id",
		name = "plugins",
		uniques = {},
		fks = {
			{
				on_delete = "cascade",
				name = "route",
				reference = "routes"
			},
			{
				on_delete = "cascade",
				name = "service",
				reference = "services"
			},
			{
				on_delete = "cascade",
				name = "consumer",
				reference = "consumers"
			}
		}
	}
}

local function ws_migration_up(ops)
	return ops:ws_adjust_fields(ee_core_entities)
end

local function ws_migration_teardown(ops)
	return function (connector)
		ops:drop_run_on(connector)
		log.debug("run_on dropped")

		if ops:has_workspace_entities(connector)[1] then
			ops:ws_adjust_data(connector, ce_core_entities)
			log.debug("adjusted core data")
			ops:ws_adjust_data(connector, ee_core_entities)
			log.debug("adjusted EE data")
			ops:ws_clean_kong_admin_rbac_user(connector)
			log.debug("cleaned ADMIN RBAC data")
			ops:ws_set_default_ws_for_admin_entities(connector)
			log.debug("set default_ws_for_admin_entities")
		end
	end
end

return {
	postgres = {
		up = [[
      DO $$
      BEGIN
        ALTER TABLE IF EXISTS ONLY "applications" ADD "custom_id" TEXT UNIQUE;
      EXCEPTION WHEN duplicate_column THEN
        -- Do nothing, accept existing state
      END;
      $$;
    ]] .. ws_migration_up(operations.postgres.up),
		teardown = ws_migration_teardown(operations.postgres.teardown)
	}
}
