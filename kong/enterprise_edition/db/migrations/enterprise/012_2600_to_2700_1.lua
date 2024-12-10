local log = require("kong.cmd.utils.log")
local operations = require("kong.enterprise_edition.db.migrations.operations.1500_to_2100")
local ee_new_entities = {
	{
		primary_key = "id",
		name = "consumer_groups",
		uniques = {
			"name"
		},
		fks = {}
	},
	{
		primary_key = "id",
		name = "consumer_group_plugins",
		uniques = {},
		fks = {
			{
				on_delete = "cascade",
				name = "consumer_group",
				reference = "consumer_groups"
			}
		}
	}
}

local function ws_migration_up(ops)
	return ops:ws_adjust_fields(ee_new_entities)
end

local function ws_migration_teardown(ops)
	return function (connector)
		ops:drop_run_on(connector)
		log.debug("run_on dropped")

		if ops:has_workspace_entities(connector)[1] then
			ops:ws_adjust_data(connector, ee_new_entities)
			log.debug("adjusted EE data")
		end
	end
end

return {
	postgres = {
		up = [[
      CREATE TABLE IF NOT EXISTS "consumer_groups" (
        "id"          UUID                         PRIMARY KEY,
        "created_at"  TIMESTAMP WITH TIME ZONE     DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
        "name"        TEXT                         UNIQUE
      );

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "consumer_groups_name_idx" ON "consumer_groups" ("name");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      CREATE TABLE IF NOT EXISTS "consumer_group_plugins" (
        "id"          UUID                         PRIMARY KEY,
        "created_at"  TIMESTAMP WITH TIME ZONE     DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
        "consumer_group_id"     UUID                         REFERENCES "consumer_groups" ("id") ON DELETE CASCADE,
        "name"        TEXT                         NOT NULL,
        "cache_key"   TEXT                         UNIQUE,
        "config"      JSONB                        NOT NULL
      );

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "consumer_group_plugins_group_id_idx" ON "consumer_group_plugins" ("consumer_group_id");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "consumer_group_plugins_plugin_name_idx" ON "consumer_group_plugins" ("name");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      CREATE TABLE IF NOT EXISTS "consumer_group_consumers" (
        "created_at"  TIMESTAMP WITH TIME ZONE     DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
        "consumer_group_id"     UUID                         REFERENCES "consumer_groups" ("id") ON DELETE CASCADE,
        "consumer_id" UUID                         REFERENCES "consumers" ("id") ON DELETE CASCADE,
        "cache_key"   TEXT                         UNIQUE,
        PRIMARY KEY (consumer_group_id, consumer_id)
      );

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "consumer_group_consumers_group_id_idx" ON "consumer_group_consumers" ("consumer_group_id");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      DO $$
      BEGIN
        CREATE INDEX IF NOT EXISTS "consumer_group_consumers_consumer_id_idx" ON "consumer_group_consumers" ("consumer_id");
      EXCEPTION WHEN UNDEFINED_COLUMN THEN
        -- Do nothing, accept existing state
      END$$;

      ]] .. ws_migration_up(operations.postgres.up),
		teardown = ws_migration_teardown(operations.postgres.teardown)
	}
}
