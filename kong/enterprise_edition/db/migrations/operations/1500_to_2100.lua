local ce_operations = require("kong.db.migrations.operations.200_to_210")
local log = require("kong.cmd.utils.log")
local concat = table.concat
local fmt = string.format

local function render(template, keys)
	return template:gsub("$%(([A-Z_]+)%)", keys)
end

local function postgres_run_query_in_transaction(connector, query)
	assert(connector:query(concat({
		"BEGIN",
		query,
		"COMMIT"
	}, ";")))
end

local function postgres_list_tables(connector)
	local tables = {}
	local sql = fmt([[
    SELECT table_name
      FROM information_schema.tables
     WHERE table_schema='%s'
  ]], connector.config.schema)
	local rows, err = connector:query(sql)

	if err then
		return nil, err
	end

	for _, v in ipairs(rows) do
		local _, vv = next(v)
		tables[vv] = true
	end

	return tables
end

local function postgres_remove_prefixes_code(entity, code)
	if #entity.uniques > 0 then
		local fields = {}

		for _, f in ipairs(entity.uniques) do
			table.insert(fields, f .. " = regexp_replace(" .. f .. ", '^(' || (SELECT string_agg(name, '|') FROM workspaces) ||'):', '')")
		end

		table.insert(code, render("        UPDATE $(TABLE) SET $(FIELDS);\n      ", {
			TABLE = entity.name,
			FIELDS = table.concat(fields, ", ")
		}))
	end
end

local function postgres_workspaceable_code(entity, code)
	table.insert(code, render([[

      -- fixing up workspaceable rows for $(TABLE)

      UPDATE $(TABLE)
      SET ws_id = we.workspace_id
      FROM workspace_entities we
      WHERE entity_type='$(TABLE)'
        AND unique_field_name='$(PK)'
        AND unique_field_value=$(TABLE).$(PK)::text;
    ]], {
		TABLE = entity.name,
		PK = entity.primary_key
	}))
end

local postgres = {
	up = {},
	teardown = {
		ws_fixup_workspaceable_rows = function (_, connector, entity)
			log.debug("ws_fixup_workspaceable_rows: " .. entity.name)

			local code = {}
			local existing_tables, err = postgres_list_tables(connector)

			if err then
				ngx.log(ngx.ERR, "err: ", type(err) == "string" and err or type(err))

				return nil, err
			end

			if existing_tables.workspace_entities then
				postgres_workspaceable_code(entity, code)
			end

			postgres_remove_prefixes_code(entity, code)
			postgres_run_query_in_transaction(connector, table.concat(code))
			log.debug("ws_fixup_workspaceable_rows: " .. entity.name .. " DONE")
		end,
		ws_fixup_consumer_plugin_rows = function (_, connector, entity)
			log.debug("ws_fixup_consumer_plugin_rows: " .. entity.name)

			local code = {}
			local existing_tables, err = postgres_list_tables(connector)

			if err then
				ngx.log(ngx.ERR, "err: ", type(err) == "string" and err or type(err))

				return nil, err
			end

			if existing_tables.ws_migrations_backup then
				for _, unique in ipairs(entity.uniques) do
					table.insert(code, render([[
              INSERT INTO ws_migrations_backup (entity_type, entity_id, unique_field_name, unique_field_value)
              SELECT '$(TABLE)', $(TABLE).$(PK)::text, '$(UNIQUE)', $(TABLE).$(UNIQUE)
              FROM $(TABLE);
            ]], {
						TABLE = entity.name,
						PK = entity.primary_key,
						UNIQUE = unique
					}))
				end
			end

			local consumer_plugin = false

			for _, fk in ipairs(entity.fks) do
				if fk.reference == "consumers" then
					consumer_plugin = true

					break
				end
			end

			if consumer_plugin then
				table.insert(code, render([[
            UPDATE $(TABLE)
            SET ws_id = c.ws_id
            FROM consumers c
            WHERE $(TABLE).consumer_id = c.id;
          ]], {
					TABLE = entity.name
				}))
			elseif existing_tables.workspace_entities then
				postgres_workspaceable_code(entity, code)
			end

			postgres_remove_prefixes_code(entity, code)
			postgres_run_query_in_transaction(connector, table.concat(code))
			log.debug("ws_fixup_consumer_plugin_rows: " .. entity.name .. " DONE")
		end,
		ws_clean_kong_admin_rbac_user = function (_, connector)
			connector:query([[
        UPDATE rbac_users
           SET name = 'kong_admin'
         WHERE name = 'default:kong_admin';
      ]])
		end,
		ws_set_default_ws_for_admin_entities = function (_, connector)
			local code = {}
			local entities = {
				"rbac_user"
			}

			for _, e in ipairs(entities) do
				table.insert(code, render([[

            -- assign admin linked $(TABLE)' ws_id to default ws id

            update $(TABLE)
            set ws_id = (select id from workspaces where name='default')
            where id in (select $(COLUMN) from admins);
          ]], {
					TABLE = e .. "s",
					COLUMN = e .. "_id"
				}))
			end

			postgres_run_query_in_transaction(connector, table.concat(code))
		end,
		drop_run_on = function (_, connector)
			connector:query([[
        DO $$
        BEGIN
          ALTER TABLE IF EXISTS ONLY "plugins" DROP COLUMN "run_on";
        EXCEPTION WHEN UNDEFINED_COLUMN THEN
          -- Do nothing, accept existing state
        END;
        $$;
      ]])
		end,
		has_workspace_entities = function (_, connector)
			return connector:query("        SELECT * FROM pg_catalog.pg_tables WHERE tablename='workspace_entities';\n      ")
		end
	}
}

local function ws_adjust_data(ops, connector, entities)
	for _, entity in ipairs(entities) do
		log.debug("adjusting data for: " .. entity.name)
		ops:ws_fixup_workspaceable_rows(connector, entity)
		log.debug("adjusting data for: " .. entity.name .. " ...DONE")
	end
end

postgres.teardown.ws_adjust_data = ws_adjust_data

local function ws_migrate_plugin(plugin_entities)
	local function ws_migration_teardown(ops)
		return function (connector)
			for _, entity in ipairs(plugin_entities) do
				ops:ws_fixup_consumer_plugin_rows(connector, entity)
			end
		end
	end

	return {
		postgres = {
			up = "",
			teardown = ws_migration_teardown(postgres.teardown)
		}
	}
end

local ee_operations = {
	postgres = postgres,
	ws_migrate_plugin = ws_migrate_plugin,
	utils = {
		render = render,
		postgres_has_workspace_entities = postgres.teardown.has_workspace_entities
	}
}

for db, stages in pairs(ce_operations) do
	if type(stages) == "table" then
		for stage, ops in pairs(stages) do
			for name, fn in pairs(ops) do
				if not ee_operations[db][stage][name] then
					ee_operations[db][stage][name] = fn
				end
			end
		end
	end
end

return ee_operations
