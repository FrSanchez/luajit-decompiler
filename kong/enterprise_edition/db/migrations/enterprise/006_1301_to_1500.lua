local openssl_x509 = require("resty.openssl.x509")
local str = require("resty.string")

local function pg_delete_we_orphan(entity)
	return "    DELETE FROM workspace_entities WHERE entity_id IN (\n      SELECT entity_id FROM (\n        SELECT * from workspace_entities WHERE entity_type='" .. entity .. "'\n      ) t1 LEFT JOIN " .. entity .. [[
 t2
      ON t2.id::text = t1.entity_id
      WHERE t2.id IS NULL
    );
  ]]
end

local function pg_fix_we_counters(entity)
	return [[
    UPDATE workspace_entity_counters AS wec
      SET count = we.count FROM (
        SELECT d.workspace_id AS workspace_id,
               d.entity_type AS entity_type,
               coalesce(c.count, 0) AS count
        FROM (
          SELECT id AS workspace_id, ']] .. entity .. [[
'::text AS entity_type
          FROM workspaces
        ) AS d LEFT JOIN (
        SELECT workspace_id, entity_type, COUNT(DISTINCT entity_id)
          FROM workspace_entities
          WHERE entity_type = ']] .. entity .. [[
'
          GROUP BY workspace_id, entity_type
        ) c
        ON d.workspace_id = c.workspace_id
      ) AS we
    WHERE wec.workspace_id = we.workspace_id
    AND wec.entity_type = we.entity_type;
  ]]
end

local function pg_ca_certificates_migration(connector)
	assert(connector:connect_migrations())

	for ca_cert, err in connector:iterate("SELECT * FROM ca_certificates") do
		if err then
			return nil, err
		end

		local digest = str.to_hex(openssl_x509.new(ca_cert.cert):digest("sha256"))

		if not digest then
			return nil, "cannot create digest value of certificate with id: " .. ca_cert.id
		end

		local sql = string.format("          UPDATE ca_certificates SET cert_digest = '%s' WHERE id = '%s';\n        ", digest, ca_cert.id)

		assert(connector:query(sql))
	end

	assert(connector:query("ALTER TABLE ca_certificates ALTER COLUMN cert_digest SET NOT NULL"))
end

return {
	postgres = {
		up = [[
      CREATE TABLE IF NOT EXISTS applications (
        id          uuid,
        created_at  timestamp,
        updated_at  timestamp,
        name text,
        description text,
        redirect_uri text,
        meta text,
        developer_id uuid references developers (id) on delete cascade,
        consumer_id  uuid references consumers (id) on delete cascade,
        PRIMARY KEY(id)
      );

      CREATE INDEX IF NOT EXISTS applications_developer_id_idx ON applications(developer_id);

      CREATE TABLE IF NOT EXISTS application_instances (
        id          uuid,
        created_at  timestamp,
        updated_at  timestamp,
        status int,
        service_id uuid references services (id) on delete cascade,
        application_id  uuid references applications (id) on delete cascade,
        composite_id text unique,
        suspended boolean NOT NULL,
        PRIMARY KEY(id)
      );

      CREATE TABLE IF NOT EXISTS document_objects (
        id          uuid,
        created_at  timestamp,
        updated_at  timestamp,
        service_id uuid references services (id) on delete cascade,
        path text unique,
        PRIMARY KEY(id)
      );

      -- XXX: EE keep run_on for now
      DO $$
      BEGIN
        ALTER TABLE IF EXISTS ONLY "plugins" ADD "run_on" TEXT;
      EXCEPTION WHEN duplicate_column THEN
        -- Do nothing, accept existing state
      END;
      $$;

      CREATE TABLE IF NOT EXISTS "event_hooks" (
        "id"           UUID                         UNIQUE,
        "created_at"   TIMESTAMP WITHOUT TIME ZONE  DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
        "source"       TEXT NOT NULL,
        "event"        TEXT,
        "handler"      TEXT NOT NULL,
        "on_change"    BOOLEAN,
        "snooze"       INTEGER,
        "config"       JSON                         NOT NULL
      );

      -- add `license_creation_date` field for license_data table
      DO $$
        BEGIN
          ALTER TABLE license_data ADD COLUMN license_creation_date TIMESTAMP;
        EXCEPTION WHEN duplicate_column THEN
          -- Do nothing, accept existing state
        END;
      $$;

      -- ca_certificates table
      ALTER TABLE ca_certificates DROP CONSTRAINT IF EXISTS ca_certificates_cert_key;

      DO $$
        BEGIN
          ALTER TABLE ca_certificates ADD COLUMN "cert_digest" TEXT UNIQUE;
        EXCEPTION WHEN duplicate_column THEN
          -- Do nothing, accept existing state
        END;
      $$;
    ]],
		teardown = function (connector)
			assert(connector:query([[
        DO $$
        BEGIN
          ALTER TABLE IF EXISTS ONLY "plugins" ADD "run_on" TEXT;
        EXCEPTION WHEN duplicate_column THEN
          -- Do nothing, accept existing state
        END;
        $$;
      ]]))

			local entities = {
				"keyauth_credentials",
				"oauth2_tokens",
				"oauth2_authorization_codes"
			}

			for _, entity in ipairs(entities) do
				assert(connector:query(pg_delete_we_orphan(entity)))
				assert(connector:query(pg_fix_we_counters(entity)))
			end

			pg_ca_certificates_migration(connector)
		end
	}
}
