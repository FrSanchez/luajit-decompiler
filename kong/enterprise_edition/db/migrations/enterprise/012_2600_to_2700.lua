return {
	postgres = {
		up = [[
      DO $$
      BEGIN
      UPDATE consumers
      SET
        username = CONCAT(username, '_ADMIN_'),
        username_lower = CONCAT(username_lower, '_admin_')
      WHERE
        username !~ '_ADMIN_$'
      AND
        type = 2;
      END;
      $$;

      DO $$
      BEGIN
        ALTER TABLE IF EXISTS ONLY "license_data" ADD "year" smallint;
        ALTER TABLE IF EXISTS ONLY "license_data" ADD "month" smallint;
      EXCEPTION WHEN DUPLICATE_COLUMN THEN
        -- Do nothing, accept existing state
      END;
      $$;

      DO $$
      BEGIN
        UPDATE "license_data" SET "year" = 0 WHERE "year" IS NULL;
        UPDATE "license_data" SET "month" = 0 WHERE "month" IS NULL;
        ALTER TABLE "license_data" ALTER COLUMN "year" SET NOT NULL;
        ALTER TABLE "license_data" ALTER COLUMN "month" SET NOT NULL;
        DROP INDEX IF EXISTS license_data_key_idx;
        ALTER TABLE license_data DROP CONSTRAINT IF EXISTS license_data_pkey;
        CREATE UNIQUE INDEX IF NOT EXISTS license_data_key_idx ON license_data(node_id, year, month);
      END
      $$;

    ]]
	}
}
