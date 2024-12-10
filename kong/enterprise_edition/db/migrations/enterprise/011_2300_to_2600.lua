local operations_230_260 = require("kong.db.migrations.operations.230_to_260")

return {
	postgres = {
		up = [[
      DO $$
      BEGIN
        ALTER TABLE IF EXISTS ONLY "admins" ADD "username_lower" TEXT;
      EXCEPTION WHEN DUPLICATE_COLUMN THEN
        -- Do nothing, accept existing state
      END;
      $$;

      UPDATE admins SET username_lower=LOWER(username);
    ]],
		teardown = function (connector)
			operations_230_260.output_duplicate_username_lower_report(connector, "postgres")
		end
	}
}
