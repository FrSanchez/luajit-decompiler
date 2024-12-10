return {
	postgres = {
		up = [[
        DO $$
        BEGIN
          ALTER TABLE IF EXISTS ONLY "plugins" ADD "ordering" jsonb;
        EXCEPTION WHEN DUPLICATE_COLUMN THEN
          -- Do nothing, accept existing state
        END;
        $$;

        CREATE TABLE IF NOT EXISTS keyring_keys (
            id text PRIMARY KEY,
            recovery_key_id text not null,
            key_encrypted text not null,
            created_at timestamp with time zone not null,
            updated_at timestamp with time zone not null
        );
      ]],
		teardown = function (connector)
			local _, err = connector:query("DELETE FROM plugins WHERE name = 'collector'")

			if err then
				return nil, err
			end

			return true
		end
	}
}
