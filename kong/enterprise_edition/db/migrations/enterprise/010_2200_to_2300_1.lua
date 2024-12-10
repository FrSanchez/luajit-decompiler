return {
	postgres = {
		up = [[

      ALTER TABLE IF EXISTS ONLY "licenses" ALTER COLUMN "created_at" DROP DEFAULT;
      ALTER TABLE IF EXISTS ONLY "licenses" ALTER COLUMN "created_at" TYPE TIMESTAMP WITH TIME ZONE USING "created_at" AT TIME ZONE 'UTC';

      ALTER TABLE IF EXISTS ONLY "licenses" ALTER COLUMN "updated_at" DROP DEFAULT;
      ALTER TABLE IF EXISTS ONLY "licenses" ALTER COLUMN "updated_at" TYPE TIMESTAMP WITH TIME ZONE USING "updated_at" AT TIME ZONE 'UTC';

    ]],
		teardown = function (connector)
			assert(connector:query([[
        DELETE FROM licenses WHERE payload IS NULL;
        ALTER TABLE IF EXISTS ONLY "licenses" ALTER COLUMN "payload" SET NOT NULL;

        DELETE FROM licenses WHERE id IN (
          SELECT l.id FROM licenses l, licenses ll
          WHERE l.payload = ll.payload
          AND l.id < ll.id
        );

        ALTER TABLE "licenses" DROP CONSTRAINT IF EXISTS "licenses_payload_key";
        ALTER TABLE IF EXISTS ONLY "licenses" ADD CONSTRAINT "licenses_payload_key" UNIQUE (payload);
      ]]))
		end
	}
}
