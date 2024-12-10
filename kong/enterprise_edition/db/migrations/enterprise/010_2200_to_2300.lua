return {
	postgres = {
		up = [[
        CREATE TABLE IF NOT EXISTS licenses(
              id                uuid PRIMARY KEY,
              payload text,
              created_at        timestamp without time zone DEFAULT timezone('utc'::text, ('now'::text)::timestamp(0) with time zone),
              updated_at        timestamp without time zone DEFAULT timezone('utc'::text, ('now'::text)::timestamp(0) with time zone)
        );
    ]]
	}
}
