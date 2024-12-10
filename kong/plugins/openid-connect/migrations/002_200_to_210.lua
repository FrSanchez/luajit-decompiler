local jwks = require("kong.openid-connect.jwks")

return {
	postgres = {
		up = [[
      CREATE TABLE IF NOT EXISTS "oic_jwks" (
        "id"    UUID    PRIMARY KEY,
        "jwks"  JSONB
      );
    ]],
		teardown = function (connector)
			local generated_jwks, err = jwks.new({
				json = true
			})

			if not generated_jwks then
				return nil, err
			end

			local insert_query = string.format([[
        INSERT INTO "oic_jwks" ("id", "jwks")
             VALUES ('c3cfba2d-1617-453f-a416-52e6edb5f9a0', '%s')
        ON CONFLICT DO NOTHING;
      ]], generated_jwks)
			local _ = nil
			_, err = connector:query(insert_query)

			if err then
				return nil, err
			end

			return true
		end
	}
}
