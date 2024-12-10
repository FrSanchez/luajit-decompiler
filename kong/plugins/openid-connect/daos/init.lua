local typedefs = require("kong.db.schema.typedefs")
local oidcdefs = require("kong.plugins.openid-connect.typedefs")

return {
	{
		name = "oic_issuers",
		generate_admin_api = false,
		endpoint_key = "issuer",
		primary_key = {
			"id"
		},
		cache_key = {
			"issuer"
		},
		fields = {
			{
				id = typedefs.uuid
			},
			{
				issuer = typedefs.url({
					required = true,
					unique = true
				})
			},
			{
				configuration = {
					required = true,
					type = "string"
				}
			},
			{
				keys = {
					required = true,
					type = "string"
				}
			},
			{
				secret = {
					referenceable = true,
					type = "string",
					required = true,
					encrypted = true
				}
			},
			{
				created_at = typedefs.auto_timestamp_s
			}
		}
	},
	{
		name = "oic_jwks",
		dao = "kong.plugins.openid-connect.daos.jwks",
		generate_admin_api = false,
		primary_key = {
			"id"
		},
		fields = {
			{
				id = {
					type = "string",
					eq = "c3cfba2d-1617-453f-a416-52e6edb5f9a0",
					uuid = true,
					default = "c3cfba2d-1617-453f-a416-52e6edb5f9a0",
					auto = false
				}
			},
			{
				jwks = {
					type = "record",
					required = true,
					fields = {
						{
							keys = {
								type = "array",
								required = true,
								elements = oidcdefs.jwk
							}
						}
					}
				}
			}
		}
	}
}
