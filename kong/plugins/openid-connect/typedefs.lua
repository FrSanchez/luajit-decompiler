local schema = require("kong.db.schema")
local jwk = schema.define({
	required = false,
	type = "record",
	fields = {
		{
			issuer = {
				required = false,
				type = "string"
			}
		},
		{
			kty = {
				required = false,
				type = "string"
			}
		},
		{
			use = {
				required = false,
				type = "string"
			}
		},
		{
			key_ops = {
				required = false,
				type = "array",
				elements = {
					required = false,
					type = "string"
				}
			}
		},
		{
			alg = {
				required = false,
				type = "string"
			}
		},
		{
			kid = {
				required = false,
				type = "string"
			}
		},
		{
			x5u = {
				required = false,
				type = "string"
			}
		},
		{
			x5c = {
				required = false,
				type = "array",
				elements = {
					required = false,
					type = "string"
				}
			}
		},
		{
			x5t = {
				required = false,
				type = "string"
			}
		},
		{
			["x5t#S256"] = {
				required = false,
				type = "string"
			}
		},
		{
			k = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			x = {
				required = false,
				type = "string"
			}
		},
		{
			y = {
				required = false,
				type = "string"
			}
		},
		{
			crv = {
				required = false,
				type = "string"
			}
		},
		{
			n = {
				required = false,
				type = "string"
			}
		},
		{
			e = {
				required = false,
				type = "string"
			}
		},
		{
			d = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			p = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			q = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			dp = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			dq = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			qi = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			oth = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			r = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		},
		{
			t = {
				referenceable = true,
				required = false,
				encrypted = true,
				type = "string"
			}
		}
	}
})

return {
	jwk = jwk
}
