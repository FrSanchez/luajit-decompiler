local typedefs = require("kong.db.schema.typedefs")
local rule = {
	type = "record",
	fields = {
		{
			upstream_name = {
				required = true,
				type = "string"
			}
		},
		{
			condition = {
				type = "map",
				required = true,
				len_min = 1,
				keys = {
					type = "string"
				},
				values = {
					type = "string"
				}
			}
		}
	}
}

return {
	name = "route-by-header",
	fields = {
		{
			protocols = typedefs.protocols_http
		},
		{
			consumer_group = typedefs.no_consumer_group
		},
		{
			config = {
				type = "record",
				fields = {
					{
						rules = {
							type = "array",
							description = "Route by header rules.",
							default = {},
							elements = rule
						}
					}
				}
			}
		}
	}
}
