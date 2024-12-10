local typedefs = require("kong.db.schema.typedefs")

return {
	name = "degraphql",
	fields = {
		{
			consumer = typedefs.no_consumer
		},
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
						graphql_server_path = typedefs.path({
							default = "/graphql",
							required = true
						})
					}
				}
			}
		}
	}
}
