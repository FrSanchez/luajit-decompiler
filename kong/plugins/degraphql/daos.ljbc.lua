local typedefs = require("kong.db.schema.typedefs")

return {
	{
		name = "degraphql_routes",
		endpoint_key = "id",
		primary_key = {
			"id"
		},
		fields = {
			{
				id = typedefs.uuid
			},
			{
				service = {
					type = "foreign",
					reference = "services"
				}
			},
			{
				methods = {
					type = "set",
					elements = typedefs.http_method,
					default = {
						"GET"
					}
				}
			},
			{
				uri = {
					type = "string",
					required = true
				}
			},
			{
				query = {
					type = "string",
					required = true
				}
			},
			{
				created_at = typedefs.auto_timestamp_s
			},
			{
				updated_at = typedefs.auto_timestamp_s
			}
		}
	}
}
