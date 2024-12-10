return function (plugin_name)
	local Schema = require("kong.db.schema")
	local typedefs = require("kong.db.schema.typedefs")
	local loadstring = loadstring

	local function validate_function(fun)
		local _, err = loadstring(fun)

		if err then
			return false, "error parsing " .. plugin_name .. ": " .. err
		end

		return true
	end

	local phase_functions = Schema.define({
		required = true,
		type = "array",
		description = "Custom functions, which can be user-defined, are cached and executed sequentially during specific phases: `certificate`, `rewrite`, `access`, `header_filter`, `body_filter`, and `log`.",
		default = {},
		elements = {
			required = false,
			type = "string",
			custom_validator = validate_function
		}
	})

	return {
		name = plugin_name,
		fields = {
			{
				protocols = typedefs.protocols_http_and_ws({
					required = false
				})
			},
			{
				consumer = typedefs.no_consumer
			},
			{
				consumer_group = typedefs.no_consumer_group
			},
			{
				protocols = typedefs.protocols
			},
			{
				config = {
					type = "record",
					fields = {
						{
							certificate = phase_functions
						},
						{
							rewrite = phase_functions
						},
						{
							access = phase_functions
						},
						{
							header_filter = phase_functions
						},
						{
							body_filter = phase_functions
						},
						{
							log = phase_functions
						},
						{
							ws_handshake = phase_functions
						},
						{
							ws_client_frame = phase_functions
						},
						{
							ws_upstream_frame = phase_functions
						},
						{
							ws_close = phase_functions
						}
					}
				}
			}
		},
		entity_checks = {
			{
				at_least_one_of = {
					"config.certificate",
					"config.rewrite",
					"config.access",
					"config.header_filter",
					"config.body_filter",
					"config.log",
					"config.ws_handshake",
					"config.ws_upstream_frame",
					"config.ws_client_frame",
					"config.ws_close"
				}
			}
		}
	}
end
