local typedefs = require("kong.db.schema.typedefs")

return {
	name = "aws-lambda",
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
						timeout = {
							type = "number",
							default = 60000,
							required = true,
							description = "An optional timeout in milliseconds when invoking the function."
						}
					},
					{
						keepalive = {
							type = "number",
							default = 60000,
							required = true,
							description = "An optional value in milliseconds that defines how long an idle connection lives before being closed."
						}
					},
					{
						aws_key = {
							type = "string",
							encrypted = true,
							description = "The AWS key credential to be used when invoking the function.",
							referenceable = true
						}
					},
					{
						aws_secret = {
							type = "string",
							encrypted = true,
							description = "The AWS secret credential to be used when invoking the function. ",
							referenceable = true
						}
					},
					{
						aws_assume_role_arn = {
							type = "string",
							encrypted = true,
							description = "The target AWS IAM role ARN used to invoke the Lambda function.",
							referenceable = true
						}
					},
					{
						aws_role_session_name = {
							type = "string",
							default = "kong",
							description = "The identifier of the assumed role session."
						}
					},
					{
						aws_region = typedefs.host
					},
					{
						function_name = {
							type = "string",
							description = "The AWS Lambda function to invoke. Both function name and function ARN (including partial) are supported.",
							required = false
						}
					},
					{
						qualifier = {
							type = "string",
							description = "The qualifier to use when invoking the function."
						}
					},
					{
						invocation_type = {
							type = "string",
							description = "The InvocationType to use when invoking the function. Available types are RequestResponse, Event, DryRun.",
							default = "RequestResponse",
							required = true,
							one_of = {
								"RequestResponse",
								"Event",
								"DryRun"
							}
						}
					},
					{
						log_type = {
							type = "string",
							description = "The LogType to use when invoking the function. By default, None and Tail are supported.",
							default = "Tail",
							required = true,
							one_of = {
								"Tail",
								"None"
							}
						}
					},
					{
						host = typedefs.host
					},
					{
						port = typedefs.port({
							default = 443
						})
					},
					{
						disable_https = {
							type = "boolean",
							default = false
						}
					},
					{
						unhandled_status = {
							type = "integer",
							description = "The response status code to use (instead of the default 200, 202, or 204) in the case of an Unhandled Function Error.",
							between = {
								100,
								999
							}
						}
					},
					{
						forward_request_method = {
							type = "boolean",
							default = false,
							description = "An optional value that defines whether the original HTTP request method verb is sent in the request_method field of the JSON-encoded request."
						}
					},
					{
						forward_request_uri = {
							type = "boolean",
							default = false,
							description = "An optional value that defines whether the original HTTP request URI is sent in the request_uri field of the JSON-encoded request."
						}
					},
					{
						forward_request_headers = {
							type = "boolean",
							default = false,
							description = "An optional value that defines whether the original HTTP request headers are sent as a map in the request_headers field of the JSON-encoded request."
						}
					},
					{
						forward_request_body = {
							type = "boolean",
							default = false,
							description = "An optional value that defines whether the request body is sent in the request_body field of the JSON-encoded request. If the body arguments can be parsed, they are sent in the separate request_body_args field of the request. "
						}
					},
					{
						is_proxy_integration = {
							type = "boolean",
							default = false,
							description = "An optional value that defines whether the response format to receive from the Lambda to this format."
						}
					},
					{
						awsgateway_compatible = {
							type = "boolean",
							default = false,
							description = "An optional value that defines whether the plugin should wrap requests into the Amazon API gateway."
						}
					},
					{
						proxy_url = typedefs.url
					},
					{
						skip_large_bodies = {
							type = "boolean",
							default = true,
							description = "An optional value that defines whether Kong should send large bodies that are buffered to disk"
						}
					},
					{
						base64_encode_body = {
							type = "boolean",
							default = true,
							description = "An optional value that Base64-encodes the request body."
						}
					},
					{
						aws_imds_protocol_version = {
							type = "string",
							description = "Identifier to select the IMDS protocol version to use: `v1` or `v2`.",
							default = "v1",
							required = true,
							one_of = {
								"v1",
								"v2"
							}
						}
					},
					{
						empty_arrays_mode = {
							type = "string",
							description = "An optional value that defines whether Kong should send empty arrays (returned by Lambda function) as `[]` arrays or `{}` objects in JSON responses. The value `legacy` means Kong will send empty arrays as `{}` objects in response",
							default = "legacy",
							required = true,
							one_of = {
								"legacy",
								"correct"
							}
						}
					}
				}
			}
		}
	},
	entity_checks = {
		{
			mutually_required = {
				"config.aws_key",
				"config.aws_secret"
			}
		},
		{
			custom_entity_check = {
				field_sources = {
					"config.proxy_url"
				},
				fn = function (entity)
					local proxy_url = entity.config and entity.config.proxy_url

					if type(proxy_url) == "string" then
						local scheme = proxy_url:match("^([^:]+)://")

						if scheme and scheme ~= "http" then
							return nil, "proxy_url scheme must be http"
						end
					end

					return true
				end
			}
		}
	}
}
