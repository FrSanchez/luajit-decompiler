local log = require("kong.plugins.openid-connect.log")
local type = type
local ipairs = ipairs

local function new(args, oic, cache, ignore_signature)
	local opts, hint, use_cache = nil

	return function (access_token, ttl)
		if not opts then
			use_cache = args.get_conf_arg("cache_introspection")
			hint = args.get_conf_arg("introspection_hint", "access_token")
			local accept = args.get_conf_arg("introspection_accept", "application/json")
			local endpoint = args.get_conf_arg("introspection_endpoint")
			local auth_method = args.get_conf_arg("introspection_endpoint_auth_method")
			local client_headers = args.get_conf_arg("introspection_headers_client")
			local client_args = args.get_conf_arg("introspection_post_args_client")
			local headers = args.get_conf_args("introspection_headers_names", "introspection_headers_values")
			local pargs = args.get_conf_args("introspection_post_args_names", "introspection_post_args_values")
			local token_param_name = args.get_conf_arg("introspection_token_param_name")

			if client_headers then
				log("parsing client headers for introspection request")

				for _, header_name in ipairs(client_headers) do
					local header_value = args.get_header(header_name)

					if header_value then
						headers = headers or {}
						headers[header_name] = header_value
					end
				end
			end

			if accept then
				headers = headers or {}
				headers.Accept = accept
			end

			if client_args then
				log("parsing client post arguments for introspection request")

				for _, client_arg_name in ipairs(client_args) do
					local extra_arg = args.get_uri_arg(client_arg_name)

					if extra_arg then
						if type(pargs) ~= "table" then
							pargs = {}
						end

						pargs[client_arg_name] = extra_arg
					else
						extra_arg = args.get_post_arg(client_arg_name)

						if extra_arg then
							if type(pargs) ~= "table" then
								pargs = {}
							end

							pargs[client_arg_name] = extra_arg
						end
					end
				end
			end

			opts = {
				introspection_format = "string",
				introspection_endpoint = endpoint,
				introspection_endpoint_auth_method = auth_method,
				headers = headers,
				args = pargs,
				token_param_name = token_param_name
			}
		end

		if use_cache then
			log("introspecting token with caching enabled")
		else
			log("introspecting token")
		end

		return cache.introspection.load(oic, access_token, hint, ttl, use_cache, ignore_signature, opts)
	end
end

return {
	new = new
}
