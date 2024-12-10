local log = require("kong.plugins.openid-connect.log")
local type = type
local ipairs = ipairs

local function new(args, oic, cache, ignore_signature)
	local opts, use_cache = nil

	return function (access_token, ttl)
		if not opts then
			use_cache = args.get_conf_arg("cache_user_info")
			local accept = args.get_conf_arg("userinfo_accept", "application/json")
			local endpoint = args.get_conf_arg("userinfo_endpoint")
			local client_headers = args.get_conf_arg("userinfo_headers_client")
			local client_args = args.get_conf_arg("userinfo_query_args_client")
			local headers = args.get_conf_args("userinfo_headers_names", "userinfo_headers_values")
			local qargs = args.get_conf_args("userinfo_query_args_names", "userinfo_query_args_values")

			if client_headers then
				log("parsing client headers for user info request")

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
				log("parsing client query arguments for user info request")

				for _, client_arg_name in ipairs(client_args) do
					local extra_arg = args.get_uri_arg(client_arg_name)

					if extra_arg then
						if type(qargs) ~= "table" then
							qargs = {}
						end

						qargs[client_arg_name] = extra_arg
					else
						extra_arg = args.get_post_arg(client_arg_name)

						if extra_arg then
							if type(qargs) ~= "table" then
								qargs = {}
							end

							qargs[client_arg_name] = extra_arg
						end
					end
				end
			end

			opts = {
				userinfo_format = "string",
				userinfo_endpoint = endpoint,
				headers = headers,
				query = qargs
			}
		end

		if use_cache then
			log("loading user info with caching enabled")
		else
			log("loading user info")
		end

		return cache.userinfo.load(oic, access_token, ttl, use_cache, ignore_signature, opts)
	end
end

return {
	new = new
}
