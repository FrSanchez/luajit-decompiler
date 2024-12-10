local tls = {}
local utils = require("kong.tools.utils")
local match = string.match
local get_cn_parent_domain = utils.get_cn_parent_domain
local common_name_allowed = nil
local cache = setmetatable({}, {
	__mode = "k"
})

function common_name_allowed(kong_config, cp_cert, dp_x509)
	local dp_cn, err = get_cn_parent_domain(dp_x509)

	if not dp_cn then
		return false, "data plane presented incorrect client certificate " .. "during handshake, unable to extract CN: " .. tostring(err)
	end

	local allowed = cache[kong_config]

	if not allowed then
		if kong_config.cluster_allowed_common_names and #kong_config.cluster_allowed_common_names > 0 then
			allowed = {}

			for _, name in ipairs(kong_config.cluster_allowed_common_names) do
				allowed[name] = true
			end
		else
			allowed = setmetatable({}, {
				__index = function (_, k)
					return match(k, "^[%a%d-]+%.(.+)$") == cp_cert.parent_common_name
				end
			})
		end

		cache[kong_config] = allowed
	end

	if allowed[dp_cn] then
		return true
	else
		return false, "data plane presented client certificate with incorrect " .. "CN during handshake, got: " .. dp_cn
	end
end

function tls.ee_validate_client_cert(kong_config, cp_cert, dp_x509)
	if kong_config.cluster_mtls == "pki_check_cn" then
		local allow, err = common_name_allowed(kong_config, cp_cert, dp_x509)

		if not allow then
			return false, err
		end
	end

	return true
end

return tls
