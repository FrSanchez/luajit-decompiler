local ngx_ssl = require("ngx.ssl")
local server_name = ngx_ssl.server_name
local _M = {}
local kong = kong

function _M.execute(snis_set)
	local server_name = server_name()
	local sni_mapping = server_name and snis_set[server_name] or snis_set["*"]

	if sni_mapping then
		kong.log.debug("enabled, will request certificate from client")

		local chain = nil

		if sni_mapping.ca_cert_chain then
			kong.log.debug("set client ca certificate chain")

			chain = sni_mapping.ca_cert_chain.ctx
		end

		local res, err = kong.client.tls.request_client_certificate(chain)

		if not res then
			kong.log.err("unable to request client to present its certificate: ", err)
		end

		res, err = kong.client.tls.disable_session_reuse()

		if not res then
			kong.log.err("unable to disable session reuse for client certificate: ", err)
		end
	end
end

return _M
