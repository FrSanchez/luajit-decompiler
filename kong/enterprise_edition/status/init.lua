local workspaces = require("kong.workspaces")
local utils = require("kong.tools.utils")
local fmt = string.format
local kong = kong
local ngx = ngx
local unescape_uri = ngx.unescape_uri
local _M = {
	before_filter = function (self)
		local req_id = utils.random_string()
		ngx.ctx.admin_api = {
			req_id = req_id
		}
		ngx.header["X-Kong-Status-Request-ID"] = req_id
		ngx.ctx.rbac = nil

		workspaces.set_workspace(nil)

		local ws_name = workspaces.DEFAULT_WORKSPACE

		if self.params.workspace_name then
			ws_name = unescape_uri(self.params.workspace_name)
		end

		local workspace, err = workspaces.select_workspace_by_name_with_cache(ws_name)

		if err then
			ngx.log(ngx.ERR, err)

			return kong.response.exit(500, {
				message = err
			})
		end

		if not workspace then
			kong.response.exit(404, {
				message = fmt("Workspace '%s' not found", ws_name)
			})
		end

		workspaces.set_workspace(workspace)

		self.params.workspace_name = nil
	end
}

return _M
