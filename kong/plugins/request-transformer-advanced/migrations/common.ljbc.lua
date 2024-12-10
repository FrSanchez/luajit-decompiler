local utils = require("kong.tools.utils")
local _M = {
	rt_rename = function (_, _, dao)
		local plugins, err = dao.plugins:find_all({
			name = "request-transformer"
		})

		if err then
			return err
		end

		for i = 1, #plugins do
			local plugin = plugins[i]
			local _, err = dao.plugins:insert({
				name = "request-transformer-advanced",
				api_id = plugin.api_id,
				consumer_id = plugin.consumer_id,
				enabled = plugin.enabled,
				config = utils.cycle_aware_deep_copy(plugin.config)
			})

			if err then
				return err
			end

			local _, err = dao.plugins:delete(plugin, {
				quite = true
			})

			if err then
				return err
			end
		end
	end
}

return _M
