local operations = require("kong.db.migrations.operations.280_to_300")

local function ws_migration_teardown(ops)
	return function (connector)
		ops:fixup_plugin_config(connector, "openid-connect", function (config)
			if config.session_redis_password == nil then
				config.session_redis_password = config.session_redis_auth
			end

			config.session_redis_auth = nil

			return true
		end)
	end
end

return {
	postgres = {
		up = "",
		teardown = ws_migration_teardown(operations.postgres.teardown)
	}
}
