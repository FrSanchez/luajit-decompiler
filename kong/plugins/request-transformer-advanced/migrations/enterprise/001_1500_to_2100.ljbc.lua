local operations = require("kong.enterprise_edition.db.migrations.operations.1500_to_2100")

local function ws_migration_teardown(ops)
	return function (connector)
		ops:fixup_plugin_config(connector, "request-transformer-advanced", function (config)
			config.allow = config.whitelist
			config.whitelist = nil

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
