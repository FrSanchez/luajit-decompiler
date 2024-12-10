local operations = require("kong.enterprise_edition.db.migrations.operations.1500_to_2100")
local log = require("kong.cmd.utils.log")
local postgres_has_workspace_enitites = operations.utils.postgres_has_workspace_entities

return {
	postgres = {
		up = "",
		teardown = function (connector)
			if not postgres_has_workspace_enitites(nil, connector)[1] then
				return nil
			end

			local _, err = connector:query([[

        -- revert consumers ws_id from workspace_entities table

        UPDATE consumers
        SET ws_id = we.workspace_id
        FROM workspace_entities we
        WHERE entity_type='consumers'
          AND unique_field_name='id'
          AND unique_field_value=consumers.id::text;
      ]])

			if err then
				log.debug(err)
			end
		end
	}
}
