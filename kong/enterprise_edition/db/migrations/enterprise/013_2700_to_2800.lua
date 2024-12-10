return {
	postgres = {
		teardown = function (connector)
			local _, err = connector:query("        DELETE FROM workspace_entity_counters\n              WHERE entity_type = 'oauth2_tokens';\n      ")

			return err == nil, err
		end
	}
}
