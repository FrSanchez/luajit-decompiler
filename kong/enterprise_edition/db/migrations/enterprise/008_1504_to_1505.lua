return {
	postgres = {
		up = "      -- update all old records that doesn't have current timestamp for `license_creation_date` field after migrations\n      UPDATE license_data SET license_creation_date = CURRENT_TIMESTAMP WHERE license_creation_date IS NULL;\n    ",
		teardown = function (connector)
		end
	}
}
