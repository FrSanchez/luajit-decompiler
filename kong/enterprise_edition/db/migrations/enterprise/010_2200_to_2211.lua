return {
	postgres = {
		up = "      -- new vitals tables\n      CREATE TABLE IF NOT EXISTS vitals_stats_days (LIKE vitals_stats_minutes INCLUDING defaults INCLUDING constraints INCLUDING indexes);\n    ",
		teardown = function (connector)
		end
	}
}
