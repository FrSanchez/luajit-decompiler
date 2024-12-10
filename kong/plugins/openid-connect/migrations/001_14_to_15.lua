return {
	postgres = {
		up = "      -- Unique constraint on \"issuer\" already adds btree index\n      DROP INDEX IF EXISTS \"oic_issuers_idx\";\n    "
	}
}
