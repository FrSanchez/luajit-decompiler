local access = require("kong.plugins.request-transformer-advanced.access")
local meta = require("kong.meta")
local RequestTransformerHandler = {
	access = function (self, conf)
		access.execute(conf)
	end,
	VERSION = meta.core_version,
	PRIORITY = 802
}

return RequestTransformerHandler
