local version = setmetatable({
	patch = 0,
	minor = 5,
	major = 3,
	ee_patch = 1
}, {
	__tostring = function (t)
		return string.format("%d.%d.%d.%d%s", t.major, t.minor, t.patch, t.ee_patch, t.suffix or "")
	end
})

return {
	_VERSION = tostring(version) .. "-enterprise-edition",
	_VERSION_TABLE = version,
	_SERVER_TOKENS = "kong/" .. tostring(version) .. "-enterprise-edition",
	version = tostring(version)
}
