local kong = kong
local REDIRECT_HEADERS = {
	Location = ""
}

return function (location, status)
	REDIRECT_HEADERS.Location = location

	return kong.response.exit(status or 302, "", REDIRECT_HEADERS)
end
