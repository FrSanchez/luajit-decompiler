local real_getinfo = debug.getinfo

function debug.getinfo(arg, flags)
	if type(arg) == "number" then
		local info = real_getinfo(arg + 1, flags)

		if info and info.source then
			info.source = info.source:gsub("@/tmp/build", "@")
		end

		return info
	else
		return real_getinfo(arg, flags)
	end
end
