local websocket = {}
local new_tab = require("table.new")
local nrec = 7

function websocket.init_state(ctx)
	local client = new_tab(0, nrec)
	client.role = "client"
	ctx.KONG_WEBSOCKET_CLIENT = client
	local upstream = new_tab(0, nrec)
	upstream.role = "upstream"
	ctx.KONG_WEBSOCKET_UPSTREAM = upstream
end

function websocket.get_state(ctx, role)
	local key = role == "client" and "KONG_WEBSOCKET_CLIENT" or "KONG_WEBSOCKET_UPSTREAM"
	local state = ctx[key]

	if not state then
		error("ctx." .. key .. " does not exist")
	end

	return state
end

return websocket
