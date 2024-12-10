local scope = {}

function scope.run_with_ws_scope(ws, cb, ...)
	assert(type(ws) == "table" and ws.id, "ws must be a workspace table")

	local old_ws = ngx.ctx.workspace
	ngx.ctx.workspace = ws.id
	local res, err = cb(...)
	ngx.ctx.workspace = old_ws

	return res, err
end

return scope
