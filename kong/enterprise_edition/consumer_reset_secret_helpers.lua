local ee_jwt = require("kong.enterprise_edition.jwt")
local enums = require("kong.enterprise_edition.dao.enums")
local INVALIDATED = enums.TOKENS.STATUS.INVALIDATED
local PENDING = enums.TOKENS.STATUS.PENDING
local CONSUMED = enums.TOKENS.STATUS.CONSUMED
local _M = {}
local null = ngx.null

function _M.create(consumer, client_addr, expiry)
	local ok, err = _M.invalidate_pending_resets(consumer)

	if not ok then
		return nil, err
	end

	local row, err = kong.db.consumer_reset_secrets:insert({
		consumer = {
			id = consumer.id
		},
		client_addr = client_addr
	}, {
		workspace = null
	})

	if err then
		return nil, err
	end

	local claims = {
		id = consumer.id,
		exp = ngx.time() + expiry
	}
	local jwt, err = ee_jwt.generate_JWT(claims, row.secret)

	if err then
		return nil, err
	end

	return jwt
end

function _M.invalidate_pending_resets(consumer)
	for secret, err in kong.db.consumer_reset_secrets:each_for_consumer({
		id = consumer.id
	}) do
		if err then
			return nil, err
		end

		if secret.status == PENDING then
			local _, err = kong.db.consumer_reset_secrets:update({
				id = secret.id
			}, {
				status = INVALIDATED
			})

			if err then
				return nil, err
			end
		end
	end

	return true
end

function _M.consume_secret(secret_id)
	return kong.db.consumer_reset_secrets:update({
		id = secret_id
	}, {
		status = CONSUMED
	})
end

return _M
