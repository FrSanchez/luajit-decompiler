local _M = {
	CONSUMERS = {
		STATUS = {
			UNVERIFIED = 5,
			INVITED = 4,
			REVOKED = 3,
			REJECTED = 2,
			PENDING = 1,
			APPROVED = 0
		},
		TYPE = {
			PROXY = 0,
			APPLICATION = 3,
			ADMIN = 2,
			DEVELOPER = 1
		},
		STATUS_LABELS = {},
		TYPE_LABELS = {}
	},
	TOKENS = {
		STATUS = {
			INVALIDATED = 3,
			CONSUMED = 2,
			PENDING = 1
		}
	}
}

for k, v in pairs(_M.CONSUMERS.STATUS) do
	_M.CONSUMERS.STATUS_LABELS[v] = k
end

for k, v in pairs(_M.CONSUMERS.TYPE) do
	_M.CONSUMERS.TYPE_LABELS[v] = k
end

return _M
