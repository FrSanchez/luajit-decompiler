local cjson = require("cjson.safe")
local utils = require("kong.tools.utils")
local time = ngx.time
local log = ngx.log
local INFO = ngx.INFO
local ERR = ngx.ERR
local DEBUG = ngx.DEBUG
local timer_at = ngx.timer.at
local sleep = ngx.sleep
local math_max = math.max
local knode = kong and kong.node and kong.node or require("kong.pdk.node").new()
local worker_count = ngx.worker.count()
local _log_prefix = "[counters] "
local STORAGE_KEY = "counters"
local FLUSH_LIST_KEY = "counters:flush_list"
local FLUSH_LOCK_KEY = "counters:flush_lock"
local _M = {}
local mt = {
	__index = _M
}
local persistence_handler = nil

function persistence_handler(premature, self)
	if premature then
		return
	end

	if self.hybrid_cp then
		return
	end

	local delay = self.flush_interval
	local when = delay - (ngx.now() - math.floor(ngx.now() / delay) * delay)

	if when < 1 then
		when = delay or when
	end

	local ok, err = timer_at(when, persistence_handler, self)

	if not ok then
		return nil, "failed to start recurring vitals timer (2): " .. err
	end

	local _, err = self:flush_counters()

	if err then
		log(ERR, _log_prefix, "flush_counters() threw an error: ", err)
	end
end

function _M.new(opts)
	local node_id, err = knode.get_id()

	if err then
		return nil, "error occurred during initialization phase of counters library"
	end

	local self = {
		name = opts.name or "counters:" .. tostring(utils.uuid()),
		node_id = node_id,
		list_cache = ngx.shared.kong_counters,
		flush_interval = opts.flush_interval or 15,
		counters = {
			start_at = time(),
			metrics = {}
		}
	}

	return setmetatable(self, mt)
end

function _M:init()
	local delay = self.flush_interval
	local when = delay - (ngx.now() - math.floor(ngx.now() / delay) * delay)

	log(INFO, _log_prefix, "starting counters timer (1) in ", when, " seconds")

	local ok, _ = timer_at(when, persistence_handler, self)

	if ok then
		self:reset_counters()
	end
end

local function build_flush_key(self)
	return FLUSH_LIST_KEY .. ":" .. self.name
end

local function build_storage_key(name)
	return name and STORAGE_KEY .. ":" .. name or STORAGE_KEY
end

function _M:flush_lock()
	local lock_key = FLUSH_LOCK_KEY .. ":" .. self.name
	local ok, err = self.list_cache:safe_add(lock_key, true, self.flush_interval - 0.01)

	if not ok then
		if err ~= "exists" then
			log(ERR, _log_prefix, "failed to acquire lock: ", err)
		end

		return false
	end

	return true
end

function _M:poll_worker_data(flush_key, expected)
	local i = 0
	expected = expected or worker_count

	while true do
		sleep(math_max(self.flush_interval / 100, 0.001))

		local num_posted, err = self.list_cache:llen(flush_key)

		if err then
			return nil, err
		end

		if num_posted == expected then
			break
		end

		i = i + 1

		if i > 10 then
			log(INFO, _log_prefix, num_posted, " of ", expected, " workers reported.")

			break
		end
	end

	return true
end

function _M:merge_worker_data(flush_key)
	local result_data = {}

	for key, _ in pairs(self.counters.metrics) do
		result_data[key] = {}
	end

	for item = 1, self.list_cache:llen(flush_key) do
		local encoded_data, err = self.list_cache:rpop(flush_key)

		if not encoded_data then
			return nil, err
		end

		local data = cjson.decode(encoded_data)

		for counter_key, _ in pairs(self.counters.metrics) do
			for j = 1, self.flush_interval do
				local time_unit = tostring(j - 1)
				local worker_data = data[counter_key][time_unit] or 0
				result_data[counter_key][time_unit] = result_data[counter_key][time_unit] and result_data[counter_key][time_unit] + worker_data or worker_data
			end
		end
	end

	return result_data
end

function _M:flush_counters()
	local counters = self.counters
	local lock = self:flush_lock()
	local flush_key = nil
	flush_key = build_flush_key(self)
	local data, err = cjson.encode(counters.metrics)

	if not data then
		return nil, "could not encode table value: " .. err
	end

	local ok, err = self.list_cache:rpush(flush_key, data)

	if not ok then
		log(ERR, _log_prefix, "error attempting to push to list: ", err)
	end

	self:reset_counters()

	if lock then
		log(DEBUG, _log_prefix, "pid ", ngx.worker.pid(), " acquired lock")

		local ok, err = self:poll_worker_data(flush_key)

		if not ok then
			return nil, err
		end

		log(DEBUG, _log_prefix, "merge worker data")

		local merged_data, err = self:merge_worker_data(flush_key)

		if not merged_data then
			return nil, err
		end

		log(DEBUG, _log_prefix, "encode merged workers data")

		local flush_data = {
			start_at = self.counters.start_at,
			data = merged_data
		}
		local encoded_flush_data, err = cjson.encode(flush_data)

		if not encoded_flush_data then
			return nil, "could not encode flush data: " .. err
		end

		log(DEBUG, _log_prefix, "store merged workers data")

		local storage_key = build_storage_key(self.name)
		local ok, err = self.list_cache:rpush(storage_key, encoded_flush_data)

		if not ok then
			log(ERR, _log_prefix, "error attempting to push to list: ", err)
		end
	end

	log(DEBUG, _log_prefix, "flush done")

	return true
end

function _M:reset_counters(counters_data)
	local counters = counters_data or self.counters
	counters.start_at = time()

	for key, _ in pairs(counters.metrics) do
		counters.metrics[key] = {}
	end

	return counters
end

function _M:current_bucket()
	local bucket = time() - self.counters.start_at

	if bucket > self.flush_interval - 1 then
		bucket = self.flush_interval - 1
	end

	return tostring(bucket)
end

function _M:add_key(key)
	if not self.counters.metrics[key] then
		self.counters.metrics[key] = {}
	end
end

function _M:increment(key)
	local bucket = self:current_bucket()

	if bucket then
		if not self.counters.metrics[key] then
			log(ERR, _log_prefix, "key does not exist: " .. key)

			return
		end

		if not self.counters.metrics[key][bucket] then
			self.counters.metrics[key][bucket] = 0
		end

		self.counters.metrics[key][bucket] = self.counters.metrics[key][bucket] + 1
	end
end

function _M:get_counters()
	local data = {}
	local storage_key = build_storage_key(self.name)

	for i = 1, self.list_cache:llen(storage_key) do
		local encoded_data, err = self.list_cache:rpop(storage_key)

		if not encoded_data then
			return nil, err
		end

		local decoded_data = cjson.decode(encoded_data)

		table.insert(data, decoded_data)
	end

	return data
end

return _M
