local ratelimiting = require("kong.tools.public.rate-limiting").new_instance("rate-limiting-advanced")
local schema = require("kong.plugins.rate-limiting-advanced.schema")
local event_hooks = require("kong.enterprise_edition.event_hooks")
local helpers = require("kong.enterprise_edition.consumer_groups_helpers")
local meta = require("kong.meta")
local uuid = require("kong.tools.uuid")
local pl_tablex = require("pl.tablex")
local ngx = ngx
local null = ngx.null
local kong = kong
local ceil = math.ceil
local floor = math.floor
local max = math.max
local min = math.min
local rand = math.random
local time = ngx.time
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local NewRLHandler = {
	PRIORITY = 910,
	VERSION = meta.core_version
}
local X_RATELIMIT_LIMIT = "X-RateLimit-Limit"
local X_RATELIMIT_REMAINING = "X-RateLimit-Remaining"
local RATELIMIT_LIMIT = "RateLimit-Limit"
local RATELIMIT_REMAINING = "RateLimit-Remaining"
local RATELIMIT_RESET = "RateLimit-Reset"
local RATELIMIT_RETRY_AFTER = "Retry-After"
local human_window_size_lookup = {
	"second",
	[60.0] = "minute",
	[3600.0] = "hour",
	[31536000.0] = "year",
	[2592000.0] = "month",
	[86400.0] = "day"
}
local id_lookup = {
	ip = function ()
		return kong.client.get_forwarded_ip()
	end,
	credential = function ()
		return kong.client.get_credential() and kong.client.get_credential().id
	end,
	consumer = function ()
		return kong.client.get_consumer() and kong.client.get_consumer().id or kong.client.get_credential() and kong.client.get_credential().id
	end,
	service = function ()
		return kong.router.get_service() and kong.router.get_service().id
	end,
	header = function (conf)
		return kong.request.get_header(conf.header_name)
	end,
	path = function (conf)
		return kong.request.get_path() == conf.path and conf.path
	end,
	["consumer-group"] = function (conf)
		local scoped_to_cg_id = conf.consumer_group_id

		if not scoped_to_cg_id then
			return nil
		end

		for _, cg in ipairs(kong.client.get_consumer_groups()) do
			if cg.id == scoped_to_cg_id then
				return cg.id
			end
		end

		return nil
	end
}

local function create_timer(config)
	local rate = config.sync_rate
	local namespace = config.namespace
	local timer_id = uuid.uuid()
	local now = ngx.now()
	local when = rate - (now - floor(now / rate) * rate)

	kong.log.debug("creating timer for namespace ", namespace, ", timer_id: ", timer_id, ", initial sync in ", when, " seconds")
	ngx.timer.at(when, ratelimiting.sync, namespace, timer_id)

	ratelimiting.config[namespace].timer_id = timer_id

	ratelimiting.fetch(nil, namespace, now, min(rate - 0.001, 2), true)
end

local function new_namespace(config, timer_id)
	if not config then
		kong.log.warn("[rate-limiting-advanced] no config was specified.", " Skipping the namespace creation.")

		return false
	end

	kong.log.debug("attempting to add namespace ", config.namespace)

	local ok, err = pcall(function ()
		local strategy = config.strategy == "cluster" and kong.configuration.database or "redis"
		local strategy_opts = strategy == "redis" and config.redis

		if config.strategy == "local" then
			config.sync_rate = -1
		end

		local dict_name = config.dictionary_name

		if dict_name == nil then
			dict_name = schema.fields.dictionary_name.default

			if dict_name then
				kong.log.warn("[rate-limiting-advanced] no shared dictionary was specified.", " Trying the default value '", dict_name, "'...")
			else
				kong.log.warn("[rate-limiting-advanced] no schema default was specified.", " Skipping the namespace creation.")

				return false
			end
		end

		if ngx.shared[dict_name] == nil then
			kong.log.notice("[rate-limiting-advanced] specified shared dictionary '", dict_name, "' doesn't exist. Falling back to the 'kong' shared dictionary")

			dict_name = "kong"
		end

		kong.log.notice("[rate-limiting-advanced] using shared dictionary '" .. dict_name .. "'")
		ratelimiting.new({
			namespace = config.namespace,
			sync_rate = config.sync_rate,
			strategy = strategy,
			strategy_opts = strategy_opts,
			dict = dict_name,
			window_sizes = config.window_size,
			db = kong.db,
			timer_id = timer_id
		})
	end)

	if not ok then
		kong.log.err("err in creating new ratelimit namespace: ", err)

		return false
	end

	return true
end

local sync_fields = {
	"window_size",
	"sync_rate",
	"strategy",
	"dictionary_name",
	"redis"
}

local function get_sync_conf(conf)
	local sync_conf = {}

	for _, k in ipairs(sync_fields) do
		sync_conf[k] = conf[k]
	end

	return sync_conf
end

local function are_same_config(conf1, conf2)
	return pl_tablex.deepcompare(conf1, conf2)
end

function NewRLHandler:init_worker()
	event_hooks.publish("rate-limiting-advanced", "rate-limit-exceeded", {
		description = "Run an event when a rate limit has been exceeded",
		fields = {
			"consumer",
			"ip",
			"service",
			"rate",
			"limit",
			"window"
		},
		unique = {
			"consumer",
			"ip",
			"service"
		}
	})
end

function NewRLHandler:configure(configs)
	local namespaces = {}

	if configs then
		for _, config in ipairs(configs) do
			local namespace = config.namespace
			local sync_rate = config.sync_rate

			if not sync_rate or sync_rate == null then
				sync_rate = -1
			end

			if namespaces[namespace] then
				if not are_same_config(namespaces[namespace], get_sync_conf(config)) then
					kong.log.err("multiple rate-limiting-advanced plugins with the namespace '", namespace, "' have different counter syncing configurations. Please correct them to use the same configuration.")
				end
			else
				namespaces[namespace] = get_sync_conf(config)
			end

			kong.log.debug("clear and reset ", namespace)

			if not ratelimiting.config[namespace] then
				new_namespace(config)
			else
				local timer_id = nil

				if sync_rate > 0 then
					timer_id = ratelimiting.config[namespace].timer_id
				end

				ratelimiting.clear_config(namespace)
				new_namespace(config, timer_id)

				if sync_rate > 0 and sync_rate < 1 then
					kong.log.warn("Config option 'sync_rate' " .. sync_rate .. " is between 0 and 1; a config update is recommended")
				end
			end
		end
	end

	for namespace in pairs(ratelimiting.config) do
		if not namespaces[namespace] then
			kong.log.debug("clearing old namespace ", namespace)

			ratelimiting.config[namespace].kill = true
			ratelimiting.config[namespace].timer_id = nil
		end
	end
end

function NewRLHandler:access(conf)
	local namespace = conf.namespace
	local now = time()
	local key = id_lookup[conf.identifier](conf)
	key = key or id_lookup.ip()
	local deny_window_index = nil

	if not ratelimiting.config[namespace] then
		new_namespace(conf)
	end

	if conf.sync_rate > 0 and not ratelimiting.config[namespace].timer_id then
		create_timer(conf)
	end

	local config = nil

	if conf.enforce_consumer_groups and kong.client.get_consumer() and conf.consumer_groups then
		local consumer = kong.client.get_consumer()

		for i = 1, #conf.consumer_groups do
			local consumer_group = helpers.get_consumer_group(conf.consumer_groups[i])

			if consumer_group and helpers.is_consumer_in_group(consumer.id, consumer_group.id) then
				local config_raw = helpers.get_consumer_group_config(consumer_group.id, "rate-limiting-advanced")

				if config_raw then
					config = config_raw.config

					break
				end

				kong.log.warn("Consumer group " .. consumer_group.name .. " enforced but no consumer group configurations provided. Original plugin configurations will apply.")

				break
			end
		end
	end

	config = config or conf
	local limit, window, remaining, reset = nil
	local window_type = config.window_type
	local shm = ngx.shared[conf.dictionary_name]
	local headers_rl = {}

	for i = 1, #config.window_size do
		local current_window = tonumber(config.window_size[i])
		local current_limit = tonumber(config.limit[i])
		local rate = nil

		if deny_window_index then
			rate = ratelimiting.sliding_window(key, current_window, nil, namespace)
		else
			rate = ratelimiting.increment(key, current_window, 1, namespace, config.window_type == "fixed" and 0 or nil)
		end

		local window_start = floor(now / current_window) * current_window
		local window_start_timstamp_key = "timestamp:" .. current_window .. ":window_start"

		if current_limit < rate and window_type == "sliding" then
			shm:add(window_start_timstamp_key, window_start)

			window_start = shm:get(window_start_timstamp_key) or window_start
		else
			shm:delete(window_start_timstamp_key)
		end

		local window_name = human_window_size_lookup[current_window] or current_window
		local current_remaining = floor(max(current_limit - rate, 0))

		if not conf.hide_client_headers then
			headers_rl[X_RATELIMIT_LIMIT .. "-" .. window_name] = current_limit
			headers_rl[X_RATELIMIT_REMAINING .. "-" .. window_name] = current_remaining

			if not limit or current_remaining < remaining or current_remaining == remaining and window < current_window then
				limit = current_limit
				window = current_window
				remaining = current_remaining
				reset = max(1, window - (now - window_start))

				if window_type == "sliding" then
					local window_adjustment = max(0, (rate - limit) / limit * window)
					reset = ceil(reset + window_adjustment)
				end
			end
		end

		if current_limit < rate then
			deny_window_index = i
			local ok, err = event_hooks.emit("rate-limiting-advanced", "rate-limit-exceeded", {
				consumer = kong.client.get_consumer() or {},
				ip = kong.client.get_forwarded_ip(),
				service = kong.router.get_service() or {},
				rate = rate,
				limit = current_limit,
				window = window_name
			})

			if not ok then
				kong.log.warn("failed to emit event: ", err)
			end
		end
	end

	headers_rl[RATELIMIT_LIMIT] = limit
	headers_rl[RATELIMIT_REMAINING] = remaining
	headers_rl[RATELIMIT_RESET] = reset

	if deny_window_index then
		local retry_after = reset
		local jitter_max = config.retry_after_jitter_max

		if retry_after and jitter_max > 0 then
			retry_after = retry_after + rand(jitter_max)
		end

		headers_rl[RATELIMIT_RETRY_AFTER] = retry_after

		if conf.disable_penalty and window_type == "sliding" then
			for i = 1, deny_window_index do
				local current_window = tonumber(config.window_size[i])

				ratelimiting.increment(key, current_window, -1, namespace, 0)
			end
		end

		return kong.response.exit(conf.error_code, {
			message = conf.error_message
		}, headers_rl)
	else
		kong.response.set_headers(headers_rl)
	end
end

return NewRLHandler
