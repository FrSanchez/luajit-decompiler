local redis = require("kong.enterprise_edition.redis")
local typedefs = require("kong.db.schema.typedefs")
local ngx = ngx
local concat = table.concat

local function check_shdict(name)
	if not ngx.shared[name] then
		return false, "missing shared dict '" .. name .. "'"
	end

	return true
end

return {
	name = "rate-limiting-advanced",
	fields = {
		{
			protocols = typedefs.protocols_http
		},
		{
			config = {
				type = "record",
				fields = {
					{
						identifier = {
							type = "string",
							default = "consumer",
							description = "The type of identifier used to generate the rate limit key. Defines the scope used to increment the rate limiting counters. Can be `ip`, `credential`, `consumer`, `service`, `header`, `path` or `consumer-group`.",
							required = true,
							one_of = {
								"ip",
								"credential",
								"consumer",
								"service",
								"header",
								"path",
								"consumer-group"
							}
						}
					},
					{
						window_size = {
							type = "array",
							required = true,
							description = "One or more window sizes to apply a limit to (defined in seconds). There must be a matching number of window limits and sizes specified.",
							elements = {
								type = "number"
							}
						}
					},
					{
						window_type = {
							type = "string",
							default = "sliding",
							description = "Sets the time window type to either `sliding` (default) or `fixed`. Sliding windows apply the rate limiting logic while taking into account previous hit rates (from the window that immediately precedes the current) using a dynamic weight. Fixed windows consist of buckets that are statically assigned to a definitive time range, each request is mapped to only one fixed window based on its timestamp and will affect only that window's counters.",
							one_of = {
								"fixed",
								"sliding"
							}
						}
					},
					{
						limit = {
							type = "array",
							required = true,
							description = "One or more requests-per-window limits to apply. There must be a matching number of window limits and sizes specified.",
							elements = {
								type = "number"
							}
						}
					},
					{
						sync_rate = {
							type = "number",
							description = "How often to sync counter data to the central data store. A value of 0 results in synchronous behavior; a value of -1 ignores sync behavior entirely and only stores counters in node memory. A value greater than 0 will sync the counters in the specified number of seconds. The minimum allowed interval is 0.02 seconds (20ms)."
						}
					},
					{
						namespace = {
							type = "string",
							required = true,
							auto = true,
							description = "The rate limiting library namespace to use for this plugin instance. Counter data and sync configuration is isolated in each namespace. NOTE: For the plugin instances sharing the same namespace, all the configurations that are required for synchronizing counters, e.g. `strategy`, `redis`, `sync_rate`, `window_size`, `dictionary_name`, need to be the same."
						}
					},
					{
						strategy = {
							type = "string",
							default = "local",
							description = "The rate-limiting strategy to use for retrieving and incrementing the limits. Available values are: `local` and `cluster`.",
							required = true,
							one_of = {
								"cluster",
								"redis",
								"local"
							}
						}
					},
					{
						dictionary_name = {
							type = "string",
							required = true,
							default = "kong_rate_limiting_counters",
							description = "The shared dictionary where counters are stored. When the plugin is configured to synchronize counter data externally (that is `config.strategy` is `cluster` or `redis` and `config.sync_rate` isn't `-1`), this dictionary serves as a buffer to populate counters in the data store on each synchronization cycle."
						}
					},
					{
						hide_client_headers = {
							type = "boolean",
							default = false,
							description = "Optionally hide informative response headers that would otherwise provide information about the current status of limits and counters."
						}
					},
					{
						retry_after_jitter_max = {
							type = "number",
							default = 0,
							description = "The upper bound of a jitter (random delay) in seconds to be added to the `Retry-After` header of denied requests (status = `429`) in order to prevent all the clients from coming back at the same time. The lower bound of the jitter is `0`; in this case, the `Retry-After` header is equal to the `RateLimit-Reset` header."
						}
					},
					{
						header_name = typedefs.header_name
					},
					{
						path = typedefs.path
					},
					{
						redis = redis.config_schema
					},
					{
						enforce_consumer_groups = {
							type = "boolean",
							default = false,
							description = "Determines if consumer groups are allowed to override the rate limiting settings for the given Route or Service. Flipping `enforce_consumer_groups` from `true` to `false` disables the group override, but does not clear the list of consumer groups. You can then flip `enforce_consumer_groups` to `true` to re-enforce the groups."
						}
					},
					{
						consumer_groups = {
							type = "array",
							description = "List of consumer groups allowed to override the rate limiting settings for the given Route or Service. Required if `enforce_consumer_groups` is set to `true`.",
							elements = {
								type = "string"
							}
						}
					},
					{
						disable_penalty = {
							type = "boolean",
							default = false,
							description = "If set to `true`, this doesn't count denied requests (status = `429`). If set to `false`, all requests, including denied ones, are counted. This parameter only affects the `sliding` window_type."
						}
					},
					{
						error_code = {
							type = "number",
							gt = 0,
							default = 429,
							description = "Set a custom error code to return when the rate limit is exceeded."
						}
					},
					{
						error_message = {
							type = "string",
							default = "API rate limit exceeded",
							description = "Set a custom error message to return when the rate limit is exceeded."
						}
					}
				}
			}
		}
	},
	entity_checks = {
		{
			custom_entity_check = {
				field_sources = {
					"config"
				},
				fn = function (entity)
					local config = entity.config

					if not config.limit or not config.window_size then
						return true
					end

					if #config.window_size ~= #config.limit then
						return nil, "You must provide the same number of windows and limits"
					end

					local t = {}

					for i, v in ipairs(config.limit) do
						t[i] = {
							config.limit[i],
							config.window_size[i]
						}
					end

					table.sort(t, function (a, b)
						return tonumber(a[1]) < tonumber(b[1])
					end)

					for i = 1, #t do
						config.limit[i] = tonumber(t[i][1])
						config.window_size[i] = tonumber(t[i][2])
					end

					if config.strategy == "cluster" and config.sync_rate ~= -1 and (kong.configuration.role ~= "traditional" or kong.configuration.database == "off") then
						return nil, concat({
							"[rate-limiting-advanced] ",
							"strategy 'cluster' is not supported with Hybrid deployments or DB-less mode. ",
							"If you did not specify the strategy, please use 'redis' strategy, 'local' strategy ",
							"or set 'sync_rate' to -1."
						})
					end

					if config.strategy == "redis" and config.redis.host == ngx.null and config.redis.sentinel_addresses == ngx.null and config.redis.cluster_addresses == ngx.null then
						return nil, "No redis config provided"
					end

					if config.strategy == "local" then
						if config.sync_rate ~= ngx.null and config.sync_rate > -1 then
							return nil, "sync_rate cannot be configured when using a local strategy"
						end

						config.sync_rate = -1
					elseif config.sync_rate == ngx.null then
						return nil, "sync_rate is required if not using a local strategy"
					end

					if config.dictionary_name ~= nil then
						local ok, err = check_shdict(config.dictionary_name)

						if not ok then
							return nil, err
						end
					end

					if config.identifier == "header" and config.header_name == ngx.null then
						return nil, "No header name provided"
					end

					if config.identifier == "path" and config.path == ngx.null then
						return nil, "No path provided"
					end

					if config.retry_after_jitter_max < 0 then
						return nil, "Non-negative retry_after_jitter_max value is expected"
					end

					if config.sync_rate > 0 and config.sync_rate < 0.02 then
						return nil, "Config option 'sync_rate' must not be a decimal between 0 and 0.02"
					end

					if config.enforce_consumer_groups and config.consumer_groups == ngx.null then
						return nil, "No consumer groups provided"
					end

					return true
				end
			}
		}
	}
}
