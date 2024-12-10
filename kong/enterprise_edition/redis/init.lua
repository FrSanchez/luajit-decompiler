local redis_connector = require("resty.redis.connector")
local redis_cluster = require("resty.rediscluster")
local typedefs = require("kong.db.schema.typedefs")
local utils = require("kong.tools.utils")
local reports = require("kong.reports")
local string_format = string.format
local table_concat = table.concat
local log = ngx.log
local ERR = ngx.ERR
local WARN = ngx.WARN
local ngx_null = ngx.null
local DEFAULT_TIMEOUT = 2000
local MAX_INT = math.pow(2, 31) - 2
local _M = {}

local function is_present(x)
	return x and ngx_null ~= x
end

local function is_redis_sentinel(redis)
	return is_present(redis.sentinel_master) or is_present(redis.sentinel_role) or is_present(redis.sentinel_addresses)
end

local function is_redis_cluster(redis)
	return is_present(redis.cluster_addresses)
end

_M.is_redis_cluster = is_redis_cluster

local function validate_addresses(addresses)
	for _, address in ipairs(addresses) do
		local parts = utils.split(address, ":")

		if #parts ~= 2 or not tonumber(parts[2]) then
			return false, "Invalid Redis host address: " .. address
		end
	end

	return true
end

_M.config_schema = {
	type = "record",
	fields = {
		{
			host = typedefs.host
		},
		{
			port = typedefs.port
		},
		{
			timeout = typedefs.timeout({
				default = DEFAULT_TIMEOUT
			})
		},
		{
			connect_timeout = typedefs.timeout
		},
		{
			send_timeout = typedefs.timeout
		},
		{
			read_timeout = typedefs.timeout
		},
		{
			username = {
				referenceable = true,
				type = "string",
				description = "Username to use for Redis connections. If undefined, ACL authentication won't be performed. This requires Redis v6.0.0+. To be compatible with Redis v5.x.y, you can set it to `default`."
			}
		},
		{
			password = {
				referenceable = true,
				type = "string",
				description = "Password to use for Redis connections. If undefined, no AUTH commands are sent to Redis.",
				encrypted = true
			}
		},
		{
			sentinel_username = {
				referenceable = true,
				type = "string",
				description = "Sentinel username to authenticate with a Redis Sentinel instance. If undefined, ACL authentication won't be performed. This requires Redis v6.2.0+."
			}
		},
		{
			sentinel_password = {
				referenceable = true,
				type = "string",
				description = "Sentinel password to authenticate with a Redis Sentinel instance. If undefined, no AUTH commands are sent to Redis Sentinels.",
				encrypted = true
			}
		},
		{
			database = {
				type = "integer",
				description = "Database to use for the Redis connection when using the `redis` strategy",
				default = 0
			}
		},
		{
			keepalive_pool_size = {
				type = "integer",
				description = "The size limit for every cosocket connection pool associated with every remote server, per worker process. If neither `keepalive_pool_size` nor `keepalive_backlog` is specified, no pool is created. If `keepalive_pool_size` isn't specified but `keepalive_backlog` is specified, then the pool uses the default value. Try to increase (e.g. 512) this value if latency is high or throughput is low.",
				default = 256,
				between = {
					1,
					MAX_INT
				}
			}
		},
		{
			keepalive_backlog = {
				type = "integer",
				description = "Limits the total number of opened connections for a pool. If the connection pool is full, connection queues above the limit go into the backlog queue. If the backlog queue is full, subsequent connect operations fail and return `nil`. Queued operations (subject to set timeouts) resume once the number of connections in the pool is less than `keepalive_pool_size`. If latency is high or throughput is low, try increasing this value. Empirically, this value is larger than `keepalive_pool_size`.",
				between = {
					0,
					MAX_INT
				}
			}
		},
		{
			sentinel_master = {
				description = "Sentinel master to use for Redis connections. Defining this value implies using Redis Sentinel.",
				type = "string"
			}
		},
		{
			sentinel_role = {
				type = "string",
				description = "Sentinel role to use for Redis connections when the `redis` strategy is defined. Defining this value implies using Redis Sentinel.",
				one_of = {
					"master",
					"slave",
					"any"
				}
			}
		},
		{
			sentinel_addresses = {
				description = "Sentinel addresses to use for Redis connections when the `redis` strategy is defined. Defining this value implies using Redis Sentinel. Each string element must be a hostname. The minimum length of the array is 1 element.",
				type = "array",
				len_min = 1,
				elements = {
					type = "string"
				},
				custom_validator = validate_addresses
			}
		},
		{
			cluster_addresses = {
				description = "Cluster addresses to use for Redis connections when the `redis` strategy is defined. Defining this value implies using Redis Cluster. Each string element must be a hostname. The minimum length of the array is 1 element.",
				type = "array",
				len_min = 1,
				elements = {
					type = "string"
				},
				custom_validator = validate_addresses
			}
		},
		{
			ssl = {
				required = false,
				type = "boolean",
				description = "If set to true, uses SSL to connect to Redis.",
				default = false
			}
		},
		{
			ssl_verify = {
				required = false,
				type = "boolean",
				description = "If set to true, verifies the validity of the server SSL certificate. If setting this parameter, also configure `lua_ssl_trusted_certificate` in `kong.conf` to specify the CA (or server) certificate used by your Redis server. You may also need to configure `lua_ssl_verify_depth` accordingly.",
				default = false
			}
		},
		{
			server_name = typedefs.sni({
				required = false
			})
		}
	},
	entity_checks = {
		{
			mutually_exclusive_sets = {
				set1 = {
					"sentinel_master",
					"sentinel_role",
					"sentinel_addresses"
				},
				set2 = {
					"host",
					"port"
				}
			}
		},
		{
			mutually_exclusive_sets = {
				set1 = {
					"sentinel_master",
					"sentinel_role",
					"sentinel_addresses"
				},
				set2 = {
					"cluster_addresses"
				}
			}
		},
		{
			mutually_exclusive_sets = {
				set1 = {
					"cluster_addresses"
				},
				set2 = {
					"host",
					"port"
				}
			}
		},
		{
			mutually_required = {
				"sentinel_master",
				"sentinel_role",
				"sentinel_addresses"
			}
		},
		{
			mutually_required = {
				"host",
				"port"
			}
		},
		{
			mutually_required = {
				"connect_timeout",
				"send_timeout",
				"read_timeout"
			}
		}
	}
}

local function parse_addresses(addresses, ip_field_name)
	local parsed_addresses = {}

	for i = 1, #addresses do
		local address = addresses[i]
		local parts = utils.split(address, ":")
		local parsed_address = {
			[ip_field_name] = parts[1],
			port = tonumber(parts[2])
		}
		parsed_addresses[#parsed_addresses + 1] = parsed_address
	end

	return parsed_addresses
end

local function configure_timeouts(conf)
	local timeout = conf.timeout

	if timeout then
		local deprecation = {
			version_removed = "3.0.0.0",
			deprecated_after = "2.5.0.0",
			msg = "redis schema field `timeout` is deprecated, " .. "use `connect_timeout`, `send_timeout` and `read_timeout`"
		}

		log(WARN, deprecation.msg, " (deprecated after ", deprecation.deprecated_after, ", scheduled for removal in ", deprecation.version_removed, ")")
	else
		timeout = DEFAULT_TIMEOUT
	end

	conf.connect_timeout = conf.connect_timeout ~= ngx_null and conf.connect_timeout or timeout
	conf.send_timeout = conf.send_timeout ~= ngx_null and conf.send_timeout or timeout
	conf.read_timeout = conf.read_timeout ~= ngx_null and conf.read_timeout or timeout
end

function _M.init_conf(conf)
	if is_redis_cluster(conf) then
		table.sort(conf.cluster_addresses)

		conf.parsed_cluster_addresses = parse_addresses(conf.cluster_addresses, "ip")
	elseif is_redis_sentinel(conf) then
		conf.parsed_sentinel_addresses = parse_addresses(conf.sentinel_addresses, "host")
	end

	configure_timeouts(conf)
end

function _M.connection(conf)
	local red = nil
	local connect_opts = {
		ssl = conf.ssl,
		ssl_verify = conf.ssl_verify,
		server_name = conf.server_name,
		pool_size = conf.keepalive_pool_size,
		backlog = conf.keepalive_backlog
	}

	if is_redis_cluster(conf) then
		local err = nil
		red, err = redis_cluster:new({
			dict_name = "kong_locks",
			name = "redis-cluster" .. table.concat(conf.cluster_addresses),
			serv_list = conf.parsed_cluster_addresses,
			username = conf.username,
			password = conf.password,
			connect_timeout = conf.connect_timeout,
			send_timeout = conf.send_timeout,
			read_timeout = conf.read_timeout,
			connect_opts = connect_opts
		})

		if not red or err then
			return nil, err
		end
	else
		local rc = redis_connector.new({
			host = conf.host,
			port = conf.port,
			connect_timeout = conf.connect_timeout,
			send_timeout = conf.send_timeout,
			read_timeout = conf.read_timeout,
			master_name = conf.sentinel_master,
			role = conf.sentinel_role,
			sentinels = conf.parsed_sentinel_addresses,
			username = conf.username,
			password = conf.password,
			sentinel_username = conf.sentinel_username,
			sentinel_password = conf.sentinel_password,
			db = conf.database,
			connection_options = connect_opts
		})
		local err, previous_errors = nil
		red, err, previous_errors = rc:connect()

		if not red or err then
			if previous_errors then
				err = string_format("current errors: %s, previous errors: %s", err, table_concat(previous_errors, ", "))
			end

			return nil, err
		end
	end

	reports.retrieve_redis_version(red)

	return red, nil
end

return _M
