local cjson = require("cjson.safe")
local tx = require("pl/tablex")
local to_hex = require("resty.string").to_hex
local Queue = require("kong.tools.queue")
local queue_schema_definition = require("kong.tools.queue_schema")
local Schema = require("kong.db.schema")
local sandbox = require("kong.tools.sandbox")
local request = require("kong.enterprise_edition.utils").request
local normalize_table = require("kong.enterprise_edition.utils").normalize_table
local balancer = require("kong.runloop.balancer")
local fmt = string.format
local ipairs = ipairs
local ngx_null = ngx.null
local md5 = ngx.md5
local hmac_sha1 = ngx.hmac_sha1
local timer_at = ngx.timer.at
local QUEUE_OPTS = {
	max_coalescing_delay = 0,
	max_batch_size = 1,
	max_entries = 10000
}
local queue_schema = assert(Schema.new(queue_schema_definition))
QUEUE_OPTS = queue_schema:process_auto_fields(QUEUE_OPTS)
local ok, err = queue_schema:validate(QUEUE_OPTS)

assert(ok, "Invalid QUEUE_OPTS: " .. require("inspect")(err))

QUEUE_OPTS.name = "event-hooks"
QUEUE_OPTS.max_bytes = nil
local template = nil
local _M = {}
local events = {}
local references = {}

local function prefix(source)
	return "event-hooks:" .. source
end

local function unprefix(source)
	return source:gsub("^event%-hooks%:", "", 1)
end

function _M.enabled()
	return kong.configuration.event_hooks_enabled
end

function _M.crud(data)
	if data.operation == "delete" then
		_M.unregister(data.entity)
	elseif data.operation == "update" then
		_M.unregister(data.old_entity)
		_M.register(data.entity)
	elseif data.operation == "create" then
		_M.register(data.entity)
	end

	if _M.has_ping(data.entity) then
		_M.enqueue({
			callback = _M.ping,
			args = {
				data.entity,
				data.operation
			}
		})
	end
end

function _M.publish(source, event, opts)
	if not _M.enabled() then
		return
	end

	if not events[source] then
		events[source] = {}
	end

	opts = opts or {}
	events[source][event] = {
		description = opts.description,
		fields = opts.fields,
		unique = opts.unique
	}

	return true
end

function _M.has_ping(entity)
	return _M.handlers[entity.handler](entity, entity.config).ping
end

function _M.ping(entity, operation)
	local handler = _M.handlers[entity.handler](entity, entity.config)

	if not handler.ping then
		return nil, fmt("handler '%s' does not support 'ping'", entity.handler)
	end

	return handler.ping(operation)
end

function _M.register(entity)
	if not _M.enabled() then
		return
	end

	local callback = _M.callback(entity)
	local source = entity.source
	local event = entity.event ~= ngx_null and entity.event or nil
	references[entity.id] = callback

	return kong.worker_events.register(callback, prefix(source), event)
end

function _M.unregister(entity)
	if not _M.enabled() then
		return
	end

	local callback = references[entity.id]
	local source = entity.source
	local event = entity.event ~= ngx_null and entity.event or nil
	references[entity.id] = nil

	return kong.worker_events.unregister(callback, prefix(source), event)
end

local function field_digest(source, event, data)
	local fields = events[source] and events[source][event] and events[source][event].unique

	return _M.digest(data, {
		fields = fields
	})
end

function _M.emit(source, event, data)
	if not _M.enabled() then
		return
	end

	local digest = field_digest(source, event, data)
	local unique = source .. ":" .. event .. ":" .. digest

	return kong.worker_events.post(prefix(source), event, data, unique)
end

function _M.list()
	return events
end

function _M.digest(data, opts)
	local opts = opts or {}
	local fields = opts.fields
	local data = fields and tx.intersection(data, tx.makeset(fields)) or data
	local _, err = cjson.encode(data)

	if err then
		return nil, err
	end

	return md5(normalize_table(data))
end

local function process_callback(config, batch)
	local entry = batch[1]
	local pok, cres_or_perr, cerr = pcall(entry.callback, unpack(entry.args))

	if not pok then
		kong.log.err(cres_or_perr)

		return nil, cres_or_perr
	end

	return cres_or_perr, cerr
end

function _M.enqueue(entry)
	Queue.enqueue(QUEUE_OPTS, process_callback, nil, entry)
end

function _M.callback(entity)
	local callback = _M.handlers[entity.handler](entity, entity.config).callback

	local function wrap(data, event, source, pid)
		local ttl = entity.snooze ~= ngx_null and entity.snooze or nil
		local on_change = entity.on_change ~= ngx_null and entity.on_change or nil
		local source = unprefix(source)

		if ttl or on_change then
			local cache_key = fmt("event_hooks:%s:%s:%s", entity.id, source, event)
			local digest, err = field_digest(source, event, data)

			if err then
				kong.log.err(fmt("cannot serialize '%s:%s' event data. err: '%s'. " .. "Ignoring on_change/snooze for this event-hook", source, event, err))
			else
				if on_change and ttl then
					cache_key = cache_key .. ":" .. digest
				end

				local c_digest, _, hit_lvl = kong.cache:get(cache_key, nil, function (ttl)
					return digest, nil, ttl
				end, ttl)

				if hit_lvl ~= 3 then
					if on_change and not ttl then
						if c_digest == digest then
							kong.log.warn("ignoring event_hooks event: ", cache_key)

							return
						else
							kong.cache.mlcache.lru:set(cache_key, digest)
						end
					else
						kong.log.warn("ignoring event_hooks event: ", cache_key)

						return
					end
				end
			end
		end

		local blob = {
			callback = callback,
			args = {
				data,
				event,
				source,
				pid
			}
		}

		return _M.enqueue(blob)
	end

	return wrap
end

function _M.test(entity, data)
	local callback = _M.handlers[entity.handler](entity, entity.config).callback
	local blob = {
		callback = callback,
		args = {
			data,
			entity.event,
			entity.source,
			42
		}
	}

	return process_callback({
		blob
	})
end

local function sign_body(secret)
	return function (body)
		return "sha1", to_hex(hmac_sha1(secret, body))
	end
end

function _M.register_events(events_handler)
	if not _M.enabled() then
		return
	end

	local function dao_adapter(data)
		return {
			entity = data.entity,
			old_entity = data.old_entity,
			schema = data.schema and data.schema.name,
			operation = data.operation
		}
	end

	local operations = {
		"create",
		"update",
		"delete"
	}

	for _, op in ipairs(operations) do
		_M.publish("dao:crud", op, {
			fields = {
				"operation",
				"entity",
				"old_entity",
				"schema"
			},
			adapter = dao_adapter
		})
	end

	for name, _ in pairs(kong.db.daos) do
		_M.publish("crud", name, {
			fields = {
				"operation",
				"entity",
				"old_entity",
				"schema"
			},
			adapter = dao_adapter
		})

		for _, op in ipairs(operations) do
			_M.publish("crud", name .. ":" .. op, {
				fields = {
					"operation",
					"entity",
					"old_entity",
					"schema"
				},
				adapter = dao_adapter
			})
		end
	end

	events_handler.register(function (data, event, source, pid)
		_M.emit(source, event, dao_adapter(data))
	end, "crud")
	events_handler.register(function (data, event, source, pid)
		_M.emit(source, event, dao_adapter(data))
	end, "dao:crud")
	events_handler.register(_M.crud, "crud", "event_hooks")
	balancer.subscribe_to_healthcheck_events(function (upstream_id, ip, port, hostname, health)
		_M.emit("balancer", "health", {
			upstream_id = upstream_id,
			ip = ip,
			port = port,
			hostname = hostname,
			health = health
		})
	end)
	_M.publish("balancer", "health", {
		fields = {
			"upstream_id",
			"ip",
			"port",
			"hostname",
			"health"
		}
	})
	timer_at(0, function ()
		for entity, err in kong.db.event_hooks:each(1000) do
			if err then
				kong.log.err(err)
			else
				_M.register(entity)
			end
		end
	end)
end

_M.handlers = {
	webhook = function (entity, config)
		return {
			callback = function (data, event, source, pid)
				local headers = config.headers ~= ngx_null and config.headers or {}
				local method = "POST"
				headers["content-type"] = "application/json"
				data.event = event
				data.source = source
				local body, err = cjson.encode(data)

				if err then
					error(err)
				end

				local res, err = request(config.url, {
					method = method,
					body = body,
					sign_with = config.secret and config.secret ~= ngx_null and sign_body(config.secret),
					headers = headers,
					ssl_verify = config.ssl_verify
				})

				if not err then
					return true, {
						body = res.body,
						headers = res.headers,
						status = res.status
					}
				end

				return nil, err
			end,
			ping = function (operation)
				local headers = config.headers ~= ngx_null and config.headers or {}
				local method = "POST"
				headers["content-type"] = "application/json"
				local data = {
					source = "kong:event_hooks",
					event = "ping",
					operation = operation,
					event_hooks = entity
				}
				local body, err = cjson.encode(data)

				if err then
					error(err)
				end

				local res, err = request(config.url, {
					method = method,
					body = body,
					sign_with = config.secret and config.secret ~= ngx_null and sign_body(config.secret),
					headers = headers,
					ssl_verify = config.ssl_verify
				})

				if not err then
					return true, {
						body = res.body,
						headers = res.headers,
						status = res.status
					}
				end

				return nil, err
			end
		}
	end,
	["webhook-custom"] = function (entity, config)
		if not template then
			template = require("resty.template")
		end

		return {
			callback = function (data, event, source, pid)
				local payload, body, headers = nil
				local method = config.method
				data.event = event
				data.source = source

				if config.payload and config.payload ~= ngx_null then
					if config.payload_format then
						payload = {}

						for k, v in pairs(config.payload) do
							payload[k] = template.compile(v)(data)
						end
					else
						payload = config.payload
					end
				end

				if config.body and config.body ~= ngx_null then
					if config.body_format then
						body = template.compile(config.body)(data)
					else
						body = config.body
					end
				end

				if config.headers and config.headers ~= ngx_null then
					if config.headers_format then
						headers = {}

						for k, v in pairs(config.headers) do
							headers[k] = template.compile(v)(data)
						end
					else
						headers = config.headers
					end
				end

				local res, err = request(config.url, {
					method = method,
					data = payload,
					body = body,
					sign_with = config.secret and config.secret ~= ngx_null and sign_body(config.secret),
					headers = headers,
					ssl_verify = config.ssl_verify
				})

				if not err then
					return true, {
						body = res.body,
						headers = res.headers,
						status = res.status
					}
				end

				return nil, err
			end
		}
	end,
	log = function (entity, config)
		return {
			callback = function (data, event, source, pid)
				kong.log.inspect("log callback: ", {
					event,
					source,
					data,
					pid
				})

				return true
			end
		}
	end,
	lambda = function (entity, config)
		local functions = {}
		local opts = {
			chunk_name = "event_hooks:" .. entity.id
		}

		local function err_fn(err)
			return function ()
				return nil, err
			end
		end

		for i, fn_str in ipairs(config.functions or {}) do
			local fn, err = sandbox.validate_function(fn_str, opts)

			if err then
				fn = err_fn(err)
			end

			table.insert(functions, fn)
		end

		return {
			callback = function (data, event, source, pid)
				local err = nil

				for _, fn in ipairs(functions) do
					data, err = fn(data, event, source, pid)

					if err then
						break
					end
				end

				if err then
					return nil, err
				else
					return data
				end
			end
		}
	end
}
_M.events = events
_M.references = references
_M.process_callback = process_callback

return _M
