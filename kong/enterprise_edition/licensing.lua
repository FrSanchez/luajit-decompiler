local tx = require("pl.tablex")
local utils = require("kong.tools.utils")
local conf_loader = require("kong.conf_loader")
local license_helpers = require("kong.enterprise_edition.license_helpers")
local event_hooks = require("kong.enterprise_edition.event_hooks")
local tx_deepcompare = tx.deepcompare
local next = next
local string_find = string.find
local _M = {}

local function MagicTable(uberself, opts)
	opts = opts or {}
	local source = nil

	if opts.lazy then
		source = {}
	end

	local methods = {
		clear = table.clear,
		update = function (self, data, eval)
			if opts.lazy then
				source = data

				return
			end

			for k, v in pairs(data) do
				if eval and type(v) == "function" then
					v = v(self)
				end

				rawset(self, k, v)
			end
		end
	}

	if opts.has_remove_sensitive then
		function methods.remove_sensitive()
			return conf_loader.remove_sensitive(_M.configuration)
		end
	end

	local function index(self, key)
		if methods[key] then
			return methods[key]
		end

		local value = nil

		if opts.lazy then
			value = source[key]

			if type(value) == "function" then
				value = value(self)
			end

			rawset(self, key, value)
		else
			value = rawget(self, key)
		end

		return value
	end

	return setmetatable(uberself, {
		__index = index,
		__newindex = function ()
			error("cannot write to MagicTable™", 2)
		end
	})
end

_M.MagicTable = MagicTable
_M.features = MagicTable({}, {
	lazy = true
})
_M.configuration = MagicTable({}, {
	has_remove_sensitive = true,
	lazy = false
})
local FREE_LICENSE = {}

local function get_license_changed()
	local license = license_helpers.read_license_info()

	if kong and kong.license and tx_deepcompare(kong.license, license) then
		ngx.log(ngx.DEBUG, "[licensing] license has not changed")

		return
	end

	return license or FREE_LICENSE
end

local function get_license_event_type(license)
	if not next(license) then
		return "UNLOAD"
	end

	return "LOAD"
end

local function post_load_license_event_local(worker_events)
	local license = get_license_changed()

	if not license then
		return
	end

	ngx.log(ngx.DEBUG, "[licensing] post license reload event to self worker. license: ", get_license_event_type(license))
	worker_events.post_local("license", "load", {
		license = license
	})
end

local function post_load_license_event(worker_events)
	local license = get_license_changed()

	if not license then
		return
	end

	ngx.log(ngx.DEBUG, "[licensing] broadcasting license reload event to all workers. license: ", get_license_event_type(license))
	worker_events.post("license", "load", {
		license = license
	})
end

local function load_license(worker_events, license)
	ngx.log(ngx.DEBUG, "[licensing] license:load event -> license: ", get_license_event_type(license))

	local _l_type = _M.l_type

	_M:update(license)

	if _l_type == _M.l_type then
		ngx.log(ngx.DEBUG, "[licensing] license type has not changed")

		return
	end

	_M:post_conf_change_worker_event()
end

function _M:register_events()
	local kong = kong
	local worker_events = kong.worker_events
	local cluster_events = kong.cluster_events

	worker_events.register(function (data, event, source, pid)
		post_load_license_event_local(worker_events)
	end, "declarative", "reconfigure")
	worker_events.register(function (data, event, source, pid)
		post_load_license_event(worker_events)
	end, "crud", "licenses")
	worker_events.register(function (data, event, source, pid)
		load_license(worker_events, data.license)
	end, "license", "load")
	cluster_events:subscribe("invalidations", function (key)
		if string_find(key, "license") then
			ngx.log(ngx.DEBUG, "[licensing] received invalidate event from cluster ", key)
			post_load_license_event(worker_events)
		end
	end)
end

function _M:init_worker()
	local license = license_helpers.read_license_info()

	self:update(license)

	if kong.configuration.role == "data_plane" then
		self:post_conf_change_worker_event()
	end

	license_helpers.report_expired_license(kong.configuration.konnect_mode)
	self:register_events()
end

function _M:post_conf_change_worker_event()
	local worker_events = kong.worker_events

	if not worker_events then
		return
	end

	event_hooks.register_events(worker_events)
	worker_events.post_local("kong:configuration", "change", {
		configuration = _M.configuration,
		features = _M.features,
		l_type = _M.l_type
	})
end

function _M:update(license)
	if kong then
		kong.license = license
	end

	_M.l_type = license_helpers.get_type(license)

	ngx.log(ngx.INFO, "[licensing] license type: ", _M.l_type)
	_M.features:clear()
	_M.features:update(utils.cycle_aware_deep_copy(license_helpers.get_featureset(_M.l_type)))
	_M.configuration:clear()
	_M.configuration:update(utils.cycle_aware_deep_copy(_M.kong_conf))
	_M.configuration:update(_M.features.conf or {}, true)
end

function _M:update_featureset()
	local license = nil

	if kong then
		license = kong.license
	end

	if not license then
		return nil
	end

	if _M.l_type == license_helpers.get_type(license) then
		return nil
	end

	_M:update(license)
	_M:post_conf_change_worker_event()
end

function _M:can(what)
	return _M.features[what] ~= false
end

function _M:allow_ee_entity(op)
	local allow_ee_entity = _M.features.allow_ee_entity

	if not allow_ee_entity then
		return true
	end

	if license_helpers.is_exceeds_grace_period() then
		return true
	end

	return allow_ee_entity[op] ~= false
end

function _M:license_type()
	return _M.l_type
end

function _M:new(kong_conf)
	local license = license_helpers.read_license_info()
	_M.kong_conf = kong_conf

	_M:update(license)

	return _M
end

return setmetatable(_M, {
	__call = _M.new,
	__index = _M.features
})
