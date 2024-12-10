local jit = require("jit")

assert(jit.version_num == 20100, "LuaJIT core/library version mismatch")

local profile = require("jit.profile")
local resty_lock = require("resty.lock")
local pl_path = require("pl.path")
local math_ceil = math.ceil
local debug_getinfo = debug.getinfo
local string_format = string.format
local string_sub = string.sub
local table_insert = table.insert
local table_concat = table.concat
local table_remove = table.remove
local ngx_DEBUG = ngx.DEBUG
local ngx_time = ngx.time
local ngx_worker_pid = ngx.worker.pid
local ngx_log = ngx.log
local MAX_STACK_DEPTH = 64
local SYNC_INTERVAL = 1
local SHDICT_SATATE = "kong_profiling_state"
local SHDICT_LOCK = "kong_locks"
local STATE_LOCK_KEY = "cpu:state_lock"
local FILE_LOCK_KEY = "cpu:file_lock"
local STATUS_KEY = "cpu:status"
local PID_KEY = "cpu:pid"
local TIMEOUT_AT_KEY = "cpu:timeout_at"
local STEP_KEY = "cpu:step"
local INTERVAL_KEY = "cpu:count"
local MODE_KEY = "cpu:mode"
local PATH_KEY = "cpu:path"
local SAMPLES_KEY = "cpu:samples"
local LOCK_OPTS_FOR_CHECKING = {
	timeout = 0
}
local LOCK_OPTS_FOR_STATE_LOCK = {
	exptime = 0,
	timeout = 0
}
local LOCK_OPTS_FOR_FILE_LOCK = {
	exptime = 30,
	timeout = 0
}
local TORLERANCE_TIME = 10
local stacktrace = {}
local force_stop_at = math.huge
local current_samples = 0
local last_sync_samples = math.huge
local current_state_lock = nil
local _M = {
	VALIDATE_MODES = {
		time = true,
		instruction = true
	}
}

local function get_shdict()
	return assert(ngx.shared[SHDICT_SATATE])
end

local function sync_samples()
	local shm = get_shdict()

	shm:set(SAMPLES_KEY, current_samples)
end

local function instruction_callback(event, _line)
	if event ~= "count" then
		return
	end

	if force_stop_at < ngx_time() then
		_M.stop()

		return
	end

	local now = ngx_time()

	if SYNC_INTERVAL < now - last_sync_samples then
		last_sync_samples = now

		sync_samples()
	end

	local callstack = {}

	for i = 1, MAX_STACK_DEPTH do
		local info = debug_getinfo(i + 1, "nSl")

		if not info then
			break
		end

		local str = string_format("%s:%d:%s();", info.source, info.currentline, info.name or info.what)

		table_insert(callstack, str)
	end

	local top = callstack[1]
	callstack[1] = string_sub(top, 1, -2)
	local _callstack = callstack
	callstack = {}

	for _ = 1, #_callstack do
		table_insert(callstack, table_remove(_callstack))
	end

	local trace = table_concat(callstack, nil)
	stacktrace[trace] = (stacktrace[trace] or 0) + 1
	current_samples = current_samples + 1
end

local function time_callback(th, samples, vmmode)
	if force_stop_at < ngx_time() then
		_M.stop()

		return
	end

	local now = ngx_time()

	if SYNC_INTERVAL < now - last_sync_samples then
		last_sync_samples = now

		sync_samples()
	end

	local trace = profile.dumpstack(th, "Zpl;", -MAX_STACK_DEPTH)
	current_samples = current_samples + samples

	if vmmode == "J" then
		trace = string_format("%sJIT_compiler", trace)
	end

	if vmmode == "G" then
		trace = string_format("%sGC", trace)
	end

	if vmmode == "C" then
		trace = string_format("%sC_code", trace)
	end

	stacktrace[trace] = (stacktrace[trace] or 0) + samples
end

local function mark_active(opt)
	local shm = get_shdict()
	local timeout_at = ngx_time() + opt.timeout
	local step = math_ceil(opt.step)
	local interval = math_ceil(opt.interval)
	local path = opt.path
	local mode = opt.mode
	local expire = opt.timeout + TORLERANCE_TIME
	LOCK_OPTS_FOR_STATE_LOCK.exptime = expire
	current_state_lock = assert(resty_lock:new(SHDICT_LOCK, LOCK_OPTS_FOR_STATE_LOCK))

	assert(current_state_lock:lock(STATE_LOCK_KEY))
	assert(shm:set(STATUS_KEY, "started", expire), "failed to set profiling state")
	assert(shm:set(PID_KEY, ngx_worker_pid(), 0))
	assert(shm:set(TIMEOUT_AT_KEY, timeout_at, expire))
	assert(shm:set(STEP_KEY, step, expire))
	assert(shm:set(INTERVAL_KEY, interval, expire))
	assert(shm:set(MODE_KEY, mode, expire))
	assert(shm:set(PATH_KEY, path, 0))
	assert(shm:set(SAMPLES_KEY, 0, expire))

	force_stop_at = timeout_at
	current_samples = 0
	last_sync_samples = ngx_time()
end

local function mark_inactive()
	local shm = get_shdict()

	assert(shm:set(STATUS_KEY, "stopped", 0), "failed to set profiling state")

	stacktrace = {}
	force_stop_at = math.huge
	last_sync_samples = math.huge

	assert(current_state_lock:unlock())

	current_state_lock = nil
end

function _M.is_active()
	local lock = assert(resty_lock:new(SHDICT_LOCK, LOCK_OPTS_FOR_CHECKING))
	local elapsed, err = lock:lock(STATE_LOCK_KEY)

	if elapsed then
		assert(lock:unlock())

		return false
	end

	if not elapsed and err == "timeout" then
		return true
	end

	error("failed to acquire the lock: " .. err)
end

function _M.state()
	local state = {}
	local shm = get_shdict()
	state.status = shm:get(STATUS_KEY) or "stopped"
	state.path = shm:get(PATH_KEY)
	state.pid = shm:get(PID_KEY)
	state.timeout_at = shm:get(TIMEOUT_AT_KEY)

	if state.status == "started" then
		state.mode = shm:get(MODE_KEY)
		state.samples = shm:get(SAMPLES_KEY)

		if state.mode == "instruction" then
			state.step = shm:get(STEP_KEY)
		elseif state.mode == "time" then
			state.interval = shm:get(INTERVAL_KEY)
		else
			error("unknown profiling mode: " .. state.mode)
		end
	elseif state.status == "stopped" then
		if state.path and not pl_path.exists(state.path) then
			state.path = nil
		end
	else
		error("unknown profiling status: " .. state.status)
	end

	return state
end

function _M.start(opt)
	if _M.is_active() then
		return nil, "profiling is already in progress"
	end

	mark_active(opt)

	stacktrace = {}
	local step = math_ceil(opt.step)
	local interval = math_ceil(opt.interval)
	local mode = opt.mode

	if mode == "instruction" then
		debug.sethook(instruction_callback, "", step)
	elseif mode == "time" then
		local mask = string_format("i%d", interval)

		profile.start(mask, time_callback)
	end

	return true
end

function _M.stop()
	if not _M.is_active() then
		return
	end

	local file_lock = assert(resty_lock:new(SHDICT_LOCK, LOCK_OPTS_FOR_FILE_LOCK))
	local elapsed, _ = file_lock:lock(FILE_LOCK_KEY)

	if not elapsed then
		ngx_log(ngx_DEBUG, "profiler is stopping by another coroutine")

		return
	end

	local state = _M.state()
	local old_stacktrace = stacktrace

	if state.mode == "instruction" then
		debug.sethook()
	else
		profile.stop()
	end

	local fp = assert(io.open(state.path, "w"))

	for k, v in pairs(old_stacktrace) do
		fp:write(string_format("%s %d\n", k, v))
	end

	fp:close()
	mark_inactive()
	assert(file_lock:unlock())
end

return _M
