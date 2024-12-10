local cpu = require("kong.enterprise_edition.profiling.cpu")
local memory = require("kong.enterprise_edition.profiling.memory")
local gc_snapshot = require("kong.enterprise_edition.profiling.gc_snapshot")
local EV_SRC_CPU_PROF = "cpu-profiling"
local EV_EV_CPU_PROF_START = "start"
local EV_EV_CPU_PROF_STOP = "stop"
local EV_SRC_MEM_TRAC = "memory-profiling"
local EV_EV_MEM_TRAC_START = "start"
local EV_EV_MEM_TRAC_STOP = "stop"
local EV_SRC_GC_SNAPSHOT = "gc-snapshot"
local EV_EV_GC_SNAPSHOT_DUMP = "dump"
local _M = {
	cpu = {},
	memory = {},
	gc_snapshot = {}
}

function _M.cpu.start(mode, step, interval, timeout, path, pid)
	return kong.worker_events.post(EV_SRC_CPU_PROF, EV_EV_CPU_PROF_START, {
		pid = pid,
		mode = mode,
		step = step,
		interval = interval,
		timeout = timeout,
		path = path
	})
end

function _M.cpu.state()
	return cpu.state()
end

function _M.cpu.stop()
	local pid = cpu.state().pid

	assert(tonumber(pid), "cpu profiling not started")

	return kong.worker_events.post(EV_SRC_CPU_PROF, EV_EV_CPU_PROF_STOP, {
		pid = tonumber(pid)
	})
end

function _M.memory.start(path, timeout, block_size, stack_depth, pid)
	return kong.worker_events.post(EV_SRC_MEM_TRAC, EV_EV_MEM_TRAC_START, {
		pid = pid,
		path = path,
		timeout = timeout,
		block_size = block_size,
		stack_depth = stack_depth
	})
end

function _M.memory.state()
	return memory.state()
end

function _M.memory.stop()
	local pid = memory.state().pid

	assert(tonumber(pid), "memory profiling not started")

	return kong.worker_events.post(EV_SRC_MEM_TRAC, EV_EV_MEM_TRAC_STOP, {
		pid = tonumber(pid)
	})
end

function _M.gc_snapshot.dump(path, timeout, pid)
	return kong.worker_events.post(EV_SRC_GC_SNAPSHOT, EV_EV_GC_SNAPSHOT_DUMP, {
		pid = pid,
		timeout = timeout,
		path = path
	})
end

function _M.gc_snapshot.state()
	return gc_snapshot.state()
end

function _M.init_worker()
	local worker_events = kong.worker_events

	worker_events.register(function (data)
		if data.pid ~= ngx.worker.pid() then
			return
		end

		local pok, res, err = pcall(cpu.start, {
			mode = data.mode,
			step = data.step,
			interval = data.interval,
			timeout = data.timeout,
			path = data.path
		})

		if not pok then
			ngx.log(ngx.ERR, "failed to start profiling: ", res)
		end

		if not res then
			ngx.log(ngx.ERR, "failed to start profiling: ", err)
		end
	end, EV_SRC_CPU_PROF, EV_EV_CPU_PROF_START)
	worker_events.register(function (data)
		if data.pid ~= ngx.worker.pid() then
			return
		end

		cpu.stop()
	end, EV_SRC_CPU_PROF, EV_EV_CPU_PROF_STOP)
	worker_events.register(function (data)
		if data.pid ~= ngx.worker.pid() then
			return
		end

		local pok, err = pcall(gc_snapshot.dump, data.path, data.timeout)

		if not pok then
			ngx.log(ngx.ERR, "failed to snapshot GC: ", err)
		end
	end, EV_SRC_GC_SNAPSHOT, EV_EV_GC_SNAPSHOT_DUMP)
	worker_events.register(function (data)
		if data.pid ~= ngx.worker.pid() then
			return
		end

		local pok, res, err = pcall(memory.start, {
			path = data.path,
			timeout = data.timeout,
			block_size = data.block_size,
			stack_depth = data.stack_depth
		})

		if not pok then
			ngx.log(ngx.ERR, "failed to memory profiling: ", res)
		end

		if not res then
			ngx.log(ngx.ERR, "failed to memory profiling: ", err)
		end
	end, EV_SRC_MEM_TRAC, EV_EV_MEM_TRAC_START)
	worker_events.register(function (data)
		if data.pid ~= ngx.worker.pid() then
			return
		end

		memory.stop()
	end, EV_SRC_MEM_TRAC, EV_EV_MEM_TRAC_STOP)
end

return _M
