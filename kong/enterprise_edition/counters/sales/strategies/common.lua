local fmt = string.format
local os = os
local OLDER_DATA_LABEL = "UNKNOWN"
local LOAD_OLDER_DATA = true

local function get_year_month(months_in_the_past)
	months_in_the_past = months_in_the_past or 0
	local current_year = tonumber(os.date("%Y"))
	local current_month = tonumber(os.date("%m"))
	local time_to_use = os.time({
		day = 1,
		year = current_year,
		month = current_month - months_in_the_past
	})
	local year = tonumber(os.date("%Y", time_to_use))
	local month = tonumber(os.date("%m", time_to_use))

	return {
		year = year,
		month = month
	}
end

local function should_report_bucket(min_date, res)
	if min_date.year < res.year or res.year == min_date.year and min_date.month <= res.month or LOAD_OLDER_DATA and res.year == 0 then
		return true
	end

	return false
end

local function get_count_by_month(res, min_year_month)
	local count = {}

	if res and min_year_month then
		for i = 1, #res do
			if res[i] and should_report_bucket(min_year_month, res[i]) then
				local label = nil

				if res[i].year ~= 0 and res[i].month ~= 0 then
					label = fmt("%04d-%02d", res[i].year, res[i].month)
				else
					label = OLDER_DATA_LABEL
				end

				if not count[label] then
					count[label] = 0
				end

				count[label] = count[label] + res[i].req_cnt
			end
		end
	end

	return count
end

local function get_request_buckets(count)
	local buckets = {}
	local total = 0

	for bucket_label, bucket_count in pairs(count) do
		local entry = {
			bucket = bucket_label,
			request_count = bucket_count
		}
		total = total + bucket_count

		table.insert(buckets, entry)
	end

	return {
		total_requests = total,
		buckets = buckets
	}
end

return {
	MONTHS_TO_REPORT = 11,
	get_year_month = get_year_month,
	get_count_by_month = get_count_by_month,
	get_request_buckets = get_request_buckets
}
