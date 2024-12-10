local Schema = require("kong.db.schema")
local tablex = require("pl.tablex")
local match_list = {
	type = "array",
	elements = {
		type = "record",
		fields = {
			{
				pattern = {
					type = "string",
					required = true
				}
			},
			{
				err = {
					type = "string"
				}
			}
		}
	}
}
local match_any_list = {
	type = "record",
	fields = {
		{
			patterns = {
				type = "array",
				required = true,
				elements = {
					type = "string"
				}
			}
		},
		{
			err = {
				type = "string"
			}
		}
	}
}
local validators = {
	{
		between = {
			type = "array",
			len_eq = 2,
			elements = {
				type = "integer"
			}
		}
	},
	{
		len_eq = {
			type = "integer"
		}
	},
	{
		len_min = {
			type = "integer"
		}
	},
	{
		len_max = {
			type = "integer"
		}
	},
	{
		match = {
			type = "string"
		}
	},
	{
		not_match = {
			type = "string"
		}
	},
	{
		match_all = match_list
	},
	{
		match_none = match_list
	},
	{
		match_any = match_any_list
	},
	{
		starts_with = {
			type = "string"
		}
	},
	{
		one_of = {
			type = "array",
			elements = {
				type = "string"
			}
		}
	},
	{
		timestamp = {
			type = "boolean"
		}
	},
	{
		uuid = {
			type = "boolean"
		}
	},
	{
		custom_validator = {
			type = "function"
		}
	}
}
local field_schema = {
	{
		type = {
			type = "string",
			required = true,
			one_of = tablex.keys(Schema.valid_types)
		}
	},
	{
		required = {
			type = "boolean"
		}
	},
	{
		reference = {
			type = "string"
		}
	},
	{
		auto = {
			type = "boolean"
		}
	},
	{
		unique = {
			type = "boolean"
		}
	},
	{
		default = {
			type = "self"
		}
	}
}

for _, field in ipairs(validators) do
	table.insert(field_schema, field)
end

for _, field in ipairs(field_schema) do
	local data = field[next(field)]
	data.nilable = not data.required
end

local fields_array = {
	type = "array",
	elements = {
		type = "map",
		required = true,
		len_eq = 1,
		keys = {
			type = "string"
		},
		values = {
			type = "record",
			fields = field_schema
		}
	}
}

table.insert(field_schema, {
	elements = {
		type = "record",
		fields = field_schema
	}
})
table.insert(field_schema, {
	keys = {
		type = "record",
		fields = field_schema
	}
})
table.insert(field_schema, {
	values = {
		type = "record",
		fields = field_schema
	}
})
table.insert(field_schema, {
	fields = fields_array
})

local conditional_validators = {}

for _, field in ipairs(validators) do
	table.insert(conditional_validators, field)
end

local entity_checkers = {
	{
		at_least_one_of = {
			type = "array",
			elements = {
				type = "string"
			}
		}
	},
	{
		only_one_of = {
			type = "array",
			elements = {
				type = "string"
			}
		}
	},
	{
		conditional = {
			type = "record",
			fields = {
				{
					if_field = {
						type = "string"
					}
				},
				{
					if_match = {
						type = "record",
						fields = conditional_validators
					}
				},
				{
					then_field = {
						type = "string"
					}
				},
				{
					then_match = {
						type = "record",
						fields = conditional_validators
					}
				}
			}
		}
	}
}
local entity_check_names = {}

for _, field in ipairs(entity_checkers) do
	local name = next(field)

	table.insert(entity_check_names, name)
end

local entity_checks_schema = {
	type = "array",
	nilable = true,
	elements = {
		type = "record",
		fields = entity_checkers,
		entity_checks = {
			{
				only_one_of = tablex.keys(Schema.entity_checkers)
			}
		}
	}
}

table.insert(field_schema, {
	entity_checks = entity_checks_schema
})

local meta_errors = {
	FIELDS_ARRAY = "each entry in fields must be a sub-table",
	REQUIRED = "field of type '%s' must declare '%s'",
	FIELDS_KEY = "each key in fields must be a string",
	ATTRIBUTE = "field of type '%s' cannot have attribute '%s'",
	TYPE = "missing type declaration",
	TABLE = "'%s' must be a table"
}
local required_attributes = {
	array = {
		"elements"
	},
	set = {
		"elements"
	},
	map = {
		"keys",
		"values"
	},
	record = {
		"fields"
	}
}
local attribute_types = {
	between = {
		integer = true
	},
	len_eq = {
		hash = true,
		array = true,
		set = true,
		string = true
	},
	match = {
		string = true
	},
	one_of = {
		string = true,
		number = true,
		integer = true
	},
	timestamp = {
		integer = true
	},
	uuid = {
		string = true
	},
	unique = {
		string = true,
		number = true,
		integer = true
	}
}
local nested_attributes = {
	keys = true,
	elements = true,
	values = true
}
local check_field = nil

local function check_fields(schema, errors)
	for _, item in ipairs(schema.fields) do
		if type(item) ~= "table" then
			errors.fields = meta_errors.FIELDS_ARRAY

			break
		end

		local k = next(item)
		local field = item[k]

		if type(field) == "table" then
			check_field(k, field, errors)
		else
			errors[k] = meta_errors.TABLE:format(k)
		end
	end

	if next(errors) then
		return nil, errors
	end

	return true
end

function check_field(k, field, errors)
	if not field.type then
		errors[k] = meta_errors.TYPE

		return nil
	end

	if required_attributes[field.type] then
		for _, required in ipairs(required_attributes[field.type]) do
			if not field[required] then
				errors[k] = meta_errors.REQUIRED:format(field.type, required)
			end
		end
	end

	for attr, _ in pairs(field) do
		if attribute_types[attr] and not attribute_types[attr][field.type] then
			errors[k] = meta_errors.ATTRIBUTE:format(field.type, attr)
		end
	end

	for name, _ in pairs(nested_attributes) do
		if field[name] then
			if type(field[name]) == "table" then
				check_field(k, field[name], errors)
			else
				errors[k] = meta_errors.TABLE:format(name)
			end
		end
	end

	if field.fields then
		return check_fields(field, errors)
	end
end

local MetaSchema = Schema.new({
	name = "metaschema",
	fields = {
		{
			name = {
				type = "string",
				required = true
			}
		},
		{
			primary_key = {
				type = "array",
				required = true,
				elements = {
					type = "string"
				}
			}
		},
		{
			workspaceable = {
				type = "boolean",
				nilable = true
			}
		},
		{
			fields = {
				type = "array",
				elements = {
					type = "map",
					required = true,
					len_eq = 1,
					keys = {
						type = "string"
					},
					values = {
						type = "record",
						fields = field_schema
					}
				}
			}
		},
		{
			entity_checks = entity_checks_schema
		},
		{
			check = {
				type = "function",
				nilable = true
			}
		},
		{
			dao = {
				type = "string",
				nilable = true
			}
		}
	},
	check = function (schema)
		local errors = {}

		if not schema.fields then
			errors.fields = meta_errors.TABLE:format("fields")

			return nil, errors
		end

		for _, item in ipairs(schema.fields) do
			if type(item) ~= "table" then
				errors.fields = meta_errors.FIELDS_ARRAY

				break
			end

			local k = next(item)
			local field = item[k]

			if type(field) == "table" then
				check_field(k, field, errors)
			else
				errors[k] = meta_errors.TABLE:format(k)
			end
		end

		if next(errors) then
			return nil, errors
		end

		return true
	end
})
MetaSchema.valid_types = setmetatable({
	["function"] = true
}, {
	__index = Schema.valid_types
})

function MetaSchema.get_supported_validator_set()
	local set = {}

	for _, item in ipairs(validators) do
		local name = next(item)
		set[name] = true
	end

	return set
end

return MetaSchema
