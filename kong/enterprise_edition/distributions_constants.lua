local c = {
	plugins = {
		"application-registration",
		"oauth2-introspection",
		"proxy-cache-advanced",
		"openid-connect",
		"forward-proxy",
		"canary",
		"request-transformer-advanced",
		"response-transformer-advanced",
		"rate-limiting-advanced",
		"ldap-auth-advanced",
		"statsd-advanced",
		"route-by-header",
		"jwt-signer",
		"vault-auth",
		"request-validator",
		"mtls-auth",
		"graphql-proxy-cache-advanced",
		"graphql-rate-limiting-advanced",
		"degraphql",
		"route-transformer-advanced",
		"kafka-log",
		"kafka-upstream",
		"exit-transformer",
		"key-auth-enc",
		"upstream-timeout",
		"mocking",
		"opa",
		"jq",
		"websocket-size-limit",
		"websocket-validator",
		"konnect-application-auth",
		"tls-handshake-modifier",
		"tls-metadata-headers",
		"saml",
		"xml-threat-protection",
		"jwe-decrypt",
		"oas-validation"
	},
	featureset = {
		full = {
			conf = {}
		},
		full_expired = {
			conf = {},
			allow_admin_api = {
				["/licenses"] = {
					["*"] = true
				},
				["/licenses/:licenses"] = {
					["*"] = true
				}
			},
			allow_ee_entity = {
				WRITE = false,
				READ = true
			},
			disabled_ee_entities = {
				workspaces = true,
				rbac_users = true,
				rbac_user_roles = true,
				rbac_roles = true,
				rbac_role_entities = true,
				rbac_role_endpoints = true,
				consumer_group_plugins = true,
				consumer_groups = true,
				event_hooks = true
			}
		},
		free = {
			conf = {
				event_hooks_enabled = false,
				portal = false,
				anonymous_reports = true,
				vitals = false,
				rbac = "off",
				enforce_rbac = "off",
				admin_gui_auth = function ()
				end
			},
			allow_admin_api = {
				["/workspaces"] = {
					GET = true,
					OPTIONS = true
				},
				["/workspaces/:workspaces"] = {
					GET = true,
					OPTIONS = true
				}
			},
			deny_admin_api = {
				["/workspaces"] = {
					["*"] = true
				},
				["/workspaces/:workspaces"] = {
					["*"] = true
				}
			},
			allow_ee_entity = {
				WRITE = false,
				READ = false
			},
			disabled_ee_entities = {
				workspaces = false,
				rbac_users = true,
				rbac_user_roles = true,
				rbac_roles = true,
				rbac_role_entities = true,
				rbac_role_endpoints = true,
				consumer_group_plugins = true,
				consumer_groups = true,
				event_hooks = true
			}
		}
	},
	release = true
}

return setmetatable(c, {
	__index = function ()
		return {}
	end
})
