return {
	PORTAL_VITALS_ALLOWED_CACHE_KEY = "kong:portal_vitals_allowed",
	PORTAL_PREFIX = "__PORTAL-",
	ADMIN_CONSUMER_USERNAME_SUFFIX = "_ADMIN_",
	EE_DEPRECATED_PLUGIN_LIST = {},
	EE_ENTITIES = {
		"files",
		"legacy_files",
		"workspace_entity_counters",
		"consumer_reset_secrets",
		"credentials",
		"audit_requests",
		"audit_objects",
		"rbac_users",
		"rbac_roles",
		"rbac_user_roles",
		"rbac_role_entities",
		"rbac_role_endpoints",
		"admins",
		"developers",
		"document_objects",
		"applications",
		"application_instances",
		"groups",
		"group_rbac_roles",
		"login_attempts",
		"keyring_meta",
		"keyring_keys",
		"event_hooks",
		"licenses",
		{
			"consumer_groups",
			ahead_of = "plugins"
		},
		"consumer_group_plugins",
		"consumer_group_consumers"
	},
	EE_DICTS = {
		"kong_counters",
		"kong_vitals_counters",
		"kong_vitals_lists"
	},
	WORKSPACE_CONFIG = {
		PORTAL_CORS_ORIGINS = "portal_cors_origins",
		PORTAL_AUTO_APPROVE = "portal_auto_approve",
		PORTAL_DEVELOPER_META_FIELDS = "portal_developer_meta_fields",
		PORTAL_AUTH_CONF = "portal_auth_conf",
		PORTAL_IS_LEGACY = "portal_is_legacy",
		PORTAL_AUTH = "portal_auth",
		PORTAL = "portal",
		PORTAL_SESSION_CONF = "portal_session_conf",
		PORTAL_SMTP_ADMIN_EMAILS = "portal_smtp_admin_emails",
		PORTAL_EMAILS_REPLY_TO = "portal_emails_reply_to",
		PORTAL_EMAILS_FROM = "portal_emails_from",
		PORTAL_RESET_SUCCESS_EMAIL = "portal_reset_success_email",
		PORTAL_APPLICATION_STATUS_EMAIL = "portal_application_status_email",
		PORTAL_APPLICATION_REQUEST_EMAIL = "portal_application_request_email",
		PORTAL_RESET_EMAIL = "portal_reset_email",
		PORTAL_APPROVED_EMAIL = "portal_approved_email",
		PORTAL_ACCESS_REQUEST_EMAIL = "portal_access_request_email",
		PORTAL_INVITE_EMAIL = "portal_invite_email",
		PORTAL_TOKEN_EXP = "portal_token_exp"
	},
	PORTAL_RENDERER = {
		SITEMAP = [[
<?xml version="1.0" encoding="UTF-8"?>

      <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        {% for idx, url_obj in ipairs(xml_urlset) do %}
          <url>
            {% for key, value in pairs(url_obj) do %}
              <{*key*}>{*value*}</{*key*}>
            {% end %}
          </url>
        {% end %}
      </urlset>
    ]],
		PRIORITY_INDEX_OFFSET = 6,
		FALLBACK_EMAIL = [[
      <!DOCTYPE html>
      <html>
        <head>
        </head>
        <body>
          <h4>{{page.heading}}</h4>
          <p>
            {*page.body*}
          </p>
        </body>
      </html>
    ]],
		EXTENSION_LIST = {
			"txt",
			"md",
			"html",
			"json",
			"yaml",
			"yml"
		},
		SPEC_EXT_LIST = {
			"json",
			"yaml",
			"yml"
		},
		ROUTE_TYPES = {
			DEFAULT = "defualt",
			COLLECTION = "collection",
			EXPLICIT = "explicit"
		},
		FALLBACK_404 = "<html><head><title>404 Not Found</title></head><body>" .. "<h1>404 Not Found</h1><p>The page you are requesting cannot be found.</p>" .. "</body></html>",
		LAYOUTS = {
			LOGIN = "login",
			UNSET = "__UNSET__",
			UNAUTHORIZED = "unauthorized"
		}
	},
	WEBSOCKET = {
		DEFAULT_CLIENT_MAX_PAYLOAD = 1048576,
		MAX_PAYLOAD_SIZE = 33554432,
		DEFAULT_UPSTREAM_MAX_PAYLOAD = 16777216,
		STATUS = {
			NORMAL = {
				CODE = 1000,
				REASON = "Normal Closure"
			},
			GOING_AWAY = {
				CODE = 1001,
				REASON = "Going Away"
			},
			PROTOCOL_ERROR = {
				CODE = 1002,
				REASON = "Protocol Error"
			},
			UNSUPPORTED_DATA = {
				CODE = 1003,
				REASON = "Unsupported Data"
			},
			NO_STATUS = {
				CODE = 1005,
				REASON = "No Status"
			},
			ABNORMAL = {
				CODE = 1006,
				REASON = "Abnormal Closure"
			},
			INVALID_DATA = {
				CODE = 1007,
				REASON = "Invalid Frame Payload Data"
			},
			POLICY_VIOLATION = {
				CODE = 1008,
				REASON = "Policy Violation"
			},
			MESSAGE_TOO_BIG = {
				CODE = 1009,
				REASON = "Message Too Big"
			},
			SERVER_ERROR = {
				CODE = 1011,
				REASON = "Internal Server Error"
			}
		},
		OPCODE_BY_TYPE = {
			binary = 2,
			text = 1,
			close = 8,
			continuation = 0,
			pong = 10,
			ping = 9
		},
		TYPE_BY_OPCODE = {
			[0] = "continuation",
			"text",
			"binary",
			nil,
			nil,
			nil,
			nil,
			nil,
			"close",
			"ping",
			"pong"
		},
		HEADERS = {
			VERSION = "Sec-WebSocket-Version",
			EXTENSIONS = "Sec-WebSocket-Extensions",
			KEY = "Sec-WebSocket-Key",
			PROTOCOL = "Sec-WebSocket-Protocol",
			ACCEPT = "Sec-WebSocket-Accept"
		}
	},
	EE_CLUSTERING_SYNC_STATUS = {
		{
			PLUGIN_CONFIG_INCOMPATIBLE = "plugin_config_incompatible"
		}
	},
	RBAC = {
		BCRYPT_COST_FACTOR = 9
	}
}
