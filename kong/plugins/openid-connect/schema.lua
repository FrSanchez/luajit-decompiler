local Schema = require("kong.db.schema")
local typedefs = require("kong.db.schema.typedefs")
local table_contains = require("kong.tools.utils").table_contains
local oidcdefs = require("kong.plugins.openid-connect.typedefs")
local cache = require("kong.plugins.openid-connect.cache")
local arguments = require("kong.plugins.openid-connect.arguments")
local get_phase = ngx.get_phase

local function validate_issuer(conf)
	local phase = get_phase()

	if phase ~= "access" and phase ~= "content" then
		return true
	end

	local args = arguments(conf)
	local issuer_uri = args.get_conf_arg("issuer")

	if not issuer_uri then
		return true
	end

	local options = args.get_http_opts({
		extra_jwks_uris = args.get_conf_arg("extra_jwks_uris"),
		headers = args.get_conf_args("discovery_headers_names", "discovery_headers_values")
	})
	local keys = cache.issuers.rediscover(issuer_uri, options)

	if not keys then
		return false, "openid connect discovery failed"
	end

	return true
end

local function check_auth_method_for_pop(conf)
	if not conf.proof_of_possession_auth_methods_validation then
		return true
	end

	if not conf.auth_methods then
		return false
	end

	for _, auth_method in ipairs(conf.auth_methods) do
		if auth_method ~= "bearer" and auth_method ~= "introspection" and auth_method ~= "session" then
			return false, "mTLS-proof-of-possession or Demonstrating Proof-of-Possession (DPoP) only supports 'bearer', 'introspection', 'session' auth methods when proof_of_possession_auth_methods_validation is set to true."
		end
	end

	return true
end

local function validate_proof_of_possession(conf)
	local self_signed_verify_support = kong.configuration.loaded_plugins["tls-handshake-modifier"]
	local ca_chain_verify_support = kong.configuration.loaded_plugins["mtls-auth"]
	local mtls_pop_enabled = conf.proof_of_possession_mtls == "strict" or conf.proof_of_possession_mtls == "optional"
	local dpop_enabled = conf.proof_of_possession_dpop and conf.proof_of_possession_dpop ~= "off"

	if mtls_pop_enabled and not self_signed_verify_support and not ca_chain_verify_support then
		return false, "mTLS-proof-of-possession requires client certificate authentication. " .. "'tls-handshake-modifier' or 'mtls-auth' plugin could be used for this purpose."
	end

	if mtls_pop_enabled or dpop_enabled then
		local ok, err = check_auth_method_for_pop(conf)

		if not ok then
			return ok, err
		end
	end

	return true
end

local function validate_tls_client_auth_certs(conf)
	local client_auth = conf.client_auth
	client_auth = type(client_auth) == "table" and client_auth or {}

	local function has_auth_method(value)
		return table_contains(client_auth, value) or conf.token_endpoint_auth_method == value or conf.introspection_endpoint_auth_method == value or conf.revocation_endpoint_auth_method == value
	end

	local tls_client_auth_enabled = has_auth_method("tls_client_auth") or has_auth_method("self_signed_tls_client_auth")

	if not tls_client_auth_enabled then
		return true
	end

	local tls_client_auth_cert_id = conf.tls_client_auth_cert_id ~= ngx.null and conf.tls_client_auth_cert_id

	if not tls_client_auth_cert_id then
		return false, "tls_client_auth_cert_id is required when tls client auth is enabled"
	end

	return true
end

local function validate(conf)
	local ok, err = validate_issuer(conf)

	if not ok then
		return false, err
	end

	ok, err = validate_tls_client_auth_certs(conf)

	if not ok then
		return false, err
	end

	return validate_proof_of_possession(conf)
end

local session_headers = Schema.define({
	type = "set",
	elements = {
		type = "string",
		one_of = {
			"id",
			"audience",
			"subject",
			"timeout",
			"idling-timeout",
			"rolling-timeout",
			"absolute-timeout"
		}
	}
})
local config = {
	name = "openid-connect",
	fields = {
		{
			consumer = typedefs.no_consumer
		},
		{
			protocols = typedefs.protocols_http
		},
		{
			consumer_group = typedefs.no_consumer_group
		},
		{
			config = {
				type = "record",
				custom_validator = validate,
				fields = {
					{
						issuer = typedefs.url({
							required = true,
							description = "The discovery endpoint (or the issuer identifier). When there is no discovery endpoint, please also configure `config.using_pseudo_issuer=true`."
						})
					},
					{
						using_pseudo_issuer = {
							default = false,
							description = "If the plugin uses a pseudo issuer. When set to true, the plugin will not discover the configuration from the issuer URL specified with `config.issuer`.",
							type = "boolean",
							required = false
						}
					},
					{
						discovery_headers_names = {
							description = "Extra header names passed to the discovery endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						discovery_headers_values = {
							description = "Extra header values passed to the discovery endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						extra_jwks_uris = {
							description = "JWKS URIs whose public keys are trusted (in addition to the keys found with the discovery).",
							type = "set",
							required = false,
							elements = typedefs.url
						}
					},
					{
						rediscovery_lifetime = {
							default = 30,
							description = "Specifies how long (in seconds) the plugin waits between discovery attempts. Discovery is still triggered on an as-needed basis.",
							type = "number",
							required = false
						}
					},
					{
						auth_methods = {
							required = false,
							description = "Types of credentials/grants to enable.",
							type = "array",
							default = {
								"password",
								"client_credentials",
								"authorization_code",
								"bearer",
								"introspection",
								"userinfo",
								"kong_oauth2",
								"refresh_token",
								"session"
							},
							elements = {
								type = "string",
								one_of = {
									"password",
									"client_credentials",
									"authorization_code",
									"bearer",
									"introspection",
									"userinfo",
									"kong_oauth2",
									"refresh_token",
									"session"
								}
							}
						}
					},
					{
						client_id = {
							encrypted = true,
							required = false,
							description = "The client id(s) that the plugin uses when it calls authenticated endpoints on the identity provider.",
							type = "array",
							elements = {
								type = "string",
								referenceable = true
							}
						}
					},
					{
						client_secret = {
							encrypted = true,
							required = false,
							description = "The client secret.",
							type = "array",
							elements = {
								type = "string",
								referenceable = true
							}
						}
					},
					{
						client_auth = {
							description = "The default OpenID Connect client authentication method is 'client_secret_basic' (using 'Authorization: Basic' header), 'client_secret_post' (credentials in body), 'client_secret_jwt' (signed client assertion in body), 'private_key_jwt' (private key-signed assertion), 'tls_client_auth' (client certificate), 'self_signed_tls_client_auth' (self-signed client certificate), and 'none' (no authentication).",
							type = "array",
							required = false,
							elements = {
								type = "string",
								one_of = {
									"client_secret_basic",
									"client_secret_post",
									"client_secret_jwt",
									"private_key_jwt",
									"tls_client_auth",
									"self_signed_tls_client_auth",
									"none"
								}
							}
						}
					},
					{
						client_jwk = {
							description = "The JWK used for the private_key_jwt authentication.",
							type = "array",
							required = false,
							elements = oidcdefs.jwk
						}
					},
					{
						client_alg = {
							description = "The algorithm to use for client_secret_jwt (only HS***) or private_key_jwt authentication.",
							type = "array",
							required = false,
							elements = {
								type = "string",
								one_of = {
									"HS256",
									"HS384",
									"HS512",
									"RS256",
									"RS384",
									"RS512",
									"ES256",
									"ES384",
									"ES512",
									"PS256",
									"PS384",
									"PS512",
									"EdDSA"
								}
							}
						}
					},
					{
						client_arg = {
							default = "client_id",
							description = "The client to use for this request (the selection is made with a request parameter with the same name).",
							type = "string",
							required = false
						}
					},
					{
						redirect_uri = {
							description = "The redirect URI passed to the authorization and token endpoints.",
							type = "array",
							required = false,
							elements = typedefs.url
						}
					},
					{
						login_redirect_uri = {
							description = "Where to redirect the client when `login_action` is set to `redirect`.",
							type = "array",
							required = false,
							elements = typedefs.url({
								referenceable = true
							})
						}
					},
					{
						logout_redirect_uri = {
							description = "Where to redirect the client after the logout.",
							type = "array",
							required = false,
							elements = typedefs.url({
								referenceable = true
							})
						}
					},
					{
						forbidden_redirect_uri = {
							description = "Where to redirect the client on forbidden requests.",
							type = "array",
							required = false,
							elements = typedefs.url
						}
					},
					{
						forbidden_error_message = {
							default = "Forbidden",
							description = "The error message for the forbidden requests (when not using the redirection).",
							type = "string",
							required = false
						}
					},
					{
						forbidden_destroy_session = {
							default = true,
							description = "Destroy any active session for the forbidden requests.",
							type = "boolean",
							required = false
						}
					},
					{
						unauthorized_destroy_session = {
							default = true,
							description = "Destroy any active session for the unauthorized requests.",
							type = "boolean",
							required = false
						}
					},
					{
						unauthorized_redirect_uri = {
							description = "Where to redirect the client on unauthorized requests.",
							type = "array",
							required = false,
							elements = typedefs.url
						}
					},
					{
						unauthorized_error_message = {
							default = "Unauthorized",
							description = "The error message for the unauthorized requests (when not using the redirection).",
							type = "string",
							required = false
						}
					},
					{
						unexpected_redirect_uri = {
							description = "Where to redirect the client when unexpected errors happen with the requests.",
							type = "array",
							required = false,
							elements = typedefs.url
						}
					},
					{
						response_mode = {
							default = "query",
							required = false,
							description = "Response mode passed to the authorization endpoint: - `query`: for parameters in query string - `form_post`: for parameters in request body - `fragment`: for parameters in uri fragment (rarely useful as the plugin itself cannot read it) - `query.jwt`, `form_post.jwt`, `fragment.jwt`: similar to `query`, `form_post` and `fragment` but the parameters are encoded in a JWT - `jwt`: shortcut that indicates the default encoding for the requested response type.",
							type = "string",
							one_of = {
								"query",
								"form_post",
								"fragment",
								"query.jwt",
								"form_post.jwt",
								"fragment.jwt",
								"jwt"
							}
						}
					},
					{
						response_type = {
							required = false,
							description = "The response type passed to the authorization endpoint.",
							type = "array",
							default = {
								"code"
							},
							elements = {
								type = "string"
							}
						}
					},
					{
						scopes = {
							required = false,
							description = "The scopes passed to the authorization and token endpoints.",
							type = "array",
							default = {
								"openid"
							},
							elements = {
								type = "string",
								referenceable = true
							}
						}
					},
					{
						audience = {
							description = "The audience passed to the authorization endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						issuers_allowed = {
							description = "The issuers allowed to be present in the tokens (`iss` claim).",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						scopes_required = {
							description = "The scopes (`scopes_claim` claim) required to be present in the access token (or introspection results) for successful authorization. This config parameter works in both **AND** / **OR** cases.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						scopes_claim = {
							required = false,
							description = "The claim that contains the scopes. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							default = {
								"scope"
							},
							elements = {
								type = "string"
							}
						}
					},
					{
						audience_required = {
							description = "The audiences (`audience_claim` claim) required to be present in the access token (or introspection results) for successful authorization. This config parameter works in both **AND** / **OR** cases.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						audience_claim = {
							required = false,
							description = "The claim that contains the audience. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							default = {
								"aud"
							},
							elements = {
								type = "string"
							}
						}
					},
					{
						groups_required = {
							description = "The groups (`groups_claim` claim) required to be present in the access token (or introspection results) for successful authorization. This config parameter works in both **AND** / **OR** cases.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						groups_claim = {
							required = false,
							description = "The claim that contains the groups. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							default = {
								"groups"
							},
							elements = {
								type = "string"
							}
						}
					},
					{
						roles_required = {
							description = "The roles (`roles_claim` claim) required to be present in the access token (or introspection results) for successful authorization. This config parameter works in both **AND** / **OR** cases.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						roles_claim = {
							required = false,
							description = "The claim that contains the roles. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							default = {
								"roles"
							},
							elements = {
								type = "string"
							}
						}
					},
					{
						domains = {
							description = "The allowed values for the `hd` claim.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						max_age = {
							description = "The maximum age (in seconds) compared to the `auth_time` claim.",
							type = "number",
							required = false
						}
					},
					{
						authenticated_groups_claim = {
							description = "The claim that contains authenticated groups. This setting can be used together with ACL plugin, but it also enables IdP managed groups with other applications and integrations. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						pushed_authorization_request_endpoint = typedefs.url({
							required = false,
							description = "The pushed authorization endpoint. If set it overrides the value in `pushed_authorization_request_endpoint` returned by the discovery endpoint."
						})
					},
					{
						pushed_authorization_request_endpoint_auth_method = {
							description = "The pushed authorization request endpoint authentication method: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, or `none`: do not authenticate",
							type = "string",
							required = false,
							one_of = {
								"client_secret_basic",
								"client_secret_post",
								"client_secret_jwt",
								"private_key_jwt",
								"tls_client_auth",
								"self_signed_tls_client_auth",
								"none"
							}
						}
					},
					{
						require_pushed_authorization_requests = {
							description = "Forcibly enable or disable the pushed authorization requests. When not set the value is determined through the discovery using the value of `require_pushed_authorization_requests` (which defaults to `false`).",
							type = "boolean",
							required = false
						}
					},
					{
						require_proof_key_for_code_exchange = {
							description = "Forcibly enable or disable the proof key for code exchange. When not set the value is determined through the discovery using the value of `code_challenge_methods_supported`, and enabled automatically (in case the `code_challenge_methods_supported` is missing, the PKCE will not be enabled).",
							type = "boolean",
							required = false
						}
					},
					{
						require_signed_request_object = {
							description = "Forcibly enable or disable the usage of signed request object on authorization or pushed authorization endpoint. When not set the value is determined through the discovery using the value of `require_signed_request_object`, and enabled automatically (in case the `require_signed_request_object` is missing, the feature will not be enabled).",
							type = "boolean",
							required = false
						}
					},
					{
						authorization_endpoint = typedefs.url({
							required = false,
							description = "The authorization endpoint. If set it overrides the value in `authorization_endpoint` returned by the discovery endpoint."
						})
					},
					{
						authorization_query_args_names = {
							description = "Extra query argument names passed to the authorization endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						authorization_query_args_values = {
							description = "Extra query argument values passed to the authorization endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						authorization_query_args_client = {
							description = "Extra query arguments passed from the client to the authorization endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						authorization_rolling_timeout = {
							default = 600,
							description = "Specifies how long the session used for the authorization code flow can be used in seconds until it needs to be renewed. 0 disables the checks and rolling.",
							type = "number",
							required = false
						}
					},
					{
						authorization_cookie_name = {
							default = "authorization",
							description = "The authorization cookie name.",
							type = "string",
							required = false
						}
					},
					{
						authorization_cookie_path = typedefs.path({
							default = "/",
							description = "The authorization cookie Path flag.",
							required = false
						})
					},
					{
						authorization_cookie_domain = {
							description = "The authorization cookie Domain flag.",
							type = "string",
							required = false
						}
					},
					{
						authorization_cookie_same_site = {
							default = "Default",
							required = false,
							description = "Controls whether a cookie is sent with cross-origin requests, providing some protection against cross-site request forgery attacks.",
							type = "string",
							one_of = {
								"Strict",
								"Lax",
								"None",
								"Default"
							}
						}
					},
					{
						authorization_cookie_http_only = {
							default = true,
							description = "Forbids JavaScript from accessing the cookie, for example, through the `Document.cookie` property.",
							type = "boolean",
							required = false
						}
					},
					{
						authorization_cookie_secure = {
							description = "Cookie is only sent to the server when a request is made with the https: scheme (except on localhost), and therefore is more resistant to man-in-the-middle attacks.",
							type = "boolean",
							required = false
						}
					},
					{
						preserve_query_args = {
							default = false,
							description = "With this parameter, you can preserve request query arguments even when doing authorization code flow.",
							type = "boolean",
							required = false
						}
					},
					{
						token_endpoint = typedefs.url({
							required = false,
							description = "The token endpoint. If set it overrides the value in `token_endpoint` returned by the discovery endpoint."
						})
					},
					{
						token_endpoint_auth_method = {
							description = "The token endpoint authentication method: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, or `none`: do not authenticate",
							type = "string",
							required = false,
							one_of = {
								"client_secret_basic",
								"client_secret_post",
								"client_secret_jwt",
								"private_key_jwt",
								"tls_client_auth",
								"self_signed_tls_client_auth",
								"none"
							}
						}
					},
					{
						token_headers_names = {
							description = "Extra header names passed to the token endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_headers_values = {
							description = "Extra header values passed to the token endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_headers_client = {
							description = "Extra headers passed from the client to the token endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_headers_replay = {
							description = "The names of token endpoint response headers to forward to the downstream client.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_headers_prefix = {
							description = "Add a prefix to the token endpoint response headers before forwarding them to the downstream client.",
							type = "string",
							required = false
						}
					},
					{
						token_headers_grants = {
							description = "Enable the sending of the token endpoint response headers only with certain grants: - `password`: with OAuth password grant - `client_credentials`: with OAuth client credentials grant - `authorization_code`: with authorization code flow - `refresh_token` with refresh token grant.",
							type = "array",
							required = false,
							elements = {
								type = "string",
								one_of = {
									"password",
									"client_credentials",
									"authorization_code",
									"refresh_token"
								}
							}
						}
					},
					{
						token_post_args_names = {
							description = "Extra post argument names passed to the token endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_post_args_values = {
							description = "Extra post argument values passed to the token endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_post_args_client = {
							description = "Pass extra arguments from the client to the OpenID-Connect plugin. If arguments exist, the client can pass them using: - Query parameters - Request Body - Request Header  This parameter can be used with `scope` values, like this:  `config.token_post_args_client=scope`  In this case, the token would take the `scope` value from the query parameter or from the request body or from the header and send it to the token endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						introspection_endpoint = typedefs.url({
							required = false,
							description = "The introspection endpoint. If set it overrides the value in `introspection_endpoint` returned by the discovery endpoint."
						})
					},
					{
						introspection_endpoint_auth_method = {
							description = "The introspection endpoint authentication method: : `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, or `none`: do not authenticate",
							type = "string",
							required = false,
							one_of = {
								"client_secret_basic",
								"client_secret_post",
								"client_secret_jwt",
								"private_key_jwt",
								"tls_client_auth",
								"self_signed_tls_client_auth",
								"none"
							}
						}
					},
					{
						introspection_hint = {
							default = "access_token",
							description = "Introspection hint parameter value passed to the introspection endpoint.",
							type = "string",
							required = false
						}
					},
					{
						introspection_check_active = {
							default = true,
							description = "Check that the introspection response has an `active` claim with a value of `true`.",
							type = "boolean",
							required = false
						}
					},
					{
						introspection_accept = {
							default = "application/json",
							required = false,
							description = "The value of `Accept` header for introspection requests: - `application/json`: introspection response as JSON - `application/token-introspection+jwt`: introspection response as JWT (from the current IETF draft document) - `application/jwt`: introspection response as JWT (from the obsolete IETF draft document).",
							type = "string",
							one_of = {
								"application/json",
								"application/token-introspection+jwt",
								"application/jwt"
							}
						}
					},
					{
						introspection_headers_names = {
							description = "Extra header names passed to the introspection endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						introspection_headers_values = {
							encrypted = true,
							required = false,
							description = "Extra header values passed to the introspection endpoint.",
							type = "array",
							elements = {
								type = "string",
								referenceable = true
							}
						}
					},
					{
						introspection_headers_client = {
							description = "Extra headers passed from the client to the introspection endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						introspection_post_args_names = {
							description = "Extra post argument names passed to the introspection endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						introspection_post_args_values = {
							description = "Extra post argument values passed to the introspection endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						introspection_post_args_client = {
							description = "Extra post arguments passed from the client to the introspection endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						introspect_jwt_tokens = {
							default = false,
							description = "Specifies whether to introspect the JWT access tokens (can be used to check for revocations).",
							type = "boolean",
							required = false
						}
					},
					{
						revocation_endpoint = typedefs.url({
							required = false,
							description = "The revocation endpoint. If set it overrides the value in `revocation_endpoint` returned by the discovery endpoint."
						})
					},
					{
						revocation_endpoint_auth_method = {
							description = "The revocation endpoint authentication method: : `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`, or `none`: do not authenticate",
							type = "string",
							required = false,
							one_of = {
								"client_secret_basic",
								"client_secret_post",
								"client_secret_jwt",
								"private_key_jwt",
								"tls_client_auth",
								"self_signed_tls_client_auth",
								"none"
							}
						}
					},
					{
						end_session_endpoint = typedefs.url({
							required = false,
							description = "The end session endpoint. If set it overrides the value in `end_session_endpoint` returned by the discovery endpoint."
						})
					},
					{
						userinfo_endpoint = typedefs.url({
							required = false,
							description = "The user info endpoint. If set it overrides the value in `userinfo_endpoint` returned by the discovery endpoint."
						})
					},
					{
						userinfo_accept = {
							default = "application/json",
							required = false,
							description = "The value of `Accept` header for user info requests: - `application/json`: user info response as JSON - `application/jwt`: user info response as JWT (from the obsolete IETF draft document).",
							type = "string",
							one_of = {
								"application/json",
								"application/jwt"
							}
						}
					},
					{
						userinfo_headers_names = {
							description = "Extra header names passed to the user info endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						userinfo_headers_values = {
							description = "Extra header values passed to the user info endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						userinfo_headers_client = {
							description = "Extra headers passed from the client to the user info endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						userinfo_query_args_names = {
							description = "Extra query argument names passed to the user info endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						userinfo_query_args_values = {
							description = "Extra query argument values passed to the user info endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						userinfo_query_args_client = {
							description = "Extra query arguments passed from the client to the user info endpoint.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						token_exchange_endpoint = typedefs.url({
							required = false,
							description = "The token exchange endpoint."
						})
					},
					{
						session_secret = {
							encrypted = true,
							required = false,
							description = "The session secret.",
							type = "string",
							referenceable = true
						}
					},
					{
						session_audience = {
							default = "default",
							description = "The session audience, which is the intended target application. For example `\"my-application\"`.",
							type = "string",
							required = false
						}
					},
					{
						session_cookie_name = {
							default = "session",
							description = "The session cookie name.",
							type = "string",
							required = false
						}
					},
					{
						session_remember = {
							default = false,
							description = "Enables or disables persistent sessions.",
							type = "boolean",
							required = false
						}
					},
					{
						session_remember_cookie_name = {
							default = "remember",
							description = "Persistent session cookie name. Use with the `remember` configuration parameter.",
							type = "string",
							required = false
						}
					},
					{
						session_remember_rolling_timeout = {
							default = 604800,
							description = "Specifies how long the persistent session is considered valid in seconds. 0 disables the checks and rolling.",
							type = "number",
							required = false
						}
					},
					{
						session_remember_absolute_timeout = {
							default = 2592000,
							description = "Limits how long the persistent session can be renewed in seconds, until re-authentication is required. 0 disables the checks.",
							type = "number",
							required = false
						}
					},
					{
						session_idling_timeout = {
							default = 900,
							description = "Specifies how long the session can be inactive until it is considered invalid in seconds. 0 disables the checks and touching.",
							type = "number",
							required = false
						}
					},
					{
						session_rolling_timeout = {
							default = 3600,
							description = "Specifies how long the session can be used in seconds until it needs to be renewed. 0 disables the checks and rolling.",
							type = "number",
							required = false
						}
					},
					{
						session_absolute_timeout = {
							default = 86400,
							description = "Limits how long the session can be renewed in seconds, until re-authentication is required. 0 disables the checks.",
							type = "number",
							required = false
						}
					},
					{
						session_cookie_path = typedefs.path({
							default = "/",
							description = "The session cookie Path flag.",
							required = false
						})
					},
					{
						session_cookie_domain = {
							description = "The session cookie Domain flag.",
							type = "string",
							required = false
						}
					},
					{
						session_cookie_same_site = {
							default = "Lax",
							required = false,
							description = "Controls whether a cookie is sent with cross-origin requests, providing some protection against cross-site request forgery attacks.",
							type = "string",
							one_of = {
								"Strict",
								"Lax",
								"None",
								"Default"
							}
						}
					},
					{
						session_cookie_http_only = {
							default = true,
							description = "Forbids JavaScript from accessing the cookie, for example, through the `Document.cookie` property.",
							type = "boolean",
							required = false
						}
					},
					{
						session_cookie_secure = {
							description = "Cookie is only sent to the server when a request is made with the https: scheme (except on localhost), and therefore is more resistant to man-in-the-middle attacks.",
							type = "boolean",
							required = false
						}
					},
					{
						session_request_headers = session_headers({
							required = false,
							description = "Set of headers to send to upstream, use id, audience, subject, timeout, idling-timeout, rolling-timeout, absolute-timeout. E.g. `[ \"id\", \"timeout\" ]` will set Session-Id and Session-Timeout request headers."
						})
					},
					{
						session_response_headers = session_headers({
							required = false,
							description = "Set of headers to send to downstream, use id, audience, subject, timeout, idling-timeout, rolling-timeout, absolute-timeout. E.g. `[ \"id\", \"timeout\" ]` will set Session-Id and Session-Timeout response headers."
						})
					},
					{
						session_storage = {
							default = "cookie",
							required = false,
							description = "The session storage for session data: - `cookie`: stores session data with the session cookie (the session cannot be invalidated or revoked without changing session secret, but is stateless, and doesn't require a database) - `memcache`: stores session data in memcached - `redis`: stores session data in Redis.",
							type = "string",
							one_of = {
								"cookie",
								"memcache",
								"memcached",
								"redis"
							}
						}
					},
					{
						session_store_metadata = {
							default = false,
							description = "Configures whether or not session metadata should be stored. This metadata includes information about the active sessions for a specific audience belonging to a specific subject.",
							type = "boolean",
							required = false
						}
					},
					{
						session_enforce_same_subject = {
							default = false,
							description = "When set to `true`, audiences are forced to share the same subject.",
							type = "boolean",
							required = false
						}
					},
					{
						session_hash_subject = {
							default = false,
							description = "When set to `true`, the value of subject is hashed before being stored. Only applies when `session_store_metadata` is enabled.",
							type = "boolean",
							required = false
						}
					},
					{
						session_hash_storage_key = {
							default = false,
							description = "When set to `true`, the storage key (session ID) is hashed for extra security. Hashing the storage key means it is impossible to decrypt data from the storage without a cookie.",
							type = "boolean",
							required = false
						}
					},
					{
						session_memcached_prefix = {
							description = "The memcached session key prefix.",
							type = "string",
							required = false
						}
					},
					{
						session_memcached_socket = {
							description = "The memcached unix socket path.",
							type = "string",
							required = false
						}
					},
					{
						session_memcached_host = {
							default = "127.0.0.1",
							description = "The memcached host.",
							type = "string",
							required = false
						}
					},
					{
						session_memcached_port = typedefs.port({
							default = 11211,
							description = "The memcached port.",
							required = false
						})
					},
					{
						session_redis_prefix = {
							description = "The Redis session key prefix.",
							type = "string",
							required = false
						}
					},
					{
						session_redis_socket = {
							description = "The Redis unix socket path.",
							type = "string",
							required = false
						}
					},
					{
						session_redis_host = {
							default = "127.0.0.1",
							description = "The Redis host.",
							type = "string",
							required = false
						}
					},
					{
						session_redis_port = typedefs.port({
							default = 6379,
							description = "The Redis port.",
							required = false
						})
					},
					{
						session_redis_username = {
							referenceable = true,
							description = "Username to use for Redis connection when the `redis` session storage is defined and ACL authentication is desired. If undefined, ACL authentication will not be performed. This requires Redis v6.0.0+. To be compatible with Redis v5.x.y, you can set it to `default`.",
							type = "string",
							required = false
						}
					},
					{
						session_redis_password = {
							encrypted = true,
							required = false,
							description = "Password to use for Redis connection when the `redis` session storage is defined. If undefined, no AUTH commands are sent to Redis.",
							type = "string",
							referenceable = true
						}
					},
					{
						session_redis_connect_timeout = {
							description = "Session redis connection timeout in milliseconds.",
							type = "integer",
							required = false
						}
					},
					{
						session_redis_read_timeout = {
							description = "Session redis read timeout in milliseconds.",
							type = "integer",
							required = false
						}
					},
					{
						session_redis_send_timeout = {
							description = "Session redis send timeout in milliseconds.",
							type = "integer",
							required = false
						}
					},
					{
						session_redis_ssl = {
							default = false,
							description = "Use SSL/TLS for Redis connection.",
							type = "boolean",
							required = false
						}
					},
					{
						session_redis_ssl_verify = {
							default = false,
							description = "Verify identity provider server certificate.",
							type = "boolean",
							required = false
						}
					},
					{
						session_redis_server_name = {
							description = "The SNI used for connecting the Redis server.",
							type = "string",
							required = false
						}
					},
					{
						session_redis_cluster_nodes = {
							description = "The Redis cluster node host. Takes an array of host records, with either `ip` or `host`, and `port` values.",
							type = "array",
							required = false,
							elements = {
								type = "record",
								fields = {
									{
										ip = typedefs.host({
											default = "127.0.0.1",
											required = true
										})
									},
									{
										port = typedefs.port({
											default = 6379
										})
									}
								}
							}
						}
					},
					{
						session_redis_cluster_max_redirections = {
							description = "The Redis cluster maximum redirects.",
							type = "integer",
							required = false
						}
					},
					{
						reverify = {
							default = false,
							description = "Specifies whether to always verify tokens stored in the session.",
							type = "boolean",
							required = false
						}
					},
					{
						jwt_session_claim = {
							default = "sid",
							description = "The claim to match against the JWT session cookie.",
							type = "string",
							required = false
						}
					},
					{
						jwt_session_cookie = {
							description = "The name of the JWT session cookie.",
							type = "string",
							required = false
						}
					},
					{
						bearer_token_param_type = {
							required = false,
							description = "Where to look for the bearer token: - `header`: search the HTTP headers - `query`: search the URL's query string - `body`: search the HTTP request body - `cookie`: search the HTTP request cookies specified with `config.bearer_token_cookie_name`.",
							type = "array",
							default = {
								"header",
								"query",
								"body"
							},
							elements = {
								type = "string",
								one_of = {
									"header",
									"cookie",
									"query",
									"body"
								}
							}
						}
					},
					{
						bearer_token_cookie_name = {
							description = "The name of the cookie in which the bearer token is passed.",
							type = "string",
							required = false
						}
					},
					{
						client_credentials_param_type = {
							required = false,
							description = "Where to look for the client credentials: - `header`: search the HTTP headers - `query`: search the URL's query string - `body`: search from the HTTP request body.",
							type = "array",
							default = {
								"header",
								"query",
								"body"
							},
							elements = {
								type = "string",
								one_of = {
									"header",
									"query",
									"body"
								}
							}
						}
					},
					{
						password_param_type = {
							required = false,
							description = "Where to look for the username and password: - `header`: search the HTTP headers - `query`: search the URL's query string - `body`: search the HTTP request body.",
							type = "array",
							default = {
								"header",
								"query",
								"body"
							},
							elements = {
								type = "string",
								one_of = {
									"header",
									"query",
									"body"
								}
							}
						}
					},
					{
						id_token_param_type = {
							required = false,
							description = "Where to look for the id token: - `header`: search the HTTP headers - `query`: search the URL's query string - `body`: search the HTTP request body.",
							type = "array",
							default = {
								"header",
								"query",
								"body"
							},
							elements = {
								type = "string",
								one_of = {
									"header",
									"query",
									"body"
								}
							}
						}
					},
					{
						id_token_param_name = {
							description = "The name of the parameter used to pass the id token.",
							type = "string",
							required = false
						}
					},
					{
						refresh_token_param_type = {
							required = false,
							description = "Where to look for the refresh token: - `header`: search the HTTP headers - `query`: search the URL's query string - `body`: search the HTTP request body.",
							type = "array",
							default = {
								"header",
								"query",
								"body"
							},
							elements = {
								type = "string",
								one_of = {
									"header",
									"query",
									"body"
								}
							}
						}
					},
					{
						refresh_token_param_name = {
							description = "The name of the parameter used to pass the refresh token.",
							type = "string",
							required = false
						}
					},
					{
						refresh_tokens = {
							default = true,
							description = "Specifies whether the plugin should try to refresh (soon to be) expired access tokens if the plugin has a `refresh_token` available.",
							type = "boolean",
							required = false
						}
					},
					{
						upstream_headers_claims = {
							description = "The upstream header claims. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						upstream_headers_names = {
							description = "The upstream header names for the claim values.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						upstream_access_token_header = {
							default = "authorization:bearer",
							description = "The upstream access token header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_access_token_jwk_header = {
							description = "The upstream access token JWK header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_id_token_header = {
							description = "The upstream id token header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_id_token_jwk_header = {
							description = "The upstream id token JWK header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_refresh_token_header = {
							description = "The upstream refresh token header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_user_info_header = {
							description = "The upstream user info header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_user_info_jwt_header = {
							description = "The upstream user info JWT header (in case the user info returns a JWT response).",
							type = "string",
							required = false
						}
					},
					{
						upstream_introspection_header = {
							description = "The upstream introspection header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_introspection_jwt_header = {
							description = "The upstream introspection JWT header.",
							type = "string",
							required = false
						}
					},
					{
						upstream_session_id_header = {
							description = "The upstream session id header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_headers_claims = {
							description = "The downstream header claims. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						downstream_headers_names = {
							description = "The downstream header names for the claim values.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						downstream_access_token_header = {
							description = "The downstream access token header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_access_token_jwk_header = {
							description = "The downstream access token JWK header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_id_token_header = {
							description = "The downstream id token header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_id_token_jwk_header = {
							description = "The downstream id token JWK header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_refresh_token_header = {
							description = "The downstream refresh token header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_user_info_header = {
							description = "The downstream user info header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_user_info_jwt_header = {
							description = "The downstream user info JWT header (in case the user info returns a JWT response).",
							type = "string",
							required = false
						}
					},
					{
						downstream_introspection_header = {
							description = "The downstream introspection header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_introspection_jwt_header = {
							description = "The downstream introspection JWT header.",
							type = "string",
							required = false
						}
					},
					{
						downstream_session_id_header = {
							description = "The downstream session id header.",
							type = "string",
							required = false
						}
					},
					{
						login_methods = {
							required = false,
							description = "Enable login functionality with specified grants.",
							type = "array",
							default = {
								"authorization_code"
							},
							elements = {
								type = "string",
								one_of = {
									"password",
									"client_credentials",
									"authorization_code",
									"bearer",
									"introspection",
									"userinfo",
									"kong_oauth2",
									"refresh_token",
									"session"
								}
							}
						}
					},
					{
						login_action = {
							default = "upstream",
							required = false,
							description = "What to do after successful login: - `upstream`: proxy request to upstream service - `response`: terminate request with a response - `redirect`: redirect to a different location.",
							type = "string",
							one_of = {
								"upstream",
								"response",
								"redirect"
							}
						}
					},
					{
						login_tokens = {
							required = false,
							description = "What tokens to include in `response` body or `redirect` query string or fragment: - `id_token`: include id token - `access_token`: include access token - `refresh_token`: include refresh token - `tokens`: include the full token endpoint response - `introspection`: include introspection response.",
							type = "array",
							default = {
								"id_token"
							},
							elements = {
								type = "string",
								one_of = {
									"id_token",
									"access_token",
									"refresh_token",
									"tokens",
									"introspection"
								}
							}
						}
					},
					{
						login_redirect_mode = {
							default = "fragment",
							required = false,
							description = "Where to place `login_tokens` when using `redirect` `login_action`: - `query`: place tokens in query string - `fragment`: place tokens in url fragment (not readable by servers).",
							type = "string",
							one_of = {
								"query",
								"fragment"
							}
						}
					},
					{
						logout_query_arg = {
							description = "The request query argument that activates the logout.",
							type = "string",
							required = false
						}
					},
					{
						logout_post_arg = {
							description = "The request body argument that activates the logout.",
							type = "string",
							required = false
						}
					},
					{
						logout_uri_suffix = {
							description = "The request URI suffix that activates the logout.",
							type = "string",
							required = false
						}
					},
					{
						logout_methods = {
							required = false,
							description = "The request methods that can activate the logout: - `POST`: HTTP POST method - `GET`: HTTP GET method - `DELETE`: HTTP DELETE method.",
							type = "array",
							default = {
								"POST",
								"DELETE"
							},
							elements = {
								type = "string",
								one_of = {
									"POST",
									"GET",
									"DELETE"
								}
							}
						}
					},
					{
						logout_revoke = {
							default = false,
							description = "Revoke tokens as part of the logout.\n\nFor more granular token revocation, you can also adjust the `logout_revoke_access_token` and `logout_revoke_refresh_token` parameters.",
							type = "boolean",
							required = false
						}
					},
					{
						logout_revoke_access_token = {
							default = true,
							description = "Revoke the access token as part of the logout. Requires `logout_revoke` to be set to `true`.",
							type = "boolean",
							required = false
						}
					},
					{
						logout_revoke_refresh_token = {
							default = true,
							description = "Revoke the refresh token as part of the logout. Requires `logout_revoke` to be set to `true`.",
							type = "boolean",
							required = false
						}
					},
					{
						consumer_claim = {
							description = "The claim used for consumer mapping. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							required = false,
							elements = {
								type = "string"
							}
						}
					},
					{
						consumer_by = {
							required = false,
							description = "Consumer fields used for mapping: - `id`: try to find the matching Consumer by `id` - `username`: try to find the matching Consumer by `username` - `custom_id`: try to find the matching Consumer by `custom_id`.",
							type = "array",
							default = {
								"username",
								"custom_id"
							},
							elements = {
								type = "string",
								one_of = {
									"id",
									"username",
									"custom_id"
								}
							}
						}
					},
					{
						consumer_optional = {
							default = false,
							description = "Do not terminate the request if consumer mapping fails.",
							type = "boolean",
							required = false
						}
					},
					{
						credential_claim = {
							required = false,
							description = "The claim used to derive virtual credentials (e.g. to be consumed by the rate-limiting plugin), in case the consumer mapping is not used. If multiple values are set, it means the claim is inside a nested object of the token payload.",
							type = "array",
							default = {
								"sub"
							},
							elements = {
								type = "string"
							}
						}
					},
					{
						anonymous = {
							description = "An optional string (consumer UUID or username) value that functions as an “anonymous” consumer if authentication fails. If empty (default null), requests that fail authentication will return a `4xx` HTTP status code. This value must refer to the consumer `id` or `username` attribute, and **not** its `custom_id`.",
							type = "string",
							required = false
						}
					},
					{
						run_on_preflight = {
							default = true,
							description = "Specifies whether to run this plugin on pre-flight (`OPTIONS`) requests.",
							type = "boolean",
							required = false
						}
					},
					{
						leeway = {
							default = 0,
							description = "Defines leeway time (in seconds) for `auth_time`, `exp`, `iat`, and `nbf` claims",
							type = "number",
							required = false
						}
					},
					{
						verify_parameters = {
							default = false,
							description = "Verify plugin configuration against discovery.",
							type = "boolean",
							required = false
						}
					},
					{
						verify_nonce = {
							default = true,
							description = "Verify nonce on authorization code flow.",
							type = "boolean",
							required = false
						}
					},
					{
						verify_claims = {
							default = true,
							description = "Verify tokens for standard claims.",
							type = "boolean",
							required = false
						}
					},
					{
						verify_signature = {
							default = true,
							description = "Verify signature of tokens.",
							type = "boolean",
							required = false
						}
					},
					{
						ignore_signature = {
							required = false,
							description = "Skip the token signature verification on certain grants: - `password`: OAuth password grant - `client_credentials`: OAuth client credentials grant - `authorization_code`: authorization code flow - `refresh_token`: OAuth refresh token grant - `session`: session cookie authentication - `introspection`: OAuth introspection - `userinfo`: OpenID Connect user info endpoint authentication.",
							type = "array",
							default = {},
							elements = {
								type = "string",
								one_of = {
									"password",
									"client_credentials",
									"authorization_code",
									"refresh_token",
									"session",
									"introspection",
									"userinfo"
								}
							}
						}
					},
					{
						enable_hs_signatures = {
							default = false,
							description = "Enable shared secret, for example, HS256, signatures (when disabled they will not be accepted).",
							type = "boolean",
							required = false
						}
					},
					{
						disable_session = {
							description = "Disable issuing the session cookie with the specified grants.",
							type = "array",
							required = false,
							elements = {
								type = "string",
								one_of = {
									"password",
									"client_credentials",
									"authorization_code",
									"bearer",
									"introspection",
									"userinfo",
									"kong_oauth2",
									"refresh_token",
									"session"
								}
							}
						}
					},
					{
						cache_ttl = {
							default = 3600,
							description = "The default cache ttl in seconds that is used in case the cached object does not specify the expiry.",
							type = "number",
							required = false
						}
					},
					{
						cache_ttl_max = {
							description = "The maximum cache ttl in seconds (enforced).",
							type = "number",
							required = false
						}
					},
					{
						cache_ttl_min = {
							description = "The minimum cache ttl in seconds (enforced).",
							type = "number",
							required = false
						}
					},
					{
						cache_ttl_neg = {
							description = "The negative cache ttl in seconds.",
							type = "number",
							required = false
						}
					},
					{
						cache_ttl_resurrect = {
							description = "The resurrection ttl in seconds.",
							type = "number",
							required = false
						}
					},
					{
						cache_tokens = {
							default = true,
							description = "Cache the token endpoint requests.",
							type = "boolean",
							required = false
						}
					},
					{
						cache_tokens_salt = {
							auto = true,
							description = "Salt used for generating the cache key that is used for caching the token endpoint requests.",
							type = "string",
							required = false
						}
					},
					{
						cache_introspection = {
							default = true,
							description = "Cache the introspection endpoint requests.",
							type = "boolean",
							required = false
						}
					},
					{
						cache_token_exchange = {
							default = true,
							description = "Cache the token exchange endpoint requests.",
							type = "boolean",
							required = false
						}
					},
					{
						cache_user_info = {
							default = true,
							description = "Cache the user info requests.",
							type = "boolean",
							required = false
						}
					},
					{
						search_user_info = {
							default = false,
							description = "Specify whether to use the user info endpoint to get additional claims for consumer mapping, credential mapping, authenticated groups, and upstream and downstream headers.",
							type = "boolean",
							required = false
						}
					},
					{
						hide_credentials = {
							default = false,
							description = "Remove the credentials used for authentication from the request. If multiple credentials are sent with the same request, the plugin will remove those that were used for successful authentication.",
							type = "boolean",
							required = false
						}
					},
					{
						http_version = {
							default = 1.1,
							required = false,
							description = "The HTTP version used for the requests by this plugin: - `1.1`: HTTP 1.1 (the default) - `1.0`: HTTP 1.0.",
							type = "number",
							custom_validator = function (v)
								if v == 1 or v == 1.1 then
									return true
								end

								return nil, "must be 1.0 or 1.1"
							end
						}
					},
					{
						http_proxy = typedefs.url({
							required = false,
							description = "The HTTP proxy."
						})
					},
					{
						http_proxy_authorization = {
							description = "The HTTP proxy authorization.",
							type = "string",
							required = false
						}
					},
					{
						https_proxy = typedefs.url({
							required = false,
							description = "The HTTPS proxy."
						})
					},
					{
						https_proxy_authorization = {
							description = "The HTTPS proxy authorization.",
							type = "string",
							required = false
						}
					},
					{
						no_proxy = {
							description = "Do not use proxy with these hosts.",
							type = "string",
							required = false
						}
					},
					{
						keepalive = {
							default = true,
							description = "Use keepalive with the HTTP client.",
							type = "boolean",
							required = false
						}
					},
					{
						ssl_verify = {
							default = false,
							description = "Verify identity provider server certificate. If set to `true`, the plugin uses the CA certificate set in the `kong.conf` config parameter `lua_ssl_trusted_certificate`.",
							type = "boolean",
							required = false
						}
					},
					{
						timeout = {
							default = 10000,
							description = "Network IO timeout in milliseconds.",
							type = "number",
							required = false
						}
					},
					{
						display_errors = {
							default = false,
							description = "Display errors on failure responses.",
							type = "boolean",
							required = false
						}
					},
					{
						by_username_ignore_case = {
							default = false,
							description = "If `consumer_by` is set to `username`, specify whether `username` can match consumers case-insensitively.",
							type = "boolean",
							required = false
						}
					},
					{
						resolve_distributed_claims = {
							default = false,
							description = "Distributed claims are represented by the `_claim_names` and `_claim_sources` members of the JSON object containing the claims. If this parameter is set to `true`, the plugin explicitly resolves these distributed claims.",
							type = "boolean",
							required = false
						}
					},
					{
						expose_error_code = {
							default = true,
							description = "Specifies whether to expose the error code header, as defined in RFC 6750. If an authorization request fails, this header is sent in the response. Set to `false` to disable.",
							type = "boolean"
						}
					},
					{
						token_cache_key_include_scope = {
							default = false,
							description = "Include the scope in the token cache key, so token with different scopes are considered diffrent tokens.",
							type = "boolean"
						}
					},
					{
						introspection_token_param_name = {
							default = "token",
							description = "Designate token's parameter name for introspection.",
							type = "string",
							required = false
						}
					},
					{
						revocation_token_param_name = {
							default = "token",
							description = "Designate token's parameter name for revocation.",
							type = "string",
							required = false
						}
					},
					{
						proof_of_possession_mtls = {
							default = "off",
							required = false,
							description = "Enable mtls proof of possession. If set to strict, all tokens (from supported auth_methods: bearer, introspection, and session granted with bearer or introspection) are verified, if set to optional, only tokens that contain the certificate hash claim are verified. If the verification fails, the request will be rejected with 401.",
							type = "string",
							one_of = {
								"off",
								"strict",
								"optional"
							}
						}
					},
					{
						proof_of_possession_auth_methods_validation = {
							default = true,
							description = "If set to true, only the auth_methods that are compatible with Proof of Possession (PoP) can be configured when PoP is enabled. If set to false, all auth_methods will be configurable and PoP checks will be silently skipped for those auth_methods that are not compatible with PoP.",
							type = "boolean",
							required = false
						}
					},
					{
						tls_client_auth_cert_id = typedefs.uuid({
							auto = false,
							description = "ID of the Certificate entity representing the client certificate to use for mTLS client authentication for connections between Kong and the Auth Server.",
							required = false
						})
					},
					{
						tls_client_auth_ssl_verify = {
							default = true,
							description = "Verify identity provider server certificate during mTLS client authentication.",
							type = "boolean",
							required = false
						}
					},
					{
						mtls_token_endpoint = typedefs.url({
							required = false,
							description = "Alias for the token endpoint to be used for mTLS client authentication. If set it overrides the value in `mtls_endpoint_aliases` returned by the discovery endpoint."
						})
					},
					{
						mtls_introspection_endpoint = typedefs.url({
							required = false,
							description = "Alias for the introspection endpoint to be used for mTLS client authentication. If set it overrides the value in `mtls_endpoint_aliases` returned by the discovery endpoint."
						})
					},
					{
						mtls_revocation_endpoint = typedefs.url({
							required = false,
							description = "Alias for the introspection endpoint to be used for mTLS client authentication. If set it overrides the value in `mtls_endpoint_aliases` returned by the discovery endpoint."
						})
					},
					{
						proof_of_possession_dpop = {
							default = "off",
							required = false,
							description = "Enable Demonstrating Proof-of-Possession (DPoP). If set to strict, all request are verified despite the presence of the DPoP key claim (cnf.jkt). If set to optional, only tokens bound with DPoP's key are verified with the proof.",
							type = "string",
							one_of = {
								"off",
								"strict",
								"optional"
							}
						}
					},
					{
						dpop_use_nonce = {
							default = false,
							description = "Specifies whether to challenge the client with a nonce value for DPoP proof. When enabled it will also be used to calculate the DPoP proof lifetime.",
							type = "boolean",
							required = false
						}
					},
					{
						dpop_proof_lifetime = {
							default = 300,
							type = "number",
							required = false,
							description = "Specifies the lifetime in seconds of the DPoP proof. It determines how long the same proof can be used after creation. " .. "The creation time is determined by the nonce creation time if a nonce is used, and the iat claim otherwise."
						}
					}
				},
				shorthand_fields = {
					{
						authorization_cookie_lifetime = {
							type = "number",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.authorization_cookie_lifetime is deprecated, please use config.authorization_rolling_timeout instead"
							},
							func = function (value)
								return {
									authorization_rolling_timeout = value
								}
							end
						}
					},
					{
						authorization_cookie_samesite = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.authorization_cookie_samesite is deprecated, please use config.authorization_cookie_same_site instead"
							},
							func = function (value)
								if value == "off" then
									value = "Default"
								end

								return {
									authorization_cookie_same_site = value
								}
							end
						}
					},
					{
						authorization_cookie_httponly = {
							type = "boolean",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.authorization_cookie_httponly is deprecated, please use config.authorization_cookie_http_only instead"
							},
							func = function (value)
								return {
									authorization_cookie_http_only = value
								}
							end
						}
					},
					{
						session_cookie_lifetime = {
							type = "number",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_cookie_lifetime is deprecated, please use config.session_rolling_timeout instead"
							},
							func = function (value)
								return {
									session_rolling_timeout = value
								}
							end
						}
					},
					{
						session_cookie_idletime = {
							type = "number",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_cookie_idletime is deprecated, please use config.session_idling_timeout instead"
							},
							func = function (value)
								return {
									session_idling_timeout = value
								}
							end
						}
					},
					{
						session_cookie_samesite = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_cookie_samesite is deprecated, please use config.session_cookie_same_site instead"
							},
							func = function (value)
								if value == "off" then
									value = "Lax"
								end

								return {
									session_cookie_same_site = value
								}
							end
						}
					},
					{
						session_cookie_httponly = {
							type = "boolean",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_cookie_httponly is deprecated, please use config.session_cookie_http_only instead"
							},
							func = function (value)
								return {
									session_cookie_http_only = value
								}
							end
						}
					},
					{
						session_memcache_prefix = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_memcache_prefix is deprecated, please use config.session_memcached_prefix instead"
							},
							func = function (value)
								return {
									session_memcached_prefix = value
								}
							end
						}
					},
					{
						session_memcache_socket = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_memcache_socket is deprecated, please use config.session_memcached_socket instead"
							},
							func = function (value)
								return {
									session_memcached_socket = value
								}
							end
						}
					},
					{
						session_memcache_host = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_memcache_host is deprecated, please use config.session_memcached_host instead"
							},
							func = function (value)
								return {
									session_memcached_host = value
								}
							end
						}
					},
					{
						session_memcache_port = {
							type = "integer",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_memcache_port is deprecated, please use config.session_memcached_port instead"
							},
							func = function (value)
								return {
									session_memcached_port = value
								}
							end
						}
					},
					{
						session_redis_cluster_maxredirections = {
							type = "integer",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_redis_cluster_maxredirections is deprecated, please use config.session_redis_cluster_max_redirections instead"
							},
							func = function (value)
								return {
									session_redis_cluster_max_redirections = value
								}
							end
						}
					},
					{
						session_cookie_renew = {
							type = "number",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_cookie_renew option does not exist anymore"
							},
							func = function ()
							end
						}
					},
					{
						session_cookie_maxsize = {
							type = "integer",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_cookie_maxsize option does not exist anymore"
							},
							func = function ()
							end
						}
					},
					{
						session_strategy = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_strategy option does not exist anymore"
							},
							func = function ()
							end
						}
					},
					{
						session_compressor = {
							type = "string",
							deprecation = {
								removal_in_version = "4.0",
								message = "openid-connect: config.session_compressor option does not exist anymore"
							},
							func = function ()
							end
						}
					}
				}
			}
		}
	}
}

return config
