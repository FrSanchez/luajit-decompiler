local utils = require("kong.admin_gui.utils")
local portal_and_vitals_allowed = require("kong.enterprise_edition.license_helpers").portal_and_vitals_allowed
local _M = {
	fill_ee_kconfigs = function (kong_config, config_table)
		local rbac_enforced = kong_config.rbac == "both" or kong_config.rbac == "on"
		local vitals = kong_config.vitals
		local portal = kong_config.portal

		if not portal_and_vitals_allowed() then
			vitals = false
			portal = false
		end

		config_table.ADMIN_GUI_AUTH = utils.prepare_variable(kong_config.admin_gui_auth)
		config_table.ADMIN_GUI_HEADER_TXT = utils.prepare_variable(kong_config.admin_gui_header_txt)
		config_table.ADMIN_GUI_HEADER_BG_COLOR = utils.prepare_variable(kong_config.admin_gui_header_bg_color)
		config_table.ADMIN_GUI_HEADER_TXT_COLOR = utils.prepare_variable(kong_config.admin_gui_header_txt_color)
		config_table.ADMIN_GUI_FOOTER_TXT = utils.prepare_variable(kong_config.admin_gui_footer_txt)
		config_table.ADMIN_GUI_FOOTER_BG_COLOR = utils.prepare_variable(kong_config.admin_gui_footer_bg_color)
		config_table.ADMIN_GUI_FOOTER_TXT_COLOR = utils.prepare_variable(kong_config.admin_gui_footer_txt_color)
		config_table.ADMIN_GUI_LOGIN_BANNER_TITLE = utils.prepare_variable(kong_config.admin_gui_login_banner_title)
		config_table.ADMIN_GUI_LOGIN_BANNER_BODY = utils.prepare_variable(kong_config.admin_gui_login_banner_body)
		config_table.RBAC = utils.prepare_variable(kong_config.rbac)
		config_table.RBAC_ENFORCED = utils.prepare_variable(rbac_enforced)
		config_table.RBAC_HEADER = utils.prepare_variable(kong_config.rbac_auth_header)
		config_table.RBAC_USER_HEADER = utils.prepare_variable(kong_config.admin_gui_auth_header)
		config_table.FEATURE_FLAGS = utils.prepare_variable(kong_config.admin_gui_flags)
		config_table.VITALS = utils.prepare_variable(vitals)
		config_table.PORTAL = utils.prepare_variable(portal)
		config_table.PORTAL_GUI_PROTOCOL = utils.prepare_variable(kong_config.portal_gui_protocol)
		config_table.PORTAL_GUI_HOST = utils.prepare_variable(kong_config.portal_gui_host)
		config_table.PORTAL_GUI_USE_SUBDOMAINS = utils.prepare_variable(kong_config.portal_gui_use_subdomains)
	end
}

return _M
