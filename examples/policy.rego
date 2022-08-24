package app.authz

import future.keywords

####################
# 规则解析
####################

default allow := false

# 网址白名单
allow if {
	input.endpoint in data.whitelist_endpoints
}

allow if {
	platform_allowed
	api_allowed
}

# 匹配平台权限
platform_allowed if {
	roles := data.user_platforms[input.role]
	input.platform in roles
}

# 匹配 API 权限
api_allowed if {
	roles := data.user_roles[input.role]
	r := roles[_]
	permissions := data.permissions[r]
	input.endpoint in permissions
}

####################
# 规则测试
####################

test_role_permission if {
	allow with input as {"role": "admin", "endpoint": "GET/orders/:id", "platform": "web"}
	not allow with input as {"role": "admin", "endpoint": "GET/orders/:id", "platform": "app"}
	not allow with input as {"role": "admin", "endpoint": "GET/roles/:id", "platform": "web"}
	allow with input as {"role": "super_admin", "endpoint": "POST/roles/:id", "platform": "app"}
}

test_whitelist_permission if {
	allow with input as {"endpoint": "GET/login"}
	not allow with input as {"endpoint": "GET/hello/:id"}
}
