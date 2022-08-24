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

# 匹配 API 权限
allow if {
	roles := data.user_roles[input.role]
	r := roles[_]
	permissions := data.permissions[r]
	input.endpoint in permissions
}

####################
# 规则测试
####################

test_role_permission if {
	allow with input as {"role": "admin", "endpoint": "GET/orders/:id"}
	not allow with input as {"role": "admin", "endpoint": "GET/roles/:id"}
	allow with input as {"role": "super_admin", "endpoint": "POST/roles/:id"}
}

test_whitelist_permission if {
	allow with input as {"endpoint": "GET/login"}
	not allow with input as {"endpoint": "GET/hello/:id"}
}
