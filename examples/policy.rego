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

# 超级管理员允许
allow if {
	input.role == "super_admin"
}

# 匹配平台权限
allow if {
	roles := data.user_platforms[input.role]
	r := roles[_]
	permissions := data.platform_permissions[r]
	p := permissions[_]
	startswith(input.endpoint, p)
}

# 匹配 API 权限
allow if {
	roles := data.user_pages[input.role]
	r := roles[_]
	permissions := data.page_permissions[r]
	p := permissions[_]
	startswith(input.endpoint, p)
}

####################
# 规则测试
####################

test_role_permission if {
	allow with input as {"role": "admin", "endpoint": "GET/"}
	allow with input as {"role": "super_admin", "endpoint": "POST/roles/:id"}
	allow with input as {"role": "6", "endpoint": "GET/users/info"}
}

test_whitelist_permission if {
	allow with input as {"endpoint": "POST/login"}
	not allow with input as {"endpoint": "GET/users/:id"}
}
