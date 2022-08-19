package app.authz

import future.keywords


####################
# 规则解析
####################

default allow := false

# 网址白名单
allow if {
	input.path in data.whitelist_paths
}

# 匹配 API 权限
allow if {
	roles := data.user_roles[input.role]
	# for each role in that list
	r := roles[_]
	# lookup the permissions list for role r
	permissions := data.api_role_permissions[r]
	# for each permission
	p := permissions[_]
	p == {"path": input.path, "method": input.method}
}

# 匹配 WEB 权限
allow if {
	roles := data.user_roles[input.role]
	# for each role in that list
	r := roles[_]
	# lookup the permissions list for role r
	permissions := data.web_role_permissions[r]
	# for each permission
	p := permissions[_]
	p == input.path
}


####################
# 规则测试
####################

test_api_role_permission if {
	allow with input as {"role": "admin", "path": "/ping/:id", "method": "GET"}
	not allow with input as {"role": "admin", "path": "/ping/:id", "method": "POST"}
	allow with input as {"role": "super_admin", "path": "/hello/:id", "method": "POST"}
}

test_web_role_permission if {
	allow with input as {"role": "super_admin", "path": "menu:settings"}
	not allow with input as {"role": "admin", "path": "menu:settings"}
	allow with input as {"role": "admin", "path": "page:index"}
}
