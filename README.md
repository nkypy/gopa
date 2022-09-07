# gopa

## 使用

```go
// 若要修改默认返回
// 修改包内 ErrResponse
//
// src: rego 文件内容
// data: yaml 文件内容
// path: 数据库路径，若为空，则角色权限在配置文件
// inUrl: 平台信息是否在 url 中
// prefix: 路由前缀，写规则可以省略
r := gin.Default()
r.Use(gopa.Opa(src, data, "opa.db", true, "/api/v1"))
```

## 测试

```bash
# 新增测试可在 rego 文件中编辑
opa test -v examples/policy.rego examples/policy.yaml
```

## 网页访问

```bash
# 允许
http://127.0.0.1:8080/v1/orders/1?role=admin&platform=web
# 不允许
http://127.0.0.1:8080/v1/users/1?role=admin&platform=web
# 允许
http://127.0.0.1:8080/v1/users/1?role=super_admin&platform=web
```
