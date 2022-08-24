# gopa

## 使用

```go
// 若要修改默认返回
// 修改包内 ErrResponse
//
// input 为 rego 文件内容
// data 为 yaml 文件内容
// ch 为角色信息，数据库读取，写入 chan，如不传，需在 data 中配置好
// prefix 为路由前缀，如：/api/v1，这样写权限时可省略这部分
// prefix 可省略，也可多个
r := gin.Default()
ch := make(chan []byte, 1)
r.Use(gopa.Opa(input, data, ch, prefix))
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
