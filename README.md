# gopa

## 使用

```go
// 若要修改默认返回
// 修改包内 ErrResponse
//
// input 为 rego 文件内容
// data 为 yaml 文件内容
// prefix 为路由前缀，如：/api/v1，这样写权限时可省略这部分
// prefix 可省略，也可多个
r := gin.Default()
r.Use(gopa.Opa(input, data, prefix))
```

## 测试

```bash
# 新增测试可在 rego 文件中编辑
opa test -v examples/policy.rego examples/policy.yaml
```

## 网页访问

```bash
http://127.0.0.1:8080/v1/ping/haha?role=admin
```
