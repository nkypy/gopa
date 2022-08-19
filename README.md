# gopa

## 使用

```go
// prefix 为路由前缀，如：/api/v1，这样写权限时可省略这部分
// input 为 rego 文件内容
// data 为 yaml 文件内容
r := gin.Default()
r.Use(gopa.Opa(prefix, input, data))
```

## 测试

```bash
# 新增测试可在 rego 文件中编辑
opa test -v examples/policy.rego examples/policy.yaml
```
