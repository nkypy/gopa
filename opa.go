package gopa

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"gopkg.in/yaml.v3"
)

// Opa
// prefix: 路由前缀，写规则可以省略
// src: rego 文件内容
// data: yaml 文件内容
func Opa(prefix string, src, data []byte) gin.HandlerFunc {
	var store map[string]interface{}
	err := yaml.Unmarshal(data, &store)
	if err != nil {
		panic(err)
	}
	pname, _, _ := bufio.NewReader(bytes.NewReader(src)).ReadLine()
	name := strings.TrimSpace(strings.Replace(string(pname), "package ", "", 1))
	r := rego.New(
		rego.Query("x = data."+name+".allow"),
		rego.Module("policy.rego", string(src)),
		rego.Store(inmem.NewFromObject(store)),
	)

	return func(c *gin.Context) {
		path := strings.Replace(c.FullPath(), prefix, "", 1)
		if path != "" {
			ctx := context.TODO()
			query, err := r.PrepareForEval(ctx)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusOK, gin.H{
					"code": -1,
					"msg":  "policy error: " + err.Error(),
				})
				return
			}
			input := map[string]interface{}{
				"method": c.Request.Method,
				"path":   path,
			}
			input["role"] = c.Query("role")
			rs, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil || !rs[0].Bindings["x"].(bool) {
				c.AbortWithStatusJSON(http.StatusOK, gin.H{
					"code": -1,
					"msg":  "not allowed",
				})
				return
			}
		}

		c.Next()
	}
}
