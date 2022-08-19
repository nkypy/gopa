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
// src: rego 文件内容
// data: yaml 文件内容
func Opa(src, data []byte) gin.HandlerFunc {
	var store map[string]interface{}
	err := yaml.Unmarshal(data, &store)
	if err != nil {
		panic(err)
	}
	pname, _, _ := bufio.NewReader(bytes.NewReader(src)).ReadLine()
	name := strings.TrimSpace(strings.Split(string(pname), " ")[1])
	r := rego.New(
		rego.Query("x = data."+name+".allow"),
		rego.Module("policy.rego", string(src)),
		rego.Store(inmem.NewFromObject(store)),
	)

	return func(c *gin.Context) {
		path := c.FullPath()
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
