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

var ErrResponse = gin.H{
	"code": -1,
	"msg":  "not allowed",
}

var Params = []string{"role"}

// Opa
// src: rego 文件内容
// data: yaml 文件内容
// prefix: 路由前缀，写规则可以省略
func Opa(src, data []byte, prefix ...string) gin.HandlerFunc {
	var store map[string]interface{}
	err := yaml.Unmarshal(data, &store)
	if err != nil {
		panic(err)
	}
	pname, _, _ := bufio.NewReader(bytes.NewReader(src)).ReadLine()
	name := strings.TrimSpace(strings.Replace(string(pname), "package ", "", 1))
	r := rego.New(
		rego.Query("x = data."+name+".allow"),
		rego.Module("authz.rego", string(src)),
		rego.Store(inmem.NewFromObject(store)),
	)

	return func(c *gin.Context) {
		endpoint := c.FullPath()
		if endpoint != "" {
			for _, p := range prefix {
				endpoint = strings.Replace(endpoint, p, "", 1)
			}
			ctx := context.TODO()
			query, err := r.PrepareForEval(ctx)
			if err != nil {
				panic(err)
			}
			// 字段可按照需要自行修改
			input := map[string]interface{}{
				"method":   c.Request.Method,
				"endpoint": endpoint,
			}
			for _, i := range Params {
				input[i] = c.GetString(i) // 角色名从Context中获取
			}
			rs, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil || !rs[0].Bindings["x"].(bool) {
				c.AbortWithStatusJSON(http.StatusOK, ErrResponse)
				return
			}
		}

		c.Next()
	}
}
