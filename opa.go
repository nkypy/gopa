package gopa

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"gopkg.in/yaml.v3"
)

var ErrResponse = gin.H{
	"code": -1,
	"msg":  "not allowed",
}

var Params = []string{"role", "platform"}

// Opa
// src: rego 文件内容
// data: yaml 文件内容
// ch: 角色信息，数据库读取，写入chan，如不传，需在 data 中配置好
// prefix: 路由前缀，写规则可以省略
func Opa(src, data []byte, ch <-chan ([]byte), prefix ...string) gin.HandlerFunc {
	var store map[string]interface{}
	err := yaml.Unmarshal(data, &store)
	if err != nil {
		panic(err)
	}
	pname, _, _ := bufio.NewReader(bytes.NewReader(src)).ReadLine()
	name := strings.TrimSpace(strings.Replace(string(pname), "package ", "", 1))

	var locker sync.RWMutex
	var r *rego.Rego
	r = rego.New(
		rego.Query("x = data."+name+".allow"),
		rego.Module("authz.rego", string(src)),
		rego.Store(inmem.NewFromObject(store)),
	)

	// 新的角色信息传入，重加载
	go func() {
		for d := range ch {
			var role map[string]interface{}
			if err := yaml.Unmarshal(d, &role); err == nil {
				for k := range role {
					store[k] = role[k]
				}
				locker.Lock()
				r = rego.New(
					rego.Query("x = data."+name+".allow"),
					rego.Module("authz.rego", string(src)),
					rego.Store(inmem.NewFromObject(store)),
				)
				locker.Unlock()
			}
		}
	}()

	return func(c *gin.Context) {
		endpoint := c.FullPath()
		if endpoint != "" {
			for _, p := range prefix {
				endpoint = strings.Replace(endpoint, p, "", 1)
			}
			locker.RLock()
			defer locker.RUnlock()
			ctx := context.TODO()
			query, err := r.PrepareForEval(ctx)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusOK, ErrResponse)
				return
			}
			input := map[string]interface{}{
				"endpoint": c.Request.Method + endpoint,
			}
			// 字段可按照需要自行修改
			for _, i := range Params {
				input[i] = c.GetString(i) // 从Context中获取
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
