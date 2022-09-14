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
	bolt "go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

var ErrResponse = gin.H{
	"code": -1,
	"msg":  "not allowed",
}

type WhiteList struct {
	WhitelistEndpoints []string `yaml:"whitelist_endpoints"`
}

// 更新数据库角色权限后，把 user_roles 和 user_platforms 的 yaml 格式数据传入 chan
var policyCh chan []byte
var permissionTree PermissionConfig
var db *bolt.DB

// Opa
// src: rego 文件内容
// data: yaml 文件内容
// ch: 角色信息，数据库读取，写入chan，如不传，需在 data 中配置好
// path: 数据库路径，若为空，则角色权限在配置文件
// inUrl: 平台信息是否在 url 中
// prefix: 路由前缀，写规则可以省略
func Opa(src, data []byte, path string, inUrl bool, prefix ...string) gin.HandlerFunc {
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
	if len(path) != 0 {
		policyCh = make(chan []byte, 1)
		db, err = bolt.Open(path, 0666, nil)
		if err != nil {
			panic(err)
		}
		db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket([]byte(BUCKET))
			return err
		})
		// 从数据库加载信息
		loadRolePermission()
		// 新的角色信息传入，重加载
		go func() {
			for d := range policyCh {
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
	}

	permissionTree = loadPermissionInfo(data)

	var whitelist WhiteList
	yaml.Unmarshal(data, &whitelist)

	return func(c *gin.Context) {
		var platform string
		endpoint := c.FullPath()
		if endpoint != "" {
			for _, p := range prefix {
				endpoint = strings.Replace(endpoint, p, "", 1)
			}
			isWhite := false
			for _, i := range whitelist.WhitelistEndpoints {
				if i[strings.Index(i, "/"):] == endpoint {
					isWhite = true
				}
			}
			if inUrl && !isWhite {
				idx := strings.Index(endpoint[1:], "/") + 1
				platform = endpoint[1:idx]
				endpoint = endpoint[idx:]
			} else {
				platform = c.GetString("platform")
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
				"role":     c.GetString("role"),
				"platform": platform,
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

func loadRolePermission() {
	permission := map[string]map[string][]string{
		"user_roles":     {},
		"user_platforms": {},
	}
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var role RolePermission
			yaml.Unmarshal(v, &role)
			permission["user_roles"][string(k)] = role.Pages
			permission["user_platforms"][string(k)] = role.Platforms
		}
		return nil
	})
	buf, _ := yaml.Marshal(permission)
	policyCh <- buf
}
