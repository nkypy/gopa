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
	"github.com/xandercheung/ogs-go"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

// 可配置参数
type config struct {
	db      *bolt.DB
	ch      chan []byte
	prefix  []string
	errResp interface{}
	locker  sync.RWMutex
}

type ConfigOption func(*config)

// 默认配置
var defaultConfig = config{
	db:      nil,
	ch:      make(chan []byte, 1),
	prefix:  []string{"/api/v1"},
	errResp: ogs.RspError(10000, "您没有该操作的权限"),
	locker:  sync.RWMutex{},
}

type RoleField struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Name     string `yaml:"name" json:"name"`
}

// 用户权限
type RolePermission struct {
	Pages     []RoleField `yaml:"pages" json:"pages"`
	Platforms []RoleField `yaml:"platforms" json:"platforms"`
}

type Node struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Name     string `yaml:"name" json:"name"`
	Children []Node `yaml:"children" json:"children"`
}

type PermissionConfig struct {
	Pages     map[string][]Node `yaml:"pages" json:"pages"`
	Platforms []Node            `yaml:"platforms" json:"platforms"`
}

type PermissionInfo struct {
	Pages     []Node `yaml:"pages" json:"pages"`
	Platforms []Node `yaml:"platforms" json:"platforms"`
}

const BUCKET = "permission"

var roleStore = map[string]RolePermission{}
var permissionTree PermissionConfig

func WithPath(path string) ConfigOption {
	return func(c *config) {
		db, err := bolt.Open(path, 0666, nil)
		if err != nil {
			panic(err)
		}
		c.db = db
	}
}

func WithPrefix(prefix ...string) ConfigOption {
	return func(c *config) {
		c.prefix = prefix
	}
}

func WithErrResp(resp gin.H) ConfigOption {
	return func(c *config) {
		c.errResp = resp
	}
}

// Opa
// src: rego 文件内容
// data: yaml 文件内容
// opts: 其他设置
func Opa(src, data []byte, opts ...ConfigOption) gin.HandlerFunc {
	var store map[string]interface{}
	err := yaml.Unmarshal(data, &store)
	if err != nil {
		panic(err)
	}
	pname, _, _ := bufio.NewReader(bytes.NewReader(src)).ReadLine()
	name := strings.TrimSpace(strings.Replace(string(pname), "package ", "", 1))

	for _, k := range opts {
		k(&defaultConfig)
	}

	var locker sync.RWMutex
	var r *rego.Rego
	r = rego.New(
		rego.Query("x = data."+name+".allow"),
		rego.Module("authz.rego", string(src)),
		rego.Store(inmem.NewFromObject(store)),
	)

	permissionTree = loadPermissionConfig(data)
	loadFromConfToStore(permissionTree)
	if defaultConfig.db != nil {
		defaultConfig.db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket([]byte(BUCKET))
			return err
		})
		// 从数据库加载信息
		permissionToChan()
		// 新的角色信息传入，重加载
		go func() {
			for d := range defaultConfig.ch {
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

	return func(c *gin.Context) {
		endpoint := c.FullPath()
		if endpoint != "" {
			for _, p := range defaultConfig.prefix {
				endpoint = strings.Replace(endpoint, p, "", 1)
			}
			locker.RLock()
			defer locker.RUnlock()
			ctx := context.TODO()
			query, err := r.PrepareForEval(ctx)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusOK, defaultConfig.errResp)
				return
			}
			input := map[string]interface{}{
				"endpoint": c.Request.Method + endpoint,
				"role":     c.GetString("role"),
			}
			rs, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil || !rs[0].Bindings["x"].(bool) {
				c.AbortWithStatusJSON(http.StatusOK, defaultConfig.errResp)
				return
			}
		}

		c.Next()
	}
}

func FindPermission(id string) (RolePermission, error) {
	defaultConfig.locker.RLock()
	role, _ := roleStore[id]
	defaultConfig.locker.RUnlock()
	return role, nil
}

func permissionToChan() {
	permission := map[string]map[string][]string{
		"user_pages":     {},
		"user_platforms": {},
	}
	defaultConfig.locker.RLock()
	for k, v := range roleStore {
		pages := []string{}
		platforms := []string{}
		for _, i := range v.Pages {
			pages = append(pages, i.Endpoint)
		}
		for _, i := range v.Platforms {
			platforms = append(platforms, i.Endpoint)
		}
		permission["user_pages"][k] = pages
		permission["user_platforms"][k] = platforms
	}
	defaultConfig.locker.RUnlock()
	buf, _ := yaml.Marshal(permission)
	defaultConfig.ch <- buf
}

func loopRoleField(node []Node) []RoleField {
	fields := []RoleField{}
	for _, i := range node {
		fields = append(fields, RoleField{Endpoint: i.Endpoint, Name: i.Name})
		if len(i.Children) > 0 {
			fields = append(fields, loopRoleField(i.Children)...)
		}
	}
	return fields
}

func loadPermissionConfig(input []byte) PermissionConfig {
	var permission PermissionConfig
	yaml.Unmarshal(input, &permission)
	return permission
}

// 加载权限
func loadFromConfToStore(conf PermissionConfig) {
	if defaultConfig.db != nil {
		defaultConfig.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(BUCKET))
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var role RolePermission
				yaml.Unmarshal(v, &role)
				defaultConfig.locker.Lock()
				roleStore[string(k)] = RolePermission{
					Pages:     role.Pages,
					Platforms: role.Platforms,
				}
				defaultConfig.locker.Unlock()
			}
			return nil
		})
	}
	for k, v := range conf.Pages {
		defaultConfig.locker.Lock()
		roleStore[k] = RolePermission{
			Pages:     loopRoleField(v),
			Platforms: loopRoleField(conf.Platforms),
		}
		defaultConfig.locker.Unlock()
	}
}
