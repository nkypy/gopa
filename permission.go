package gopa

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xandercheung/ogs-go"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

const BUCKET = "permission"

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

type RolePermission struct {
	Pages     []string `yaml:"pages" json:"pages"`
	Platforms []string `yaml:"platforms" json:"platforms"`
}

func PermissionRouter(router *gin.RouterGroup) (r gin.IRoutes) {
	rg := router.Group("permissions")
	{
		rg.GET("/:id", findPermission)      // 获取角色权限
		rg.PUT("/:id", updatePermission)    // 更新角色权限
		rg.DELETE("/:id", deletePermission) // 删除角色权限
	}
	return rg
}

func findPermission(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	var permission RolePermission
	exist := false
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		buf := b.Get([]byte(id))
		if len(buf) != 0 {
			exist = true
		}
		return yaml.Unmarshal(buf, &permission)
	})
	pages, ok := permissionTree.Pages[id]
	if exist || !ok {
		c.JSON(http.StatusOK, ogs.RspDataOK("", permission))
		return
	}
	perm := PermissionInfo{Pages: pages, Platforms: permissionTree.Platforms}
	c.JSON(http.StatusOK, ogs.RspDataOK("", perm))
}

func FindPermission(id string) (RolePermission, error) {
	var permission RolePermission
	if db == nil {
		return permission, fmt.Errorf("数据库未初始化")
	}
	exist := false
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		buf := b.Get([]byte(id))
		if len(buf) != 0 {
			exist = true
		}
		return yaml.Unmarshal(buf, &permission)
	})
	pages, ok := permissionTree.Pages[id]
	if exist || !ok {
		return permission, nil
	}
	permission.Pages = loopPermission(pages)
	permission.Platforms = loopPermission(permissionTree.Platforms)
	return permission, nil
}

func updatePermission(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	var permission RolePermission
	if err := c.ShouldBind(&permission); err != nil {
		c.JSON(http.StatusOK, ogs.RspError(10001, "参数不正确"))
		return
	}
	buf, _ := yaml.Marshal(permission)
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		err := b.Put([]byte(id), buf)
		return err
	})
	// 从数据库加载信息
	loadRolePermission()
	c.JSON(http.StatusOK, ogs.RspOK("设置成功"))
}

func deletePermission(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		err := b.Delete([]byte(id))
		return err
	})
	// 从数据库加载信息
	loadRolePermission()
	c.JSON(http.StatusOK, ogs.RspOK("删除成功"))
}

func loadPermissionInfo(input []byte) PermissionConfig {
	var permission PermissionConfig
	yaml.Unmarshal(input, &permission)
	return permission
}

func loopPermission(node []Node) []string {
	perms := []string{}
	for _, i := range node {
		perms = append(perms, i.Endpoint)
		if len(i.Children) > 0 {
			loopPermission(i.Children)
		}
	}
	return perms
}
