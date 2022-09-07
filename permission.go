package gopa

import (
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
		rg.GET("", listPermission)          // 所有权限
		rg.GET("/:id", findPermission)      // 获取角色权限
		rg.PUT("/:id", updatePermission)    // 更新角色权限
		rg.DELETE("/:id", deletePermission) // 删除角色权限
	}
	return rg
}

func listPermission(c *gin.Context) {
	c.JSON(http.StatusOK, ogs.RspDataOK("", permissionTree))
}

func findPermission(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	var permission RolePermission
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		buf := b.Get([]byte(id))
		return yaml.Unmarshal(buf, &permission)
	})
	c.JSON(http.StatusOK, ogs.RspDataOK("", permission))
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
	c.JSON(http.StatusOK, ogs.RspOK("OK"))
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
	c.JSON(http.StatusOK, ogs.RspOK("OK"))
}

func loadPermissionInfo(input []byte) PermissionInfo {
	var permission PermissionInfo
	yaml.Unmarshal(input, &permission)
	return permission
}
