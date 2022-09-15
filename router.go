package gopa

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xandercheung/ogs-go"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

func PermissionRouter(router *gin.RouterGroup) (r gin.IRoutes) {
	rg := router.Group("permissions")
	{
		rg.GET("/menus/:id", listPermission)
		rg.GET("/:id", findPermission)                      // 获取角色权限
		rg.PUT("/:id/pages", updatePermissionPages)         // 更新角色权限
		rg.PUT("/:id/platforms", updatePermissionPlatforms) // 更新角色权限
		rg.DELETE("/:id", deletePermission)                 // 删除角色权限
	}
	return rg
}

func listPermission(c *gin.Context) {
	id := c.Param("id")
	pages, ok := permissionTree.Pages[id]
	if !ok {
		c.JSON(http.StatusOK, defaultConfig.errResp)
		return
	}
	c.JSON(http.StatusOK, ogs.RspDataOK("", PermissionInfo{Pages: pages, Platforms: permissionTree.Platforms}))
}

func findPermission(c *gin.Context) {
	id := c.Param("id")
	perm, err := FindPermission(id)
	if err != nil {
		c.JSON(http.StatusOK, defaultConfig.errResp)
		return
	}
	c.JSON(http.StatusOK, ogs.RspDataOK("", perm))
}

func updatePermissionPages(c *gin.Context) {
	if defaultConfig.db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	var permission RolePermission
	if err := c.ShouldBind(&permission); err != nil {
		c.JSON(http.StatusOK, ogs.RspError(10001, "参数不正确"))
		return
	}
	old, _ := roleStore[id]
	permission.Platforms = old.Platforms
	buf, _ := yaml.Marshal(permission)
	defaultConfig.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		err := b.Put([]byte(id), buf)
		return err
	})
	defaultConfig.locker.Lock()
	roleStore[id] = permission
	defaultConfig.locker.Unlock()
	// 从数据库加载信息
	permissionToChan()
	c.JSON(http.StatusOK, ogs.RspOK("设置成功"))
}

func updatePermissionPlatforms(c *gin.Context) {
	if defaultConfig.db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	var permission RolePermission
	if err := c.ShouldBind(&permission); err != nil {
		c.JSON(http.StatusOK, ogs.RspError(10001, "参数不正确"))
		return
	}
	old, _ := roleStore[id]
	permission.Pages = old.Pages
	buf, _ := yaml.Marshal(permission)
	defaultConfig.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		err := b.Put([]byte(id), buf)
		return err
	})
	defaultConfig.locker.Lock()
	roleStore[id] = permission
	defaultConfig.locker.Unlock()
	// 从数据库加载信息
	permissionToChan()
	c.JSON(http.StatusOK, ogs.RspOK("设置成功"))
}

func deletePermission(c *gin.Context) {
	if defaultConfig.db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	defaultConfig.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BUCKET))
		err := b.Delete([]byte(id))
		return err
	})
	defaultConfig.locker.Lock()
	delete(roleStore, id)
	defaultConfig.locker.Unlock()
	// 从数据库加载信息
	permissionToChan()
	c.JSON(http.StatusOK, ogs.RspOK("删除成功"))
}
