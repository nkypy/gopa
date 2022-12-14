package gopa

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xandercheung/ogs-go"
	bolt "go.etcd.io/bbolt"
)

type UpdatePermissonReq struct {
	Endpoints []string `yaml:"endpoints" json:"endpoints"`
}

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
	platforms := []Node{
		{Endpoint: "web_manage", Name: "Web后台"},
	}
	if id == "tenant_admin" {
		platforms = permissionTree.Platforms
	}
	c.JSON(http.StatusOK, ogs.RspDataOK("", PermissionInfo{Pages: pages, Platforms: platforms}))
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
	var req UpdatePermissonReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusOK, ogs.RspError(10001, "参数不正确"))
		return
	}
	UpdatePermissonPages(id, req.Endpoints)
	c.JSON(http.StatusOK, ogs.RspOK("设置成功"))
}

func updatePermissionPlatforms(c *gin.Context) {
	if defaultConfig.db == nil {
		c.JSON(http.StatusOK, ogs.RspError(10002, "数据库未初始化"))
		return
	}
	id := c.Param("id")
	var req UpdatePermissonReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusOK, ogs.RspError(10001, "参数不正确"))
		return
	}
	UpdatePermissionPlatforms(id, req.Endpoints)
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
