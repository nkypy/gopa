package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nkypy/gopa"

	_ "embed"
)

//go:embed policy.rego
var input []byte

//go:embed policy.yaml
var data []byte

// 角色权限示例
var role = `
user_roles:
  super_admin:
    - menu:home
  admin:
    - menu:home

user_platforms:
  super_admin:
    - web_manage
  admin:
    - web_manage
`

func main() {
	ch := make(chan []byte, 1)
	ch <- []byte(role)
	r := gin.Default()
	r.Use(Query2Ctx())
	r.Use(gopa.Opa(input, data))
	r.GET("/api/v1/web/orders/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": c.Param("id"),
		})
	})
	r.GET("/api/v1/web/users/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

// 测试用，把 Query 里的参数 写入 Context
func Query2Ctx() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("role", c.Query("role"))
		c.Next()
	}
}
