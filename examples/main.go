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

func main() {
	r := gin.Default()
	r.Use(Query2Ctx())
	r.Use(gopa.Opa(input, data, "/v1"))
	r.GET("/v1/ping/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": c.Param("id"),
		})
	})
	r.POST("/v1/ping/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

// 测试用，把 Query 里的 role 写入 Context
func Query2Ctx() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.Query("role")
		c.Set("role", role)
		c.Next()
	}
}
