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
	r.Use(gopa.Opa("/v1", input, data))
	r.GET("/v1/ping/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.POST("/v1/ping/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
