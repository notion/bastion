package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
)

func authRule(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})
		var authRules []config.AuthRules

		data := make([][]interface{}, 0)
		env.DB.Find(&authRules)

		for _, v := range authRules {
			data = append(data, []interface{}{v.ID, v.Name, v.AuthorizedHosts, v.UnixUser, v.ID, v.ID})
		}

		retData["data"] = data

		c.JSON(http.StatusOK, retData)
	}
}

func createAuthRule(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})
		var authRule config.AuthRules

		authRule.Name = c.PostForm("name")
		authRule.AuthorizedHosts = c.PostForm("authorizedhosts")
		authRule.UnixUser = c.PostForm("unixuser")

		env.DB.Save(&authRule)

		retData["data"] = authRule

		c.JSON(http.StatusOK, retData)
	}
}

func deleteAuthRule(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, _ := c.Params.Get("id")
		var authRule config.AuthRules

		env.DB.Find(&authRule, id)
		env.DB.Delete(&authRule)

		c.Redirect(http.StatusFound, "/authrules")
	}
}

func updateAuthRule(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, _ := c.Params.Get("id")

		if id == "create" {
			createAuthRule(env)(c)
			return
		}

		retData := make(map[string]interface{})
		var authRule config.AuthRules

		env.DB.Find(&authRule, id)

		authRule.Name = c.PostForm("name")
		authRule.AuthorizedHosts = c.PostForm("authorizedhosts")
		authRule.UnixUser = c.PostForm("unixuser")

		env.DB.Save(&authRule)

		retData["data"] = authRule

		c.JSON(http.StatusOK, retData)
	}
}
