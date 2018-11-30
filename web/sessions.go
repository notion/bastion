package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/notion/bastion/config"
)

func session(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		limit, err := strconv.Atoi(c.Query("length"))
		if err != nil {
			limit = 10
		}

		offset, err := strconv.Atoi(c.Query("start"))
		if err != nil {
			offset = 0
		}

		order := c.Request.URL.Query().Get("order[0][dir]")
		if order != "asc" {
			order = "desc"
		}

		orderCol := c.Request.URL.Query().Get("order[0][column]")

		switch orderCol {
		case "0":
			orderCol = "id"
		case "1":
			orderCol = "host"
		case "2":
			orderCol = "user_id"
		case "3":
			orderCol = "name"
		case "4":
			orderCol = "command"
		}

		search := c.Request.URL.Query().Get("search[value]")

		var sessions []config.Session
		ref := env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
			return db.Select([]string{"id", "email"})
		}).Select([]string{
			"id",
			"user_id",
			"time",
			"name",
			"host",
			"hostname",
			"users",
			"command",
		})

		userIds := make([]uint, 0)

		addWhere := func(db *gorm.DB) *gorm.DB {
			if search == "" {
				return db
			}

			ref := db.Where(
				"name like ? OR host like ? OR hostname like ? OR users like ? OR command like ? OR user_id in (?)",
				search,
				search,
				search,
				search,
				search,
				userIds,
			)

			return ref
		}

		if search != "" {
			search = "%" + search + "%"

			newIds := make([]uint, 0)
			var users []config.User
			env.DB.Table("users").Select("id").Where("email like ?", search).Find(&users)

			for _, u := range users {
				newIds = append(newIds, u.ID)
			}

			userIds = newIds
			ref = addWhere(ref)
		}

		ref.Order(fmt.Sprintf("%s %s", orderCol, order)).Limit(limit).Offset(offset).Find(&sessions)

		arrayData := make([]interface{}, 0)
		for _, v := range sessions {
			innerData := make([]interface{}, 8)

			innerData[0] = v.ID
			innerData[1] = fmt.Sprintf("%s - %s", v.Host, v.Hostname)
			innerData[2] = v.User.Email
			innerData[3] = v.Users
			innerData[4] = v.Name
			innerData[5] = v.Name
			innerData[6] = v.Name
			innerData[7] = v.Command

			arrayData = append(arrayData, innerData)
		}

		draw, err := strconv.Atoi(c.Query("draw"))
		if err != nil {
			draw = 1
		}

		var filteredSessions int
		var allSessions int

		env.DB.Table("sessions").Where(map[string]interface{}{"deleted_at": nil}).Count(&allSessions)
		addWhere(env.DB.Table("sessions").Where(map[string]interface{}{"deleted_at": nil})).Count(&filteredSessions)

		retData := make(map[string]interface{})

		retData["draw"] = draw
		retData["recordsTotal"] = allSessions
		retData["recordsFiltered"] = filteredSessions
		retData["data"] = arrayData

		c.JSON(http.StatusOK, retData)
	}
}

func sessionID(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, _ := c.Params.Get("id")

		if env.Vconfig.GetBool("gce.bucket.enabled") {
			ctx := context.Background()

			reader, err := env.LogsBucket.Object(id).ReadCompressed(true).NewReader(ctx)
			if err != nil {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}

			c.Header("Content-Encoding", "gzip")

			if !env.Vconfig.GetBool("gce.lb.enabled") {
				c.Header("Transfer-Encoding", "gzip")
			}

			c.Writer.WriteHeader(http.StatusOK)
			io.Copy(c.Writer, reader)
		} else if env.Vconfig.GetBool("sessions.enabled") {
			c.Header("Content-Encoding", "gzip")
			c.Header("Transfer-Encoding", "gzip")

			file, err := os.Open(path.Join(env.Vconfig.GetString("sessions.directory"), id))
			if err != nil {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}

			c.Writer.WriteHeader(http.StatusOK)
			io.Copy(c.Writer, file)
		} else {
			c.AbortWithStatus(http.StatusNotFound)
		}
	}
}
