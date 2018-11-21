package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"golang.org/x/oauth2"
)

func getUserData(conf oauth2.Config, token *oauth2.Token) (map[string]interface{}, error) {
	client := conf.Client(context.TODO(), token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("issue instantiating oauth2 client: %v", err)
	}
	defer resp.Body.Close()

	userData := make(map[string]interface{})

	data, _ := ioutil.ReadAll(resp.Body)

	err = json.Unmarshal(data, &userData)
	if err != nil {
		return nil, fmt.Errorf("issue unmarshalling data from google: %v", err)
	}

	return userData, nil
}

func getDataTablesParams(c *gin.Context) (int, int, string, string, string) {
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
	search := c.Request.URL.Query().Get("search[value]")

	return limit, offset, order, orderCol, search
}

func getLiveSessionParams(c *gin.Context) (string, string, string) {
	authcode := c.Query("authcode")
	pathKey, ok := c.Params.Get("id")
	if !ok {
		c.AbortWithError(http.StatusInternalServerError, errors.New("can't find id"))
		return "", "", ""
	}
	sidKey, ok := c.Params.Get("sid")
	if !ok {
		sidKey = ""
	}

	return authcode, pathKey, sidKey
}
