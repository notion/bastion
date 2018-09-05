package config

import (
	"github.com/fatih/color"
	"log"
)

type ColorLog struct {
	Color *color.Color
}

func NewColorLog(color *color.Color) *ColorLog {
	return &ColorLog{Color: color}
}

func (c *ColorLog) Printf(format string, a ...interface{}) {
	c.Color.Set()
	defer color.Unset()

	log.Printf(format, a)

	return
}

func (c *ColorLog) Println(a ...interface{}) {
	c.Color.Set()
	defer color.Unset()

	log.Println(a)

	return
}

func (c *ColorLog) Fatal(a ...interface{}) {
	c.Color.Set()
	defer color.Unset()

	log.Fatal(a)

	return
}