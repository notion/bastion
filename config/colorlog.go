package config

import (
	"log"

	"github.com/fatih/color"
)

// ColorLog is a wrapper around a certain color for logging
type ColorLog struct {
	Color *color.Color
}

// NewColorLog creates a new color for formatted logging
func NewColorLog(color *color.Color) *ColorLog {
	return &ColorLog{Color: color}
}

// Printf is a passthru with colors
func (c *ColorLog) Printf(format string, a ...interface{}) {
	c.Color.Set()
	defer color.Unset()

	log.Printf(format, a...)

	return
}

// Println is a passthru with colors
func (c *ColorLog) Println(a ...interface{}) {
	c.Color.Set()
	defer color.Unset()

	log.Println(a...)

	return
}

// Fatal is a passthru with colors
func (c *ColorLog) Fatal(a ...interface{}) {
	c.Color.Set()
	defer color.Unset()

	log.Fatal(a...)

	return
}
