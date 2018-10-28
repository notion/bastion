package asciicast

import (
	"encoding/json"
	"log"
	"strings"
)

// Cast is the base of the asciicast formate
type Cast struct {
	Header *Header
	Frames []*Frame
}

// Header corresponds to the asciicast v2 header protocol
type Header struct {
	Version       int               `json:"version"`
	Width         int               `json:"width"`
	Height        int               `json:"height"`
	Timestamp     int64             `json:"timestamp,omitempty"`
	Duration      float64           `json:"duration,omitempty"`
	IdleTimeLimit float64           `json:"idle_time_limit,omitempty"`
	Command       string            `json:"command,omitempty"`
	Title         string            `json:"title,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Theme         map[string]string `json:"theme,omitempty"`
}

// Frame is the base frame from an asciicast
type Frame struct {
	Time   float64
	Event  string
	Data   string
	Author string
}

// Marshal handles formatting a frame as a JSON line to be read by the asciicast readers
func (frame *Frame) Marshal() ([]byte, error) {
	frameData := make([]interface{}, 4)

	frameData[0] = frame.Time
	frameData[1] = frame.Event
	frameData[2] = frame.Data
	frameData[3] = frame.Author

	return json.Marshal(frameData)
}

// Marshal handles formatting a header as a JSON line to be read by the asciicast readers
func (header *Header) Marshal() ([]byte, error) {
	return json.Marshal(header)
}

// Marshal handles formatting a Cast as a JSON file to be read by the asciicast readers
func (cast *Cast) Marshal() (string, error) {
	var fileFormat []string

	headerJSON, err := cast.Header.Marshal()
	if err != nil {
		log.Println("Error marshaling header")
	}

	fileFormat = append(fileFormat, string(headerJSON))

	for _, frame := range cast.Frames {
		frameJSON, err := frame.Marshal()
		if err != nil {
			log.Println("Error marshaling frame data")
		}

		fileFormat = append(fileFormat, string(frameJSON))
	}

	return strings.Join(fileFormat, "\n"), err
}

// UnmarshalCast handles formatting a Cast JSON into the Cast
func UnmarshalCast(data string) (*Cast, error) {
	var cast Cast

	splitData := strings.Split(data, "\n")

	header, frames := splitData[0], splitData[1:]

	var headerStruct Header

	err := json.Unmarshal([]byte(header), &headerStruct)
	if err != nil {
		log.Println("Error unmarshaling header data")
	}

	cast.Header = &headerStruct

	for _, frame := range frames {
		frameSlice := make([]interface{}, 3)

		err := json.Unmarshal([]byte(frame), &frameSlice)
		if err != nil {
			log.Println("Error unmarshaling header data")
		}

		frameStruct := &Frame{
			Time:   frameSlice[0].(float64),
			Event:  frameSlice[1].(string),
			Data:   frameSlice[2].(string),
			Author: frameSlice[3].(string),
		}

		cast.Frames = append(cast.Frames, frameStruct)
	}

	return &cast, err
}
