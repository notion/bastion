package asciicast

import (
	"encoding/json"
	"log"
	"strings"
)

type Cast struct {
	Header *Header
	Frames []*Frame
}

type Header struct {
	Version int `json:"version"`
	Width int `json:"width"`
	Height int `json:"height"`
	Timestamp int64 `json:"timestamp,omitempty"`
	Duration float64 `json:"duration,omitempty"`
	IdleTimeLimit float64 `json:"idle_time_limit,omitempty"`
	Command string `json:"command,omitempty"`
	Title string `json:"title,omitempty"`
	Env map[string]string `json:"env,omitempty"`
	Theme map[string]string `json:"theme,omitempty"`
}

type Frame struct {
	Time float64
	Event string
	Data string
}

func (cast *Cast) Marshal() (string, error) {
	var fileFormat []string

	headerJson, err := json.Marshal(cast.Header)
	if err != nil {
		log.Println("Error marshaling header")
	}

	fileFormat = append(fileFormat, string(headerJson))

	for _, frame := range cast.Frames {
		frameData := make([]interface{}, 3)

		frameData[0] = frame.Time
		frameData[1] = frame.Event
		frameData[2] = frame.Data

		frameJson, err := json.Marshal(frameData)
		if err != nil {
			log.Println("Error marshaling frame data")
		}

		fileFormat = append(fileFormat, string(frameJson))
	}

	return strings.Join(fileFormat, "\n"), err
}

func Unmarshal(data string) (*Cast, error) {
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
			Time: frameSlice[0].(float64),
			Event: frameSlice[1].(string),
			Data: frameSlice[2].(string),
		}

		cast.Frames = append(cast.Frames, frameStruct)
	}

	return &cast, err
}