package asciicast

import (
	"io"
	"time"
	"bytes"
	"log"
	"os"
)

func NewAsciicastReadCloser(r io.ReadCloser, width int, height int) io.ReadCloser {
	return &AsciicastReadCloser{
		ReadCloser: r,
		Time: time.Now(),
		Cast: &Cast{
			Header: &Header{
				Version: 2,
				Width: width,
				Height: height,
				Timestamp: time.Now().Unix(),
			},
		},
	}
}

type AsciicastReadCloser struct {
	io.ReadCloser

	Cast   *Cast
	Time   time.Time
	Buffer bytes.Buffer
}

func (lr *AsciicastReadCloser) Read(p []byte) (n int, err error) {
	n, err = lr.ReadCloser.Read(p)

	now := time.Now()
	duration := now.Sub(lr.Time).Seconds()

	newFrame := &Frame{
		Time: duration,
		Event: "o",
		Data: bytes.NewBuffer(p[0:n]).String(),
	}

	lr.Cast.Frames = append(lr.Cast.Frames, newFrame)

	lr.Time = now

	return n, err
}

func (lr *AsciicastReadCloser) Close() error {
	data, err := lr.Cast.Marshal()
	if err != nil {
		log.Println("Error logging session", err)
	}

	f, err := os.Create("trove_test.cast")
	if err != nil {
		log.Println("Error logging session", err)
	}

	f.WriteString(data)
	f.Close()

	return lr.ReadCloser.Close()
}
