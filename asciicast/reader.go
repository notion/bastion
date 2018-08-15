package asciicast

import (
	"io"
	"time"
	"bytes"
	"log"
	"github.com/notion/trove_ssh_bastion/config"
)

func NewAsciicastReadCloser(r io.ReadCloser, width int, height int, env *config.Env) io.ReadCloser {
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
		Env: env,
	}
}

type AsciicastReadCloser struct {
	io.ReadCloser

	Cast   *Cast
	Time   time.Time
	Buffer bytes.Buffer
	Env    *config.Env
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

	return n, err
}

func (lr *AsciicastReadCloser) Close() error {
	data, err := lr.Cast.Marshal()
	if err != nil {
		log.Println("Error logging session", err)
	}

	//f, err := os.Create("trove_test.cast")
	//if err != nil {
	//	log.Println("Error logging session", err)
	//}
	//
	//f.WriteString(data)
	//f.Close()

	session := &config.Session{
		Time: lr.Time,
		Cast: data,
	}

	lr.Env.DB.Save(session)

	return lr.ReadCloser.Close()
}
