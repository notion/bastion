FROM golang:latest
LABEL maintainer="Antonio Mika <antonio@***REMOVED***>"

WORKDIR /usr/local/go/src/github.com/notion/trove_ssh_bastion
COPY . .
COPY config.example.yml config.yml

RUN go install -v ./...

CMD ["trove_ssh_bastion"]