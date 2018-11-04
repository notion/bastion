FROM golang:latest
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /usr/local/go/src/github.com/notion/trove_ssh_bastion
COPY . .
COPY config.example.yml config.yml

RUN go install -v ./...

CMD ["trove_ssh_bastion"]