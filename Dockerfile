FROM golang:1.11.3-stretch
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /usr/local/go/src/github.com/notion/bastion
COPY . .
COPY config.example.yml config.yml

RUN go install

CMD ["bastion"]