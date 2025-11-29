FROM golang:1.25

WORKDIR /app

RUN apt update && apt install -y sendmail

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/cidr-watcher

CMD ["/app/cidr-watcher"]
