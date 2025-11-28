FROM golang:1.24

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install PHP (used for post-deployment commands)
RUN apt update && apt install -y php-cli php-intl php-mbstring php-xml php-zip

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/artifact-deployer

EXPOSE 3042

CMD ["/app/artifact-deployer"]
