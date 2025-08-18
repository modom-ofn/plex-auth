FROM golang:1.22-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod tidy

COPY . .

RUN go build -o plex-auth .

EXPOSE 8080
CMD ["./plex-auth"]