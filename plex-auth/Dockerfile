FROM golang:1.22-alpine

WORKDIR /app

# Copy source files *before* tidying, so imports can be resolved
COPY . .

# Let Go figure out imports and download deps
RUN go mod tidy
RUN go mod download

# Compile the Go app
RUN go build -o plex-auth .

EXPOSE 8080
CMD ["./plex-auth"]