# Step 1: Build binary
FROM golang:1.22 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Step 2: Run binary in light image
FROM alpine:3

WORKDIR /app

COPY --from=builder /app/main .

CMD ["./main"]

