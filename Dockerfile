FROM golang:1.24 AS builder

WORKDIR /app

RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

FROM golang:1.24

WORKDIR /app

COPY --from=builder /app/main .

EXPOSE 8080

CMD ["./main"]
