# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tunnel .

FROM gcr.io/distroless/static-debian12:latest
COPY --from=build /out/tunnel /tunnel
EXPOSE 80 5223
ENTRYPOINT ["/tunnel"]
