# Stage 1: Build the frontend
FROM node:latest AS frontend-builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
COPY ./ ./
RUN chmod +x ./node_modules/.bin/* && npm run build

# Stage 2: Build the Go application
FROM golang:latest AS go-builder
WORKDIR /go/src/app
COPY . .
COPY --from=frontend-builder /app/dist ./dist
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o who-dat .

# Stage 3: Setup the final image
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=go-builder /go/src/app/who-dat .

# Set the entrypoint to the Go binary
ENTRYPOINT ["./who-dat"]
