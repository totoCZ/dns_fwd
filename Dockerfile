FROM alpine:latest

WORKDIR /app

COPY ./dns_fwd ./dns_fwd

CMD ["./dns_fwd"]
