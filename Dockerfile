FROM gcr.io/distroless/base-nossl-debian12:latest

WORKDIR /app

COPY ./dns_fwd ./dns_fwd

CMD ["./dns_fwd"]
