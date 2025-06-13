FROM gcr.io/distroless/static-debian12:latest

WORKDIR /app

COPY ./dns_fwd ./dns_fwd

CMD ["./dns_fwd"]
