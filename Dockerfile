FROM scratch

WORKDIR /app

COPY ./dns_fwd ./dns_fwd

CMD ["./dns_fwd"]
