# Use a lightweight base image, like Alpine! So tiny~ 🍃
FROM alpine:latest

# Set working directory nya~
WORKDIR /app

# Copy everything from your current directory into the container
COPY . .

# Set the entrypoint to your lovely binary! Go go dns_fwd~!
CMD ["./dns_fwd"]
