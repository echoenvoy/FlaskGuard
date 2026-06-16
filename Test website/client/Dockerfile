# Use official Node.js 14 as base image
FROM node:16.20.2-buster-slim as build

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the client code
COPY . .

RUN mv .env.example .env

# Build the client for production
RUN npm run build


FROM nginx:alpine
RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs \
    && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/certs/client.key \
        -out /etc/nginx/certs/client.crt \
        -subj "/CN=client" \
        -addext "subjectAltName=DNS:client,DNS:localhost"

# Copy the build artifacts from the build stage
COPY --from=build /usr/src/app/dist /usr/share/nginx/html
# NGINX default configuration file
COPY nginx.conf /etc/nginx/nginx.conf

# Expose HTTP and internal HTTPS ports
EXPOSE 8080
EXPOSE 8443

CMD ["nginx", "-g", "daemon off;"]
