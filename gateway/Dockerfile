
FROM node:18-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
# Healthcheck uses curl; ensure it's installed
RUN apk add --no-cache curl
EXPOSE 3000
CMD ["npm", "start"]
