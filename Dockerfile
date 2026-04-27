# syntax=docker/dockerfile:1.7
FROM node:24-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY parse.js ./
COPY lib ./lib

WORKDIR /src

ENTRYPOINT ["node", "/app/parse.js"]
CMD ["--help"]
