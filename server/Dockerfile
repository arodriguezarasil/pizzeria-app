FROM node:20-alpine

WORKDIR /app

COPY server/package*.json ./
RUN npm ci --omit=dev

COPY server/src ./src
COPY server/scripts ./scripts
COPY public ./public

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "src/server.js"]
