FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js ./
COPY lib ./lib
COPY public ./public
COPY scripts ./scripts
COPY db ./db

# data/ (master key, saved firewalls, push log) and backups/ hold secrets and
# are mounted as volumes; create them here so new volumes are owned by `node`.
RUN mkdir -p data backups && chown node:node data backups && chmod 700 data backups

USER node

# Inside the container the app must listen on all interfaces; docker-compose.yml
# publishes the port on 127.0.0.1 only, so it is still not exposed on the network.
ENV BIND=0.0.0.0 PORT=3000
EXPOSE 3000
VOLUME ["/app/data", "/app/backups"]

CMD ["node", "server.js"]
