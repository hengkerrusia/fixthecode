FROM node:alpine
WORKDIR /srv
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
RUN mkdir -p /data/uploads
EXPOSE 8080
CMD ["node", "server.js"]
