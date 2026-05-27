FROM node:20-alpine

WORKDIR /app

COPY frontend/sentinelguard-ui/package*.json ./
RUN npm ci

COPY frontend/sentinelguard-ui ./

EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
