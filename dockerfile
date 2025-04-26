FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Expose the port your app runs on
EXPOSE 3000

CMD ["node", "index.js"]