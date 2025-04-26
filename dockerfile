FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Expose the port your app runs on
EXPOSE 3000

# Use environment variables
CMD ["node", "index.js"]