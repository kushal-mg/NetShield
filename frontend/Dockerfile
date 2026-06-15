FROM node:20-alpine

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Expose Vite dev port
EXPOSE 5173

# Start Vite server binding to all host addresses
CMD ["npm", "run", "dev", "--", "--host"]
