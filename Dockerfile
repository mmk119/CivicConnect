# Use Node.js 18 base image
FROM node:18

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json first
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the whole project (frontend, backend, etc.)
COPY . .

# Set the working directory to backend for starting the server
WORKDIR /app/backend

# Ensure logs folder exists inside the container
RUN mkdir -p /app/backend/logs

# Expose port 3000
EXPOSE 3000

# Start the backend server
CMD ["node", "server.js"]
