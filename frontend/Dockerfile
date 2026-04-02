# Build stage
FROM node:20-alpine as build

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
# Using npm install to ensure package-lock is updated with new dependencies
RUN npm install

# Copy source code
COPY . .

# Set environment variables for build
# We set this to /api so that the production build points to the proxy
ENV VITE_API_URL=/api
ENV VITE_SOCKET_URL=/

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built assets from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
