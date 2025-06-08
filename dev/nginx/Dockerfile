FROM nginx:stable-alpine

# Copy custom nginx.conf (make sure it includes stream config)
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 162/udp

CMD ["nginx", "-g", "daemon off;"]
