# Minimal base image (Alpine) to reduce attack surface
FROM node:22-alpine
WORKDIR /app
# Create an unprivileged user
RUN adduser -D -u 1001 appuser
COPY app.js .
# Run as non-root
USER appuser
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node", "app.js"]
