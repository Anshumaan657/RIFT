FROM node:22.19.0-alpine AS dependencies

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM dependencies AS development
COPY . .
RUN chown -R node:node /app
USER node
EXPOSE 5173
CMD ["npm", "run", "dev"]

FROM dependencies AS build
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.4-alpine3.24@sha256:442753882674b49ae2c1de83ed67896131c0777f56df5005e356e62bc3f7e7ce AS production
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
