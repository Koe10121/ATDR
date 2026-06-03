ARG NODE_IMAGE=node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e
ARG NGINX_IMAGE=nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

FROM ${NODE_IMAGE} AS build

WORKDIR /frontend

ENV NODE_OPTIONS=--openssl-legacy-provider
ENV PYTHON=/usr/bin/python3
ENV CHROMEDRIVER_SKIP_DOWNLOAD=true

RUN apk add --no-cache python3 make g++ \
    && ln -sf python3 /usr/bin/python

COPY package*.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY . .

ARG VUE_APP_API_BASE_URL=http://127.0.0.1:8097
ARG VUE_APP_SOCKET_URL=
ARG VUE_APP_CLIENTID=
ARG VUE_APP_SCOPE=profile email
ARG VUE_APP_PROMPT=select_account
ARG VUE_APP_AUTH_SYSTEM=newSystem
ARG VUE_APP_PROJECT_APP_ID=newSystem
ARG VUE_APP_PROJECT_PERMISSION_ROOT_PATH=/new-system/security/permission
ENV VUE_APP_API_BASE_URL=${VUE_APP_API_BASE_URL}
ENV VUE_APP_SOCKET_URL=${VUE_APP_SOCKET_URL}
ENV VUE_APP_CLIENTID=${VUE_APP_CLIENTID}
ENV VUE_APP_SCOPE=${VUE_APP_SCOPE}
ENV VUE_APP_PROMPT=${VUE_APP_PROMPT}
ENV VUE_APP_AUTH_SYSTEM=${VUE_APP_AUTH_SYSTEM}
ENV VUE_APP_PROJECT_APP_ID=${VUE_APP_PROJECT_APP_ID}
ENV VUE_APP_PROJECT_PERMISSION_ROOT_PATH=${VUE_APP_PROJECT_PERMISSION_ROOT_PATH}

RUN npm run build

FROM ${NODE_IMAGE} AS local-runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080

COPY --from=build --chown=node:node /frontend/dist ./dist
COPY --chown=node:node docker-server.js ./docker-server.js

USER node

EXPOSE 8080

CMD ["node", "docker-server.js"]

FROM ${NGINX_IMAGE} AS server-runner

COPY nginx.server.conf /etc/nginx/conf.d/default.conf
COPY --from=build /frontend/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
