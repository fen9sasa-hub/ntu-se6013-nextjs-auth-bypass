FROM node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d
WORKDIR /lab
COPY --chown=node:node boundary.mjs server.mjs ./header-filter/
USER node
EXPOSE 3000
CMD ["node", "header-filter/server.mjs"]
