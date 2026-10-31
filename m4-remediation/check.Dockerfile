# Live M4 checks, run inside the private lab network (compose profile `check`). Build context: repository root.
FROM node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d
WORKDIR /lab
COPY m1-lab/shared/session.mjs m1-lab/shared/
COPY m4-remediation/tests/targets.test.mjs m4-remediation/tests/
USER node
CMD ["node", "--test", "m4-remediation/tests/targets.test.mjs"]
