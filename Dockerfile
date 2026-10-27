# Runs `toolmoat mcp`, a read-only stdio MCP server, for hosts that start
# MCP servers in a container.

FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:22-slim
LABEL org.opencontainers.image.source="https://github.com/Whitul/toolmoat" \
      org.opencontainers.image.title="toolmoat" \
      org.opencontainers.image.description="Read-only, offline MCP server that scans agent skills, plugins, hooks and MCP servers for security issues" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY package.json README.md LICENSE ./
USER node
ENTRYPOINT ["node", "/app/dist/cli.js", "mcp"]
