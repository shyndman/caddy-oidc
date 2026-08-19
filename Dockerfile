ARG CADDY_VERSION=latest
FROM caddy:${CADDY_VERSION}-builder-alpine AS builder

LABEL maintainer="@relvacode"
LABEL description="Caddy with github.com/shyndman/caddy-oidc plugin"

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 xcaddy build \
    --output /usr/bin/caddy \
    --with github.com/shyndman/caddy-oidc=.

FROM caddy:${CADDY_VERSION}-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

