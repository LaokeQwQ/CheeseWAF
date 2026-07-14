ARG GO_IMAGE=golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113
ARG NODE_IMAGE=node:24.18.0-bookworm@sha256:392e1e23f34da768d8d1f4e502b64f200d3be3465934d4b7930f57d7e2fc1989
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

FROM ${GO_IMAGE} AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG CHANNEL=container
RUN CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w \
  -X github.com/LaokeQwQ/CheeseWAF/internal/version.Version=${VERSION} \
  -X github.com/LaokeQwQ/CheeseWAF/internal/version.Commit=${COMMIT} \
  -X github.com/LaokeQwQ/CheeseWAF/internal/version.BuildTime=${BUILD_TIME} \
  -X github.com/LaokeQwQ/CheeseWAF/internal/version.Channel=${CHANNEL}" \
  -o /out/cheesewaf ./cmd/cheesewaf

FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/index.html web/tsconfig.json web/tsconfig.app.json web/tsconfig.node.json web/vite.config.ts web/vite.proxy.ts ./
COPY web/public ./public
COPY web/scripts ./scripts
COPY web/src ./src
RUN npm run build

FROM ${RUNTIME_IMAGE}
RUN useradd --system --home /var/lib/cheesewaf --shell /usr/sbin/nologin cheesewaf \
  && mkdir -p /var/lib/cheesewaf /var/log/cheesewaf /usr/share/cheesewaf/config /usr/share/cheesewaf/web \
  && chown -R cheesewaf:cheesewaf /var/lib/cheesewaf /var/log/cheesewaf
COPY --from=backend /out/cheesewaf /usr/local/bin/cheesewaf
COPY --from=web /src/web/dist/ /usr/share/cheesewaf/web/
COPY configs/cheesewaf.yaml /usr/share/cheesewaf/config/cheesewaf.yaml
COPY deploy/docker/entrypoint.sh /usr/local/bin/cheesewaf-entrypoint
RUN sed -i \
  -e 's#listen: "127.0.0.1:8080"#listen: "0.0.0.0:8080"#' \
  -e 's#admin_listen: "127.0.0.1:9443"#admin_listen: "0.0.0.0:9443"#' \
  -e 's#admin_public: false#admin_public: true#' \
  -e '/admin_tls:/,/read_timeout:/ s#enabled: false#enabled: true#' \
  -e 's#cert_file: "./data/certs/admin.crt"#cert_file: "/var/lib/cheesewaf/certs/admin.crt"#' \
  -e 's#key_file: "./data/certs/admin.key"#key_file: "/var/lib/cheesewaf/certs/admin.key"#' \
  -e 's#data_dir: "./data"#data_dir: "/var/lib/cheesewaf"#' \
  -e 's#runtime_dir: "./data/run"#runtime_dir: "/var/lib/cheesewaf/run"#' \
  -e 's#path: "./data/cheesewaf.db"#path: "/var/lib/cheesewaf/cheesewaf.db"#' \
  -e 's#path: "./logs/access.log"#path: "/var/log/cheesewaf/access.log"#' \
  -e 's#target: "./logs"#target: "/var/log/cheesewaf"#' \
  -e 's#path: "./logs/audit.log"#path: "/var/log/cheesewaf/audit.log"#' \
  /usr/share/cheesewaf/config/cheesewaf.yaml \
  && chmod 0555 /usr/local/bin/cheesewaf-entrypoint
ENV CHEESEWAF_WEB_DIR=/usr/share/cheesewaf/web
ENV CHEESEWAF_CONFIG=/var/lib/cheesewaf/config/cheesewaf.yaml
WORKDIR /var/lib/cheesewaf
USER cheesewaf
EXPOSE 8080 9443
ENTRYPOINT ["/usr/local/bin/cheesewaf-entrypoint"]
CMD ["serve"]
