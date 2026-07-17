FROM golang:1.26-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -o /out/cheesewaf ./cmd/cheesewaf

FROM node:24-bookworm AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM debian:bookworm-slim
RUN useradd --system --home /var/lib/cheesewaf --shell /usr/sbin/nologin cheesewaf \
  && mkdir -p /etc/cheesewaf /var/lib/cheesewaf /var/log/cheesewaf \
  && chown -R cheesewaf:cheesewaf /var/lib/cheesewaf /var/log/cheesewaf
COPY --from=backend /out/cheesewaf /usr/local/bin/cheesewaf
COPY --from=web /src/web/dist /usr/share/cheesewaf/web
COPY configs/cheesewaf.yaml /etc/cheesewaf/cheesewaf.yaml
USER cheesewaf
EXPOSE 8080 9443
ENTRYPOINT ["/usr/local/bin/cheesewaf"]
CMD ["serve", "--config", "/etc/cheesewaf/cheesewaf.yaml"]
