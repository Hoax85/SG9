# SG9 – Datei-Server (FTP, SFTP, WebDAV, Browser, Freigabe-Links)
# Bauen:   docker build -t sg9 .
# Starten: siehe docker-compose.yml oder deploy/unraid/sg9.xml

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/sg9 . \
 && mkdir -p /out/data /out/shares

FROM scratch
# Zertifikate für Let's Encrypt, Benachrichtigungen und Update-Prüfung
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/sg9 /sg9
# Leere Ordner als Einhängepunkte (Unraid: nobody:users = 99:100)
COPY --from=build --chown=99:100 /out/data /data
COPY --from=build --chown=99:100 /out/shares /shares

ENV SG9_DATA=/data \
    SG9_ADMIN_LISTEN=:8021 \
    TZ=Europe/Zurich

# Verwaltung, FTP, SFTP, Web/WebDAV/Links, FTP-Passivbereich
EXPOSE 8021 2121 2222 8080 50000-50100

VOLUME ["/data"]
USER 99:100
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/sg9", "-healthcheck"]
ENTRYPOINT ["/sg9"]
