# Minimal image for valesne. It does not compile anything: it copies a static
# Linux binary built beforehand for the image's architecture
# (valesne-linux-amd64 or valesne-linux-arm64), so no Go is needed inside
# Docker. Released images are built by .github/workflows/release.yml; by hand:
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o valesne-linux-amd64 .
#   docker build -t valesne .
#
# distroless/static instead of scratch: it has CA certificates (for the HTTPS
# checks), tzdata and a non-root user (uid 65532, overridden in compose).
FROM gcr.io/distroless/static:nonroot

# Set by BuildKit (the default builder) from the target platform.
ARG TARGETARCH
COPY valesne-linux-${TARGETARCH} /valesne

EXPOSE 9090

# The config lives in a mounted folder (not a single file, see
# docker-compose.yml); a default one is written on first start.
ENTRYPOINT ["/valesne"]
CMD ["-config", "/config/config.toml"]

# /healthz only says that the app runs, not whether the checks are OK.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
	CMD ["/valesne", "-healthcheck", "-config", "/config/config.toml"]
