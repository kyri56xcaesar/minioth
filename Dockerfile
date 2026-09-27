# ---- build ----
FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 works cleanly here specifically because the SQLite driver
# is modernc.org/sqlite (pure Go) rather than a CGO one — a static,
# scratch/alpine-friendly binary with no C toolchain in the final image.
RUN CGO_ENABLED=0 go build -trimpath -o /out/minioth ./cmd/minioth

# ---- runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates

COPY --from=build /out/minioth /app/minioth

# Not baked in: minioth.env has to be supplied at runtime (bind-mount or
# --env-file), since the image must never ship real secrets. See
# minioth.env.template / README Configuration for what it needs.
#
# -data-dir and -conf below are both absolute, so where they land doesn't
# depend on WORKDIR (there isn't one set here) — -data-dir=/data covers
# both backends (SQLite db, or the plain backend's flat files under
# /data/plain, see internal/store/plain.go's SetPlainDataDir), all under
# the one declared volume.
VOLUME ["/data"]
EXPOSE 9090

ENTRYPOINT ["/app/minioth"]
CMD ["-backend=db", "-data-dir=/data", "-conf=/app/minioth.env"]
