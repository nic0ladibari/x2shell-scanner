# syntax=docker/dockerfile:1
# Multi-stage: build on the glibc rust:slim image, ship on distroless.
FROM rust:1.88-slim AS build
WORKDIR /src
COPY . .
# The git SHA is injected here (the .git dir is not in the build context); if
# unset, build.rs finds no git and the metadata simply omits it.
ARG X2S_GIT_SHA
ENV X2S_GIT_SHA=${X2S_GIT_SHA}
RUN cargo build --release --locked

# distroless/cc carries glibc + libgcc for the dynamically-linked binary, and
# :nonroot drops root — a scanner has no reason to run privileged.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/x2shell-scanner /usr/local/bin/x2shell-scanner
ENTRYPOINT ["/usr/local/bin/x2shell-scanner"]
