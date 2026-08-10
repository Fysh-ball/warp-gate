# Warp Gate.
#
# There is no build stage and there is nothing to compile. Warp Gate has zero
# dependencies and no bundler, so the image is a stock Node base plus the source tree:
# the files this container serves are byte-for-byte the files in the repository. That is
# not a size optimisation, it is the whole trust argument (see THREAT-MODEL.md). A
# multi-stage build that emitted a bundle would break it, because you could no longer
# read the served bytes and the repository and see the same thing.
#
# Measured 2026-08-10, docker 28.3.1: the image is 166 MB, of which 163 MB is the
# node:22-alpine base and 1.22 MB is Warp Gate (server 110 kB, public 1.05 MB, the
# suggestion reader 2.5 kB, LICENSE and README 53 kB). Every one of those figures came
# out of `docker history`, and the build is four COPYs and takes under two seconds.

# Alpine, because nothing here needs glibc: no native modules, no dependencies at all.
#
# The `22` tag floats deliberately, and the floor matters: server/*.js are ES modules
# WITHOUT a package.json declaring "type": "module", so they load only on a Node that
# detects module syntax by itself. That has been on by default since Node 22.7.0. Pinning
# a `22.x` older than that would produce an image that builds cleanly and then dies at
# boot with ERR_REQUIRE_ESM, which is why this is documented rather than left to be
# rediscovered. The image built from this file on 2026-08-10 carried node v22.23.2 and
# started server/index.js with no package.json anywhere in it, which is the check that
# matters: `docker build` succeeds either way, so only a container that actually answers
# /api/health proves the modules loaded.
FROM node:22-alpine

WORKDIR /app

# Copied as root and never chowned, so the uid the server runs as (`node`, below) can
# read its own code and cannot write it. The inverse - COPY --chown=node - would let a
# bug in the process rewrite the very JavaScript whose integrity the whole design rests
# on. `read_only: true` in compose is the belt; this is the braces, and it still applies
# when somebody runs `docker run` without the compose file.
#
# Only what the server actually reads at runtime. tests/ and tools/ are developer tooling
# and DESIGN.md is 92 KB of prose: none of it is served, and shipping it would put files
# in the image that no request can ever reach. LICENSE and README.md are kept because
# this is AGPL software and the image should carry its own licence.
COPY server ./server
COPY public ./public
COPY deploy/read-suggestions.mjs ./deploy/read-suggestions.mjs
COPY LICENSE README.md ./

# uid/gid 1000, which the official node image already creates. Not root, because Warp
# Gate binds 3095 (not privileged), reads /app and appends to at most one file: none of
# that wants uid 0.
#
# Read this together with `cap_drop: ALL` in the compose file, because the two interact in
# a way that cost a release here. Dropping ALL removes CAP_DAC_OVERRIDE, so uid 0 inside
# the container stops being able to override file permissions and becomes an ordinary uid
# that happens to be numbered 0. A host-owned bind mount is then unwritable by
# *container-root*, which is exactly how the suggestion box came to accept every
# submission over HTTP and store none of them. Naming a non-root uid here does not avoid
# that; it makes it predictable, because there is now one number to chown a bind mount to.
USER node

EXPOSE 3095

# Hits the real endpoint rather than checking that a process exists. A `pgrep node` style
# check passes on a process that is wedged in an infinite loop, has stopped accepting
# connections, or is listening on the wrong interface because WG_HTTP_HOST was mistyped:
# every one of those is a gate that does not open, reported as healthy.
#
# The port is read from the environment so that changing WG_HTTP_PORT does not silently
# leave the healthcheck probing a closed port and marking a working container unhealthy.
# `j.ok` is parsed rather than trusting the status code, because /api/health promises
# exactly {"ok":true} and a proxy error page can be a 200.
#
# AbortSignal.timeout is not optional here: a fetch with no timeout against a server that
# accepted the connection and then stopped answering hangs until docker's own --timeout
# kills it, which reports the same "unhealthy" for a hang as for a refusal but takes the
# full 5 s to do it every single interval.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const p=process.env.WG_HTTP_PORT||3095;fetch('http://127.0.0.1:'+p+'/api/health',{signal:AbortSignal.timeout(3000)}).then(r=>r.json()).then(j=>process.exit(j&&j.ok?0:1)).catch(e=>{console.error(e.message);process.exit(1)})"

# Exec form, deliberately. The shell form would make /bin/sh PID 1, and sh does not
# forward SIGTERM to its child: `docker stop` would then wait out its full 10 s grace and
# SIGKILL the server. server/index.js handles SIGTERM by tearing every room down and
# telling the attached clients, so losing that signal turns an orderly shutdown into
# every live gate freezing until its own timeout.
#
# Measured 2026-08-10: /proc/1/cmdline is `node server/index.js`, the log records
# `warp-gate shutting down (SIGTERM)`, and `docker compose stop` returned in 534 ms. The
# timing is the tell - anything near 10,000 ms means the signal never arrived.
CMD ["node", "server/index.js"]
