"""Shared Flask extension instances that need to be importable from route
modules without triggering circular imports with app.main."""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Rate limiter for brute-force / abuse protection on sensitive endpoints
# (login, register). Keyed by client IP by default.
#
# Storage backend: in-memory by default (fine for a single-process deploy /
# local development). For a multi-process or multi-instance production
# deployment, set RATELIMIT_STORAGE_URI in .env to a shared backend such as
# Redis (e.g. redis://localhost:6379), otherwise each process/instance will
# track its own separate counters.
limiter = Limiter(key_func=get_remote_address)
