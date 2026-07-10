#!/usr/bin/env bash
#
# Creates the application's PostgreSQL role and databases for local development.
#
# Run once:   ./scripts/setup_db.sh
# Re-runnable: yes. Every statement is guarded, so running it twice is safe.
#
# ---------------------------------------------------------------------------
# Why a dedicated role instead of connecting as your macOS superuser
#
# Your Homebrew Postgres authenticates local connections with `trust`, meaning
# no password is checked, and your `umairhashmi` role is a SUPERUSER. Building
# the app against that is comfortable and wrong, for two reasons:
#
#   1. Least privilege. A SQL injection in a superuser session can DROP TABLE,
#      read pg_shadow, or COPY FROM PROGRAM (shell execution). The same
#      injection as a role that owns only its own tables is contained.
#
#   2. Dev/prod parity. If development never sends a password, the password
#      code path is never exercised until production, where it is the only
#      thing standing between the internet and your data.
#
# This script therefore creates `backend_app`: a normal, password-protected
# role that owns exactly two databases and nothing else.
# ---------------------------------------------------------------------------

set -euo pipefail
# -e  exit on any command failure
# -u  treat unset variables as an error (catches typos in $VAR)
# -o pipefail  a pipeline fails if ANY stage fails, not just the last

# Homebrew's postgresql@15 is keg-only, so its binaries may not be on PATH
# for non-interactive shells (CI, cron, editors). Add them defensively.
if [ -d "/opt/homebrew/opt/postgresql@15/bin" ]; then
    export PATH="/opt/homebrew/opt/postgresql@15/bin:$PATH"
fi

APP_USER="${APP_DB_USER:-backend_app}"
APP_PASSWORD="${APP_DB_PASSWORD:-}"
DEV_DB="${APP_DB_NAME:-backend_dev}"
TEST_DB="${APP_TEST_DB_NAME:-backend_test}"

# The bootstrapping connection. This must be a superuser, because only a
# superuser may CREATE ROLE. It is used for this script and never by the app.
ADMIN_DB="${ADMIN_DB:-postgres}"

if [ -z "$APP_PASSWORD" ]; then
    echo "error: APP_DB_PASSWORD is not set." >&2
    echo "       Read it from your .env file, e.g.:" >&2
    echo "         export APP_DB_PASSWORD=\"\$(grep '^DB_PASSWORD=' .env | cut -d= -f2-)\"" >&2
    exit 1
fi

echo "==> Checking that PostgreSQL is running"
if ! pg_isready --quiet; then
    echo "error: PostgreSQL is not accepting connections." >&2
    echo "       Start it with: brew services start postgresql@15" >&2
    exit 1
fi

echo "==> Creating role '$APP_USER' (if absent) and setting its password"
#
# CREATE ROLE has no IF NOT EXISTS clause, so we generate the statement only
# when the role is missing, then execute it with psql's \gexec.
#
# Two safety notes:
#
#   * A DO $$ ... $$ block would NOT work here. psql refuses to substitute
#     :'variables' inside dollar-quoted strings, so the server would receive
#     the literal text :'app_user'. This is a classic trap.
#
#   * format() with %I (identifier) and %L (literal) performs correct SQL
#     quoting. Interpolating the password into SQL with shell string
#     concatenation would be an injection waiting for a password containing
#     a single quote.
#
#   * stdout is discarded. \gexec ECHOES the statement it is about to run,
#     which would print the password to the terminal, to shell history, and
#     to any CI log. stderr is left alone so real errors still surface, and
#     ON_ERROR_STOP=1 guarantees a non-zero exit on failure.
psql -d "$ADMIN_DB" -v ON_ERROR_STOP=1 --quiet \
     -v app_user="$APP_USER" -v app_password="$APP_PASSWORD" <<'SQL' >/dev/null
SELECT format('CREATE ROLE %I LOGIN', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user');
\gexec

-- Always (re)set the password so re-running this script re-syncs it with .env.
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password');
\gexec
SQL
echo "    role ready"

# Deliberately NOT granted: SUPERUSER, CREATEROLE, CREATEDB, BYPASSRLS.
# The app never needs them. Migrations run as the database OWNER, which this
# role is, and that is sufficient to create and drop its own tables.

for db in "$DEV_DB" "$TEST_DB"; do
    echo "==> Creating database '$db' owned by '$APP_USER' (if absent)"
    # CREATE DATABASE cannot run inside a transaction or a DO block, so we
    # check first and only then issue it.
    exists=$(psql -d "$ADMIN_DB" -tAc "SELECT 1 FROM pg_database WHERE datname = '$db'")
    if [ "$exists" = "1" ]; then
        echo "    already exists"
    else
        createdb --owner="$APP_USER" "$db"
        echo "    created"
    fi

    # Revoke the implicit CONNECT grant that PUBLIC receives on every new
    # database. Without this, any role on the server can connect to it.
    psql -d "$ADMIN_DB" -v ON_ERROR_STOP=1 -q \
        -c "REVOKE ALL ON DATABASE \"$db\" FROM PUBLIC;" \
        -c "GRANT ALL PRIVILEGES ON DATABASE \"$db\" TO \"$APP_USER\";"

    # In Postgres 15+, PUBLIC no longer has CREATE on the public schema, but
    # the app role must own it in order to create tables there.
    psql -d "$db" -v ON_ERROR_STOP=1 -q \
        -c "ALTER SCHEMA public OWNER TO \"$APP_USER\";"
done

echo
echo "==> Verifying '$APP_USER' can reach '$DEV_DB' over TCP"
#
# Note carefully what this does and does not prove.
#
# If pg_hba.conf still authenticates host connections with `trust` (the
# Homebrew default), the server never asks for a password and this check
# succeeds even with a wrong one. It proves reachability and privileges, NOT
# authentication.
#
# Run `make db-check-auth` to see which of the two you actually have.
if PGPASSWORD="$APP_PASSWORD" psql -h localhost -U "$APP_USER" -d "$DEV_DB" \
        -tAc "SELECT 'connected as ' || current_user" 2>/dev/null; then
    echo
    echo "Success. Now run: make migrate-up"
else
    echo "error: '$APP_USER' could not connect to '$DEV_DB' over TCP." >&2
    echo "       Check DB_PASSWORD in .env matches what this script used." >&2
    exit 1
fi
