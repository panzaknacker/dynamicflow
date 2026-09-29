#!/usr/bin/env bash
set -Eeuo pipefail

project="${DECEPTICON_COMPOSE_PROJECT:-decepticon}"
home_dir="${DECEPTICON_HOME:-${HOME}/.decepticon}"
compose_file="${home_dir}/docker-compose.yml"
env_file="${home_dir}/.env"
reset=0

usage() {
    cat <<'EOF'
Usage: ./fix-decepticon-postgres.sh [--reset]

Shows Postgres status/logs for Decepticon. With --reset it stops the stack,
removes only the Decepticon Postgres volume, and tells you how to start again.
Use --reset only on a fresh/broken VM or when you accept losing LiteLLM/Web DB
state. Neo4j/workspace data is not removed.
EOF
}

while (($#)); do
    case "$1" in
    --reset)
        reset=1
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
done

if [[ ! -f "$compose_file" || ! -f "$env_file" ]]; then
    echo "missing compose runtime files in $home_dir" >&2
    exit 1
fi

echo "== Fixing runtime file permissions =="
chmod -R a+rX "$home_dir/config" "$home_dir/containers" 2>/dev/null || true
chmod a+r "$home_dir/docker-compose.yml" "$home_dir/.env.example" 2>/dev/null || true

compose=(docker compose -p "$project" -f "$compose_file" --env-file "$env_file")

echo "== Postgres container =="
docker ps -a --filter name=decepticon-postgres || true

echo
echo "== Postgres inspect =="
docker inspect decepticon-postgres --format 'status={{.State.Status}} exit={{.State.ExitCode}} health={{if .State.Health}}{{.State.Health.Status}}{{end}} error={{.State.Error}}' 2>/dev/null || true

echo
echo "== Postgres logs =="
docker logs decepticon-postgres --tail=200 2>&1 || true

if [[ "$reset" != 1 ]]; then
    cat <<EOF

To reset a broken fresh Postgres init:
  ./fix-decepticon-postgres.sh --reset
EOF
    exit 0
fi

echo
echo "== Stopping stack =="
"${compose[@]}" --profile cli --profile web --profile c2-sliver --profile ad --profile reversing down --remove-orphans || true

echo
echo "== Removing only Postgres volume =="
docker volume rm "${project}_postgres_data" || true

cat <<EOF

Postgres volume reset done. Start again with:
  decepticon start
EOF
