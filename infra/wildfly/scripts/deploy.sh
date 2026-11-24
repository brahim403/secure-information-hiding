#!/usr/bin/env bash
#
# Tessera — WildFly deployment driver (dev / prod).
#
# Applies the host/CORS/security-header CLI configuration for the chosen
# environment, then deploys the built artifacts. The base WildFly CLI scripts are
# applied through jboss-cli with the per-environment .properties files.
#
# Usage:
#   JBOSS_HOME=/opt/wildfly \
#   WILDFLY_CONTROLLER=remote+https://your-host:9993 \
#     infra/wildfly/scripts/deploy.sh <dev|prod>
#
# NOTE: not executed against a VPS in this repo — validated only against a local
# WildFly 42 (default controller 127.0.0.1:9990). Set WILDFLY_CONTROLLER for prod.
set -euo pipefail

ENV="${1:?usage: deploy.sh <dev|prod>}"
case "$ENV" in dev|prod) ;; *) echo "env must be dev or prod" >&2; exit 2;; esac

: "${JBOSS_HOME:?set JBOSS_HOME to your WildFly install}"
CONTROLLER="${WILDFLY_CONTROLLER:-127.0.0.1:9990}"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CLI_DIR="$ROOT/infra/wildfly/cli"
PROPS="$CLI_DIR/properties"
CLI="$JBOSS_HOME/bin/jboss-cli.sh"

cli_file() { "$CLI" --connect --controller="$CONTROLLER" --file="$1" --properties="$2"; }
cli_cmd()  { "$CLI" --connect --controller="$CONTROLLER" --command="$1"; }

echo ">>> [$ENV] configuring default (front office) host"
cli_file "$CLI_DIR/default-host.cli" "$PROPS/default-host-$ENV.properties"

echo ">>> [$ENV] configuring API host"
cli_file "$CLI_DIR/add-api.cli" "$PROPS/api-$ENV.properties"

echo ">>> [$ENV] configuring IAM host"
cli_file "$CLI_DIR/add-api.cli" "$PROPS/iam-$ENV.properties"

# Admin host only exists for prod in the sample properties.
if [[ "$ENV" == "prod" && -f "$PROPS/admin-host-$ENV.properties" ]]; then
  echo ">>> [$ENV] configuring admin host"
  cli_file "$CLI_DIR/add-host.cli" "$PROPS/admin-host-$ENV.properties"
fi

echo ">>> [$ENV] deploying artifacts"
API_WAR="$ROOT/backend/api/target/tessera-api.war"
[[ -f "$API_WAR" ]] || { echo "build first: JAVA_HOME=... mvn -pl backend/api -am package" >&2; exit 1; }
cli_cmd "deploy --force $API_WAR"
# IAM war (optional second host):
# cli_cmd "deploy --force $ROOT/backend/iam/target/iam-1.0.war"

echo ">>> [$ENV] done. Reload if the CLI reported reload-required:"
echo "    $CLI --connect --controller=$CONTROLLER --command=:reload"
