#!/usr/bin/env bash
#
# Tessera — WildFly version update helper.
#
# Downloads a target WildFly release and switches the ~/tools/wildfly symlink to
# it, keeping the previous install for rollback. Standalone config is NOT copied
# automatically — review and migrate standalone.xml deliberately.
#
# Usage: update-wildfly.sh <version>   e.g. update-wildfly.sh 42.0.1.Final
#
# NOTE: not executed in CI here; run on the target host.
set -euo pipefail

VERSION="${1:?usage: update-wildfly.sh <version>  (e.g. 42.0.1.Final)}"
TOOLS="${TOOLS_DIR:-$HOME/tools}"
URL="https://github.com/wildfly/wildfly/releases/download/${VERSION}/wildfly-${VERSION}.zip"

mkdir -p "$TOOLS"
tmp="$(mktemp -d)"
echo ">>> downloading $URL"
curl -fsSL -o "$tmp/wildfly.zip" "$URL"
echo ">>> extracting"
unzip -q "$tmp/wildfly.zip" -d "$TOOLS"
rm -rf "$tmp"

if [[ -L "$TOOLS/wildfly" ]]; then
  prev="$(readlink -f "$TOOLS/wildfly")"
  echo ">>> previous install kept for rollback: $prev"
fi
ln -sfn "$TOOLS/wildfly-${VERSION}" "$TOOLS/wildfly"
echo ">>> WildFly is now $TOOLS/wildfly -> wildfly-${VERSION}"
echo ">>> review standalone.xml, then restart the service."
