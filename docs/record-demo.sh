#!/usr/bin/env bash
# Re-record the README demo.
#
#   brew install asciinema agg
#   docs/record-demo.sh
#
# The window size is fixed so the whole report fits without scrolling; if the
# output grows past 42 rows, raise it here and re-record.
set -euo pipefail

cd "$(dirname "$0")/.."

asciinema rec \
	--overwrite \
	--window-size 100x42 \
	--idle-time-limit 2 \
	--title "whyisitdown" \
	--command docs/demo-session.sh \
	docs/demo.cast

agg --font-size 14 --theme asciinema --idle-time-limit 2 docs/demo.cast docs/demo.gif

echo "wrote docs/demo.cast and docs/demo.gif"
