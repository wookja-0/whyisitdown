#!/usr/bin/env bash
# The session recorded for the README demo. Run it through docs/record-demo.sh
# rather than directly; it expects to be driven by asciinema.
#
# whyisitdown must be on PATH, and it must be the version being demonstrated.
set -u

# Type the command out a character at a time, so the recording reads like
# someone using the tool rather than a screenshot that happens to move.
type_line() {
	printf '\033[38;5;245m$\033[0m '
	local i
	for ((i = 0; i < ${#1}; i++)); do
		printf '%s' "${1:i:1}"
		sleep 0.035
	done
	printf '\n'
	sleep 0.35
}

type_line 'whyisitdown https://example.com'
whyisitdown https://example.com

# Hold the final frame long enough to read the summary.
sleep 4
