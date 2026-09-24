#!/bin/sh
set -eu
id apisurvey >/dev/null 2>&1 || useradd --system --home /opt/api-survey-ai --shell /usr/sbin/nologin apisurvey
python3 -m venv .venv
.venv/bin/pip install .
install -d -o apisurvey -g apisurvey /var/lib/api-survey-ai
printf '%s\n' 'Configure dumpcap capabilities/group access; do not run the agent as root.'
