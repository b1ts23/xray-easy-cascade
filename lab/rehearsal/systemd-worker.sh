#!/bin/sh
set -eu
echo worker > /run/worker-done
systemctl stop rehearsal-rollback.timer
