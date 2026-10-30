#!/bin/sh
# Container entrypoint. /cowrie/var is a mounted volume, so the directories the
# image created there are hidden at runtime: recreate them, then run twistd in the
# foreground with no pidfile (the root filesystem is read-only).
set -eu
mkdir -p var/log/cowrie var/lib/cowrie/tty var/lib/cowrie/downloads var/run
exec twistd --umask=0022 --nodaemon --pidfile= --logger cowrie.python.logfile.stdoutLogger cowrie
