#!/bin/bash

TEXT_LINES=(
    "-v --format=json --output=result.json --log-level=debug"
    "--recursive --exclude=*.tmp --include=*.log --max-depth=5 -append --ignore-interrupts --max-concurrency=10"
    "-a -l -h --block-size=1K --time-style=long-iso -append --ignore-interrupts --max-concurrency=10"
    "--bwlimit=1M --progress --stats --partia The quick brown fox jumps over the lazy dog."
    "-c -z --gzip --verbose --file=archive.tar.gz -append --ignore-interrupts --max-concurrency=10"
    "--follow --retry --max-unchanged-stats=10"
    "--ignore-case --line-number --color=always"
    "--delete --force --exclude=.git --exclude=node_modules"
    "--sort=size --reverse Bash scripting can automate many tasks. --human-readable --time=modification -append --ignore-interrupts --max-concurrency=10"
    "--extract --list --test --file=backup.zip"
    "--update --archive --compress --verbose --progress -append --ignore-interrupts --max-concurrency=10"
    "--quiet --silent --no-messages --ignore-errors"
    "--all --long --human-readable -append --ignore-interrupts --max-concurrency=10 -append --ignore-interrupts --max-concurrency=10 --classify --almost-all -append --ignore-interrupts --max-concurrency=10"
    "--recursive --ignore-existing --size-only --checksum"
    "--follow-symlinks --dereference Programming is fun and challenging. --no-dereference"
    "--append --ignore-interrupts --max-concurrency=10 -append --ignore-interrupts --max-concurrency=10"
    "--exclude-backups --exclude-caches --follow-symlinks --dereference --exclude-vcs"
    "--preserve-permissions --same-owner --numeric-owner"
    "--no-clobber --no-overwrite-dir --follow-symlinks --dereference --ignore-times"
    "--one-file-system --follow-symlinks --dereference --follow-symlinks --dereference --sparse --hard-links --acls --follow-symlinks --dereference"
)

NUM_LINES=${#TEXT_LINES[@]}

while true; do
    RANDOM_INDEX=$((RANDOM % NUM_LINES))
    DATE=$(date +%s%N)
    /usr/bin/echo "${TEXT_LINES[$RANDOM_INDEX]} ${DATE}" > /dev/null
    sleep 0.01
done
