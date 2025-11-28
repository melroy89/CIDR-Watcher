#!/usr/bin/env bash
docker build -t registry.melroy.org/melroy/cidr-watcher/cidr-watcher:latest .

# Publish to both GitLab Registry
docker push registry.melroy.org/melroy/cidr-watcher/cidr-watcher:latest
