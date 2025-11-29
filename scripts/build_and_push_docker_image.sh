#!/usr/bin/env bash
docker build -t registry.melroy.org/melroy/cidr-watcher/cidr-watcher:latest .
docker push registry.melroy.org/melroy/cidr-watcher/cidr-watcher:latest
