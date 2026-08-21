#!/bin/sh
set -eu
branch="$(git branch --show-current 2>/dev/null || echo dev-local)"
case "$branch" in
  master|main)
    echo stable
    ;;
  canary)
    echo canary
    ;;
  dev)
    echo dev
    ;;
  *)
    echo dev-local
    ;;
esac
