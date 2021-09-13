#!/usr/bin/env bash
set -euo pipefail

gh release upload "$GITHUB_TAG" dist/*.tar.gz --clobber
