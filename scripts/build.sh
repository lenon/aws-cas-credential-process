#!/usr/bin/env bash
set -euo pipefail

ldflags="
    -X 'github.com/lenon/aws-cas-credential-process/cmd.gitTag=${GITHUB_TAG}'
    -X 'github.com/lenon/aws-cas-credential-process/cmd.gitCommit=${GITHUB_SHA}'
"

bin_ext=""
if [ "$GOOS" == "windows" ]; then
  bin_ext=".exe"
fi

output="dist/aws-cas-credential-process-$GOOS-$GOARCH$bin_ext"

mkdir -p dist
go build -o "$output" -ldflags="$ldflags"
tar -czf "$output.tar.gz" "$output"
