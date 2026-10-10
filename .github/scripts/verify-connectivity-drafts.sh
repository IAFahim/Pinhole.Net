#!/usr/bin/env bash
# Run on a host with normal socket access. Mirrors the separate CI test processes;
# a denied socket or failing check fails the script instead of being reported as green.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$repo_root"

dotnet build Pinhole.Net.slnx -c Release --disable-build-servers -warnaserror

frameworks=("$@")
if (( ${#frameworks[@]} == 0 )); then frameworks=(net8.0 net10.0); fi
for framework in "${frameworks[@]}"; do
  dotnet test tests/Pinhole.Tests -c Release -f "$framework" --no-build \
    --filter "FullyQualifiedName~InteropTests" \
    --logger trx --logger "console;verbosity=detailed" \
    --blame-hang --blame-hang-timeout 5m --blame-hang-dump-type mini

  dotnet test tests/Pinhole.Tests -c Release -f "$framework" --no-build \
    --filter "Category!=Performance&FullyQualifiedName!~BoundedResourceTests&FullyQualifiedName!~InteropTests" \
    --logger trx --logger "console;verbosity=detailed" \
    --blame-hang --blame-hang-timeout 2m --blame-hang-dump-type mini

  dotnet test tests/Pinhole.Tests -c Release -f "$framework" --no-build \
    --filter "FullyQualifiedName~BoundedResourceTests" \
    --logger trx --logger "console;verbosity=detailed" \
    --blame-hang --blame-hang-timeout 2m --blame-hang-dump-type mini

  dotnet test tests/Pinhole.Tests -c Release -f "$framework" --no-build \
    --filter "Category=Performance" \
    --logger trx --logger "console;verbosity=detailed" \
    -- xUnit.MaxParallelThreads=1
done
