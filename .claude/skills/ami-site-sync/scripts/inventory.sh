#!/usr/bin/env bash
# Inventory the released StigReady BASE AMIs and print one line per OS/arch.
#
# Reads ONLY: AMI Name + the OS/Arch/Lifecycle/Product tags.
# Never emits AMI IDs, snapshot IDs, CVE/score data, or anything from the
# evidence bucket. Output is safe to reason about for public site copy.
#
# Usage: inventory.sh [profile] [region]
set -euo pipefail

PROFILE="${1:-stigready}"
REGION="${2:-us-east-1}"

aws ec2 describe-images \
  --owners self \
  --profile "$PROFILE" \
  --region "$REGION" \
  --filters 'Name=name,Values=stigready-base-*' 'Name=state,Values=available' \
  --query 'Images[].Name' \
  --output text 2>/dev/null \
| tr '\t' '\n' \
| sed 's/^stigready-base-//' \
| awk -F'-' '
    {
      ver = $NF                      # trailing vX.Y.Z
      if (NF >= 3 && $(NF-1) == "aarch64") { os = $1; arch = "arm64" }
      else                                 { os = $1; arch = "x86_64" }
      key = os "|" arch
      # keep the highest version string seen for this os/arch
      if (!(key in best) || ver > best[key]) best[key] = ver
    }
    END { for (k in best) print k "|" best[k] }
  ' \
| sort -t'|' -k1,1 -k2,2
