#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

HOME_REGION=${HOME_REGION:-${AWS_REGION:-us-east-1}}
ENABLE_REGIONS=${ENABLE_REGIONS:-""}
STACK_NAME_PREFIX=${STACK_NAME_PREFIX:-aws-global-security-baseline-regional}

if [[ -z "${ENABLE_REGIONS}" ]]; then
  echo "ERROR: set ENABLE_REGIONS first, for example: export ENABLE_REGIONS=\"us-west-2 eu-west-1\"" >&2
  exit 1
fi

for region in ${ENABLE_REGIONS}; do
  if [[ "${region}" == "${HOME_REGION}" ]]; then
    echo "==> Skipping ${region}; deploy.sh manages the home Region stack"
    continue
  fi

  echo "==> Deploying regional security services in ${region}"
  EXISTING_GUARDDUTY_DETECTOR=$(aws guardduty list-detectors --region "${region}" --query 'DetectorIds[0]' --output text 2>/dev/null || true)
  CREATE_GUARDDUTY_DETECTOR=true
  CREATE_SECURITY_HUB=true
  CREATE_ACCESS_ANALYZER=true

  if [[ -n "${EXISTING_GUARDDUTY_DETECTOR}" && "${EXISTING_GUARDDUTY_DETECTOR}" != "None" ]]; then
    CREATE_GUARDDUTY_DETECTOR=false
  fi

  if aws securityhub describe-hub --region "${region}" >/dev/null 2>&1; then
    CREATE_SECURITY_HUB=false
  fi

  EXISTING_ACCESS_ANALYZER=$(aws accessanalyzer list-analyzers --region "${region}" --query "analyzers[?name=='account-external-access'].name | [0]" --output text 2>/dev/null || true)
  if [[ "${EXISTING_ACCESS_ANALYZER}" == "account-external-access" ]]; then
    CREATE_ACCESS_ANALYZER=false
  fi

  aws cloudformation deploy \
    --stack-name "${STACK_NAME_PREFIX}-${region}" \
    --template-file "${PROJECT_DIR}/cloudformation/regional-security-services.yaml" \
    --region "${region}" \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
      IncludeGlobalResourceTypes=false \
      CreateGuardDutyDetector="${CREATE_GUARDDUTY_DETECTOR}" \
      CreateSecurityHub="${CREATE_SECURITY_HUB}" \
      CreateAccessAnalyzer="${CREATE_ACCESS_ANALYZER}"

  aws configservice start-configuration-recorder \
    --configuration-recorder-name default \
    --region "${region}"
done

echo "Done."
