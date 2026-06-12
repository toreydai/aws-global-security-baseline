#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

AWS_REGION=${AWS_REGION:-us-east-1}
STACK_NAME=${STACK_NAME:-aws-global-security-baseline}
ALERT_EMAIL=${ALERT_EMAIL:-}
ENABLE_KMS_ENCRYPTION=${ENABLE_KMS_ENCRYPTION:-false}
MONTHLY_BUDGET_AMOUNT=${MONTHLY_BUDGET_AMOUNT:-0}

if [[ -z "${ALERT_EMAIL}" ]]; then
  echo "ERROR: set ALERT_EMAIL first, for example: export ALERT_EMAIL=security@example.com" >&2
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
EXISTING_GUARDDUTY_DETECTOR=$(aws guardduty list-detectors --region "${AWS_REGION}" --query 'DetectorIds[0]' --output text 2>/dev/null || true)
CREATE_GUARDDUTY_DETECTOR=true
CREATE_SECURITY_HUB=true
CREATE_ACCESS_ANALYZER=true

if [[ -n "${EXISTING_GUARDDUTY_DETECTOR}" && "${EXISTING_GUARDDUTY_DETECTOR}" != "None" ]]; then
  CREATE_GUARDDUTY_DETECTOR=false
fi

if aws securityhub describe-hub --region "${AWS_REGION}" >/dev/null 2>&1; then
  CREATE_SECURITY_HUB=false
fi

EXISTING_ACCESS_ANALYZER=$(aws accessanalyzer list-analyzers --region "${AWS_REGION}" --query "analyzers[?name=='account-external-access'].name | [0]" --output text 2>/dev/null || true)
if [[ "${EXISTING_ACCESS_ANALYZER}" == "account-external-access" ]]; then
  CREATE_ACCESS_ANALYZER=false
fi

aws cloudformation deploy \
  --stack-name "${STACK_NAME}" \
  --template-file "${PROJECT_DIR}/cloudformation/security-baseline.yaml" \
  --region "${AWS_REGION}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    AlertEmail="${ALERT_EMAIL}" \
    EnableKmsEncryption="${ENABLE_KMS_ENCRYPTION}" \
    MonthlyBudgetAmount="${MONTHLY_BUDGET_AMOUNT}" \
    CreateGuardDutyDetector="${CREATE_GUARDDUTY_DETECTOR}" \
    CreateSecurityHub="${CREATE_SECURITY_HUB}" \
    CreateAccessAnalyzer="${CREATE_ACCESS_ANALYZER}"

aws s3control put-public-access-block \
  --account-id "${ACCOUNT_ID}" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --region "${AWS_REGION}"

aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24

aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --region "${AWS_REGION}"

aws cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --region "${AWS_REGION}" \
  --query 'Stacks[0].Outputs' \
  --output table

echo
echo "Confirm the SNS subscription email sent to ${ALERT_EMAIL}."
