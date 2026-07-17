# 测试手册：AWS Global Account Minimum Security Baseline

## 前提条件

- AWS CLI v2，已配置具有 `AdministratorAccess` 权限的凭证
- 目标账号为 Global（非 China）账号
- 已 `cd` 进入项目根目录

确认身份：
```bash
aws sts get-caller-identity
```

---

## 一、部署测试

### 1.1 基础版部署

```bash
export AWS_REGION=us-east-1
export ALERT_EMAIL=your@email.com
bash scripts/deploy.sh
```

**期望结果**：

- 脚本输出 `Successfully created/updated stack - aws-global-security-baseline`
- 输出 Outputs 表格，包含 `TrailName`、`TrailBucketName`、`ConfigBucketName`、`AlertTopicArn`
- `TrailName` 值为 `account-baseline-trail`（字符串名称，非 ARN）
- 收到 SNS 订阅确认邮件，**必须点击确认**，否则不会收到告警

### 1.2 幂等重跑

不修改任何参数，再次运行：

```bash
bash scripts/deploy.sh
```

**期望结果**：脚本正常完成，不报错，Outputs 表格正常输出。若未加 `--no-fail-on-empty-changeset` 则此步会以非零退出码中断（已修复）。

---

## 二、服务验证

将 `$R` 替换为实际部署的 Region（如 `us-east-1`）：

```bash
R="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### 2.1 CloudTrail

```bash
# 录制状态
aws cloudtrail get-trail-status --name account-baseline-trail --region "$R" \
  --query '{IsLogging:IsLogging,LatestDeliveryError:LatestDeliveryError}'
```
期望：`IsLogging: true`，`LatestDeliveryError: null`

```bash
# 配置检查
aws cloudtrail describe-trails --trail-name-list account-baseline-trail --region "$R" \
  --query 'trailList[0].{MultiRegion:IsMultiRegionTrail,LogValidation:LogFileValidationEnabled,GlobalEvents:IncludeGlobalServiceEvents}'
```
期望：三项均为 `true`

### 2.2 AWS Config

```bash
aws configservice describe-configuration-recorder-status --region "$R" \
  --query 'ConfigurationRecordersStatus[0].{Recording:recording,LastStatus:lastStatus}'
```
期望：`Recording: true`，`LastStatus: SUCCESS`

```bash
aws configservice describe-config-rules --region "$R" \
  --query 'ConfigRules[].{Name:ConfigRuleName,State:ConfigRuleState}'
```
期望：`root-account-mfa-enabled`、`s3-bucket-public-read-prohibited`、`s3-bucket-public-write-prohibited` 均为 `ACTIVE`

### 2.3 GuardDuty

```bash
DETECTOR=$(aws guardduty list-detectors --region "$R" --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "$DETECTOR" --region "$R" \
  --query '{Status:Status,PublishingFrequency:FindingPublishingFrequency}'
```
期望：`Status: ENABLED`，`PublishingFrequency: FIFTEEN_MINUTES`

### 2.4 Security Hub

```bash
aws securityhub describe-hub --region "$R" --query 'HubArn'
aws securityhub get-enabled-standards --region "$R" \
  --query 'StandardsSubscriptions[].{Arn:StandardsSubscriptionArn,Status:StandardsStatus}'
```
期望：Hub ARN 存在；FSBP 标准状态为 `READY` 或 `INCOMPLETE`（刚启用时为 INCOMPLETE，扫描完成后变 READY，属正常现象）

### 2.5 IAM Access Analyzer

```bash
aws accessanalyzer list-analyzers --region "$R" \
  --query 'analyzers[].{Name:name,Type:type,Status:status}'
```
期望：`account-external-access`，`Type: ACCOUNT`，`Status: ACTIVE`

### 2.6 IAM 密码策略

```bash
aws iam get-account-password-policy \
  --query 'PasswordPolicy.{MinLen:MinimumPasswordLength,Symbols:RequireSymbols,Numbers:RequireNumbers,MaxAge:MaxPasswordAge,Reuse:PasswordReusePrevention}'
```
期望：`MinLen: 14`，`Symbols/Numbers: true`，`MaxAge: 90`，`Reuse: 24`

### 2.7 S3 账号级 Block Public Access

```bash
aws s3control get-public-access-block --account-id "$ACCOUNT_ID" --region "$R"
```
期望：四项（`BlockPublicAcls`、`IgnorePublicAcls`、`BlockPublicPolicy`、`RestrictPublicBuckets`）均为 `true`

### 2.8 日志桶安全配置

```bash
TRAIL_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aws-global-security-baseline --region "$R" \
  --query 'Stacks[0].Outputs[?OutputKey==`TrailBucketName`].OutputValue' --output text)

# 加密
aws s3api get-bucket-encryption --bucket "$TRAIL_BUCKET" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm'
# 期望：AES256（基础版）或 aws:kms（KMS 增强版）

# Lifecycle
aws s3api get-bucket-lifecycle-configuration --bucket "$TRAIL_BUCKET" \
  --query 'Rules[0].{Id:ID,Status:Status,TransitionDays:Transitions[0].Days,StorageClass:Transitions[0].StorageClass}'
# 期望：Id=glacier-after-90-days，Status=Enabled，TransitionDays=90，StorageClass=GLACIER

# Versioning
aws s3api get-bucket-versioning --bucket "$TRAIL_BUCKET" --query 'Status'
# 期望：Enabled

# HTTPS-only（HTTP 请求应返回 403）
curl -s -o /dev/null -w "%{http_code}" "http://${TRAIL_BUCKET}.s3.amazonaws.com/"
# 期望：403
```

### 2.9 CloudWatch Alarms

```bash
aws cloudwatch describe-alarms --region "$R" \
  --query 'MetricAlarms[?starts_with(AlarmName,`account-security`)].{Name:AlarmName,State:StateValue}'
```
期望：9 条告警全部存在，State 为 `OK`（无真实触发时）

### 2.10 EventBridge Rules

```bash
aws events list-rules --region "$R" \
  --query 'Rules[?contains(Name,`GuardDuty`)||contains(Name,`SecurityHub`)].{Name:Name,State:State}'
```
期望：GuardDuty 和 SecurityHub 各一条规则，State 均为 `ENABLED`

### 2.11 SNS Topic Policy（Confused-Deputy 防护）

```bash
SNS_ARN=$(aws cloudformation describe-stacks \
  --stack-name aws-global-security-baseline --region "$R" \
  --query 'Stacks[0].Outputs[?OutputKey==`AlertTopicArn`].OutputValue' --output text)

aws sns get-topic-attributes --topic-arn "$SNS_ARN" --region "$R" \
  --query 'Attributes.Policy' --output text | python3 -m json.tool | grep -A8 "SourceAccount\|AllowEventBridge"
```
期望：`AllowEventBridgePublish` 语句含 `aws:SourceAccount` 条件

---

## 三、告警联动测试（可选）

> ⚠️ 以下操作会产生真实 CloudTrail 事件并触发告警邮件。在测试环境执行，确认 SNS 订阅已确认后再操作。

### 3.1 IAM 策略变更告警

```bash
# 创建并立即删除一个测试策略，触发 IamPolicyChanges MetricFilter
aws iam create-policy --policy-name baseline-test-policy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
aws iam delete-policy \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/baseline-test-policy"
```

**期望结果**：5 分钟内收到 `account-security-iam-policy-changes` 告警邮件

### 3.2 Security Group 变更告警

```bash
# 在默认 VPC 创建并删除测试 SG
DEFAULT_VPC=$(aws ec2 describe-vpcs --region "$R" \
  --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws ec2 create-security-group --region "$R" \
  --group-name "baseline-test-sg" --description "test" --vpc-id "$DEFAULT_VPC" \
  --query 'GroupId' --output text)
aws ec2 delete-security-group --group-id "$SG_ID" --region "$R"
```

**期望结果**：5 分钟内收到 `account-security-security-group-changes` 告警邮件

---

## 四、清理

### 4.1 清空并删除堆栈

日志桶设置了 `DeletionPolicy: Retain`，需先手工清空：

```bash
REGION="${AWS_REGION:-us-east-1}"
TRAIL_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aws-global-security-baseline --region "$REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`TrailBucketName`].OutputValue' --output text)
CONFIG_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aws-global-security-baseline --region "$REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`ConfigBucketName`].OutputValue' --output text)

# 清空两个桶（含所有版本）
for BUCKET in "$TRAIL_BUCKET" "$CONFIG_BUCKET"; do
  aws s3 rm "s3://$BUCKET" --recursive
  VERSIONS=$(aws s3api list-object-versions --bucket "$BUCKET" \
    --query '[Versions,DeleteMarkers][]|[].{Key:Key,VersionId:VersionId}' --output json 2>/dev/null)
  [ "$VERSIONS" != "null" ] && [ "$VERSIONS" != "[]" ] && \
    aws s3api delete-objects --bucket "$BUCKET" --delete "{\"Objects\":${VERSIONS}}" > /dev/null
  aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION"
  echo "$BUCKET deleted"
done

# 删除堆栈
aws cloudformation delete-stack --stack-name aws-global-security-baseline --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name aws-global-security-baseline --region "$REGION"
echo "Stack deleted"
```

### 4.2 回滚 CLI 设置的账号级配置

`delete-stack` 不会撤销以下两项（由脚本通过 CLI 单独设置）：

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 删除 IAM 密码策略
aws iam delete-account-password-policy

# 删除账号级 S3 Block Public Access
aws s3control delete-public-access-block --account-id "$ACCOUNT_ID" --region "$REGION"
```

### 4.3 清理额外 Region（如有部署）

```bash
# 示例：清理 us-west-2
aws cloudformation delete-stack \
  --stack-name aws-global-security-baseline-regional-us-west-2 \
  --region us-west-2
aws cloudformation wait stack-delete-complete \
  --stack-name aws-global-security-baseline-regional-us-west-2 \
  --region us-west-2
```

额外 Region 的 Config 桶同样需要先手工清空（步骤同 4.1）。

### 4.4 清理验证

```bash
# 堆栈已删除
aws cloudformation describe-stacks --stack-name aws-global-security-baseline --region "$REGION" 2>&1 | grep -c "does not exist"
# 期望：1

# 桶已删除
aws s3api list-buckets --query "Buckets[?contains(Name,'aws-global-security-baseline')].Name" --output text
# 期望：空

# Access Analyzer 已删除（随堆栈删除）
aws accessanalyzer list-analyzers --region "$REGION" --query 'analyzers[?name==`account-external-access`].name' --output text
# 期望：空
```

---

## 五、已知注意事项

| 事项 | 说明 |
|------|------|
| Security Hub 状态 INCOMPLETE | 标准首次启用后扫描需数分钟至数小时，期间状态为 INCOMPLETE，属正常现象，不影响功能 |
| GuardDuty / SecurityHub 预存在 | 若账号已有这两项服务，脚本自动探测并跳过重建，存量配置不受影响 |
| Config 无重复创建保护 | 若账号已有名为 `default` 的 ConfigurationRecorder，堆栈会 CREATE_FAILED；在已纳管 Control Tower 的账号中不适用 |
| KMS 增强未默认启用 | `BucketKeyEnabled` 修复需要 `ENABLE_KMS_ENCRYPTION=true` 触发，基础版路径不覆盖 |
| Root MFA 为手工项 | `AccountMFAEnabled=1` 表示账号 MFA 已启用；物理设备状态无法通过 API 验证，需登录 Console 确认 |
| SNS 订阅必须手工确认 | 部署后检查邮件并点击确认，否则所有告警静默送达 SNS 但不转发邮件 |
