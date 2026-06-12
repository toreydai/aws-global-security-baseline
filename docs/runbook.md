# Runbook：AWS Global Account Minimum Security Baseline

本手册描述收到告警后的响应步骤。**收到告警不等于发生入侵**——大多数告警来自正常运维操作，关键是快速判断并记录。

响应基本原则：
1. **先判断，再行动**：确认是计划内操作还是异常，不要因误报引发过激反应
2. **留痕**：所有调查和处置操作记录到事件工单
3. **止损优先**：若确认入侵，先撤销凭证或隔离资源，再溯源

---

## 一、CloudWatch 告警响应

### 快速对照表

| 告警名称 | 常见原因 | 紧急度 |
|----------|----------|--------|
| `account-security-root-usage` | root 登录操作 | 🔴 高 |
| `account-security-cloudtrail-changes` | 有人修改审计配置 | 🔴 高 |
| `account-security-iam-policy-changes` | 权限变更 | 🟡 中 |
| `account-security-unauthorized-api-calls` | 凭证泄露或误配 | 🟡 中 |
| `account-security-console-login-failure` | 暴力破解或误输密码 | 🟡 中 |
| `account-security-security-group-changes` | 网络边界变更 | 🟡 中 |
| `account-security-network-acl-changes` | 网络边界变更 | 🟡 中 |
| `account-security-route-table-changes` | 路由变更 | 🟡 中 |
| `account-security-vpc-changes` | VPC 拓扑变更 | 🟢 低 |

---

### 1.1 `account-security-root-usage`

**触发条件**：root 用户执行了任何 API 调用或控制台登录。

**排查步骤**：

```bash
# 查看最近 root 操作记录
aws logs filter-log-events \
  --log-group-name "/aws/cloudtrail/account-baseline-trail" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --start-time $(date -d '1 hour ago' +%s000) \
  --query 'events[].message' --output text | python3 -m json.tool 2>/dev/null | grep -E "eventName|sourceIPAddress|eventTime" | head -30
```

**判断逻辑**：

- **计划内操作**（如账号设置、支持计划变更）→ 记录原因，提醒操作者改用 IAM Identity Center，关闭告警
- **不认识的 IP 或操作**：
  1. 立即到 IAM Console → 安全凭证 → 撤销所有 root 会话
  2. 如有 root access key，立即禁用
  3. 检查 root MFA 是否仍绑定设备（防止 MFA 设备被克隆）
  4. 检查近 24 小时内是否有账号设置变更（联系人、支付方式、支持计划）
  5. 上报事件，考虑联系 AWS Support

---

### 1.2 `account-security-cloudtrail-changes`

**触发条件**：CloudTrail 本身被创建、更新、删除或停止记录。

**排查步骤**：

```bash
# 查看 CloudTrail 变更详情
aws logs filter-log-events \
  --log-group-name "/aws/cloudtrail/account-baseline-trail" \
  --filter-pattern '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StopLogging) }' \
  --start-time $(date -d '30 minutes ago' +%s000) \
  --query 'events[].message' --output text | python3 -m json.tool 2>/dev/null | grep -E "eventName|userIdentity|sourceIPAddress" | head -20

# 确认 trail 当前是否仍在录制
aws cloudtrail get-trail-status --name account-baseline-trail \
  --region "${AWS_REGION:-us-east-1}" --query '{IsLogging:IsLogging}'
```

**判断逻辑**：

- `StopLogging` 或 `DeleteTrail`：**高度可疑**，攻击者常在提权后关闭审计日志以掩盖痕迹
  1. 若 trail 被停止：`aws cloudtrail start-logging --name account-baseline-trail`
  2. 若 trail 被删除：重新执行 `bash scripts/deploy.sh` 恢复
  3. 立即检查同时段其他操作（IAM 变更、资源创建）
- `UpdateTrail` / `CreateTrail`：确认操作者身份是否为授权管理员

---

### 1.3 `account-security-iam-policy-changes`

**触发条件**：IAM 策略创建、修改、附加或解绑。

**排查步骤**：

```bash
# 查看 IAM 变更详情
aws logs filter-log-events \
  --log-group-name "/aws/cloudtrail/account-baseline-trail" \
  --filter-pattern '{ ($.eventName = CreatePolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = PutRolePolicy) || ($.eventName = AttachUserPolicy) }' \
  --start-time $(date -d '30 minutes ago' +%s000) \
  --query 'events[].message' --output text | python3 -m json.tool 2>/dev/null | grep -E "eventName|userIdentity|requestParameters" | head -30
```

**判断逻辑**：

- 确认操作者是授权管理员且属于计划内变更 → 关闭告警，记录变更工单
- 非授权操作或 `AdministratorAccess` 被附加到意外实体 → 立即撤销：
  ```bash
  # 示例：撤销非预期策略附加
  aws iam detach-role-policy --role-name <role> --policy-arn <arn>
  ```

---

### 1.4 `account-security-unauthorized-api-calls`

**触发条件**：5 分钟内出现 ≥5 次 `*UnauthorizedOperation` 或 `AccessDenied*` 错误。

**排查步骤**：

```bash
# 查找拒绝来源
aws logs filter-log-events \
  --log-group-name "/aws/cloudtrail/account-baseline-trail" \
  --filter-pattern '{ ($.errorCode = "AccessDenied*") || ($.errorCode = "*UnauthorizedOperation") }' \
  --start-time $(date -d '1 hour ago' +%s000) \
  --query 'events[].message' --output text | python3 -c "
import sys,json
for line in sys.stdin:
    try:
        e=json.loads(line.strip())
        print(e.get('userIdentity',{}).get('arn','?'), '|', e.get('eventName','?'), '|', e.get('sourceIPAddress','?'))
    except: pass
" 2>/dev/null | sort | uniq -c | sort -rn | head -20
```

**判断逻辑**：

- **CI/CD 管道或应用权限不足**：权限误配，正常现象 → 排查应用 IAM 策略
- **陌生 IAM Role / 陌生 IP 集中探测权限**：凭证泄露特征 → 立即禁用对应 Access Key 或撤销 Role 信任策略

---

### 1.5 `account-security-console-login-failure`

**触发条件**：5 分钟内 ≥5 次控制台登录失败。

**排查步骤**：

```bash
aws logs filter-log-events \
  --log-group-name "/aws/cloudtrail/account-baseline-trail" \
  --filter-pattern '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }' \
  --start-time $(date -d '30 minutes ago' +%s000) \
  --query 'events[].message' --output text | python3 -c "
import sys,json
for line in sys.stdin:
    try:
        e=json.loads(line.strip())
        print(e.get('userIdentity',{}).get('userName','?'), '|', e.get('sourceIPAddress','?'))
    except: pass
" 2>/dev/null | sort | uniq -c | sort -rn
```

**判断逻辑**：

- 单用户偶发失败（记错密码）→ 记录，关闭告警
- 同一 IP 针对多个账号高频失败：凭证填充攻击 →
  1. 临时禁用被攻击 IAM 用户：`aws iam update-login-profile --user-name <user> --no-password-reset-required`（或直接删除登录配置）
  2. 考虑在 IAM Identity Center 开启强制 MFA

---

### 1.6 网络变更告警（SG / NACL / 路由表 / VPC）

`account-security-security-group-changes`、`account-security-network-acl-changes`、`account-security-route-table-changes`、`account-security-vpc-changes`

**排查步骤**：

```bash
# 以 SG 变更为例，替换 filterPattern 可查其他类型
aws logs filter-log-events \
  --log-group-name "/aws/cloudtrail/account-baseline-trail" \
  --filter-pattern '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) }' \
  --start-time $(date -d '30 minutes ago' +%s000) \
  --query 'events[].message' --output text | python3 -m json.tool 2>/dev/null | grep -E "eventName|userIdentity|requestParameters" | head -30
```

**判断逻辑**：

- 操作者是授权工程师 + 变更在变更管理系统中有记录 → 关闭告警
- 0.0.0.0/0 入方向规则被放开 → 立即复查并按需撤销：
  ```bash
  aws ec2 revoke-security-group-ingress --group-id <sg-id> \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 --region <region>
  ```
- 路由表新增指向外部 ENI / 实例的路由（数据外泄路径特征）→ 立即删除并溯源

---

## 二、GuardDuty Finding 响应

邮件告警包含 finding 类型和严重度（4–10）。

### 2.1 分级处理

| 严重度 | 级别 | 响应时限 | 处置方式 |
|--------|------|----------|----------|
| 7–10 | HIGH / CRITICAL | 1 小时内 | 立即隔离受影响资源，启动事件响应 |
| 4–6.9 | MEDIUM | 工作日内 | 调查确认，制定修复计划 |

### 2.2 常见 Finding 类型对照

| Finding 类型 | 含义 | 快速处置 |
|-------------|------|----------|
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | 已知恶意 IP 调用 API | 禁用对应 Access Key，审查该 Key 近期操作 |
| `UnauthorizedAccess:EC2/SSHBruteForce` | EC2 实例遭 SSH 暴力破解 | 收紧 SG 规则，检查是否有成功登录 |
| `Recon:IAMUser/UserPermissions` | 有人在枚举 IAM 权限 | 溯源 IAM 身份，判断是否为授权渗透测试 |
| `CryptoCurrency:EC2/BitcoinTool.B` | EC2 实例运行挖矿程序 | 立即隔离（移除公网 SG），快照取证后终止 |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | 有人关闭 CloudTrail | 立即恢复录制，审查同时段所有操作 |
| `PenTest:IAMUser/ParrotLinux` | 渗透测试工具请求 | 确认是否为授权测试，否则视为入侵 |

### 2.3 通用调查命令

```bash
# 列出近期 HIGH/CRITICAL findings
DETECTOR=$(aws guardduty list-detectors --region "${AWS_REGION:-us-east-1}" \
  --query 'DetectorIds[0]' --output text)

aws guardduty list-findings --detector-id "$DETECTOR" \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7},"service.archived":{"Eq":["false"]}}}' \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'FindingIds' --output json

# 查看具体 finding 详情（替换 FINDING_ID）
aws guardduty get-findings --detector-id "$DETECTOR" \
  --finding-ids FINDING_ID \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'Findings[0].{Type:Type,Severity:Severity,Description:Description,Resource:Resource}'
```

---

## 三、Security Hub Finding 响应

邮件包含失败的 FSBP 检查项（CRITICAL/HIGH）。

### 3.1 查看当前高危失败项

```bash
aws securityhub get-findings --region "${AWS_REGION:-us-east-1}" \
  --filters '{"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}],"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}]}' \
  --query 'Findings[].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}' \
  --output table
```

### 3.2 常见高危项对照

| 检查项 | 修复方向 |
|--------|----------|
| `root-account-mfa-enabled` | 登录 root 账号开启 MFA |
| `iam-root-access-key-check` | 删除 root access key |
| `s3-bucket-public-read-prohibited` | 关闭对应 S3 桶的公开读取 |
| `cloudtrail-enabled` | 确认 CloudTrail 正在录制 |
| `guardduty-enabled-centralized` | 在所有 Region 启用 GuardDuty |

修复完成后，将 finding 工作流状态更新为 `RESOLVED`：

```bash
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id":"<finding-id>","ProductArn":"<product-arn>"}]' \
  --workflow '{"Status":"RESOLVED"}' \
  --region "${AWS_REGION:-us-east-1}"
```

---

## 四、服务健康响应

### 4.1 CloudTrail 停止录制

**症状**：`get-trail-status` 返回 `IsLogging: false`，或收到 `LatestDeliveryError`。

```bash
# 恢复录制
aws cloudtrail start-logging --name account-baseline-trail \
  --region "${AWS_REGION:-us-east-1}"

# 检查交付错误原因
aws cloudtrail get-trail-status --name account-baseline-trail \
  --region "${AWS_REGION:-us-east-1}" \
  --query '{IsLogging:IsLogging,LatestDeliveryError:LatestDeliveryError,LatestDeliveryAttemptTime:LatestDeliveryAttemptTime}'
```

常见原因：日志桶被删除或策略变更 → 执行 `bash scripts/deploy.sh` 重建桶策略。

### 4.2 Config Recorder 停止录制

```bash
# 检查状态
aws configservice describe-configuration-recorder-status \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'ConfigurationRecordersStatus[0].{Recording:recording,LastStatus:lastStatus,LastErrorMessage:lastErrorMessage}'

# 恢复录制
aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --region "${AWS_REGION:-us-east-1}"
```

### 4.3 SNS 告警邮件停发

1. 确认 SNS 订阅状态为 `Confirmed`：
   ```bash
   SNS_ARN=$(aws cloudformation describe-stacks \
     --stack-name aws-global-security-baseline \
     --region "${AWS_REGION:-us-east-1}" \
     --query 'Stacks[0].Outputs[?OutputKey==`AlertTopicArn`].OutputValue' --output text)
   aws sns list-subscriptions-by-topic --topic-arn "$SNS_ARN" \
     --query 'Subscriptions[].{Endpoint:Endpoint,SubscriptionArn:SubscriptionArn}'
   ```
2. 若状态为 `PendingConfirmation`：重新发送确认邮件（在 SNS Console 操作，或删除订阅后重新部署）
