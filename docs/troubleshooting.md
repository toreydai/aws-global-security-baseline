# 排障手册：AWS Global Account Minimum Security Baseline

---

## 一、部署失败

### 1.1 Config Recorder 已存在

**报错**：
```
Resource handler returned message: "Failed to put configuration recorder 'default'
  (Service: Config, Status Code: 400, Request ID: ...)
  Maximum number of configuration recorders: 1"
```

**原因**：账号已有名为 `default` 的 Config Recorder（Control Tower 或手工创建）。

**解决**：部署前检查现有 Recorder 是否满足需求：
```bash
aws configservice describe-configuration-recorders --region "${AWS_REGION:-us-east-1}"
aws configservice describe-configuration-recorder-status --region "${AWS_REGION:-us-east-1}"
```
若已满足，本基线的 Config 部分可跳过——目前模板尚无 Config 跳过参数，需手工将 `ConfigurationRecorder`、`ConfigDeliveryChannel`、`ConfigBucket`、`ConfigBucketPolicy`、`ConfigRole` 及三条 Config Rules 从模板中移除后部署。

---

### 1.2 GuardDuty / SecurityHub / AccessAnalyzer 已存在报错

**报错**：
```
BadRequestException: The request is rejected because a detector already exists.
```

**原因**：脚本探测逻辑判断为"不存在"，但实际已创建（通常是并发操作或控制台手工创建）。

**解决**：手工设置跳过参数再部署：
```bash
aws cloudformation deploy \
  --stack-name aws-global-security-baseline \
  --template-file cloudformation/security-baseline.yaml \
  --region "${AWS_REGION:-us-east-1}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    AlertEmail="${ALERT_EMAIL}" \
    CreateGuardDutyDetector=false \
    CreateSecurityHub=false \
    CreateAccessAnalyzer=false
```

---

### 1.3 IAM 角色名冲突

**报错**：
```
Role with name CloudTrailLogsRole already exists.
```

**原因**：账号曾手工创建同名 Role，或之前部署残留（堆栈删除时 IAM 未清理干净）。

**解决**：
```bash
# 检查 Role 是否被旧堆栈创建
aws iam get-role --role-name CloudTrailLogsRole \
  --query 'Role.Tags'

# 若是残留，手工删除后重新部署
aws iam delete-role --role-name CloudTrailLogsRole
```

---

### 1.4 S3 BucketAlreadyOwnedByYou / BucketAlreadyExists

**报错**：
```
BucketAlreadyOwnedByYou: Your previous request to create the named bucket succeeded
```
或
```
BucketAlreadyExists: The requested bucket name is not available
```

**原因**：CloudFormation 生成随机 bucket 名，正常不会冲突。通常是残留桶未删除，或 `DeletionPolicy: Retain` 导致旧桶仍存在。

**解决**：
```bash
# 查找残留桶
aws s3api list-buckets --query "Buckets[?contains(Name,'aws-global-security-baseline')].Name" --output text

# 若是空桶残留，直接删除
aws s3api delete-bucket --bucket <bucket-name> --region "${AWS_REGION:-us-east-1}"
```
若桶有内容，参考测试手册的清理步骤清空后删除，再重跑部署。

---

### 1.5 CloudTrail 无法写入 S3

**报错**（`get-trail-status` 返回）：
```
LatestDeliveryError: "delivery failed: insufficient permissions to access S3 bucket"
```

**原因**：桶策略中 `AWSCloudTrailWrite` 的 `aws:SourceArn` 与 TrailName 参数不匹配，或桶策略未正确部署。

**解决**：
```bash
# 检查 bucket policy 中的 SourceArn
TRAIL_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aws-global-security-baseline \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'Stacks[0].Outputs[?OutputKey==`TrailBucketName`].OutputValue' --output text)
aws s3api get-bucket-policy --bucket "$TRAIL_BUCKET" --query 'Policy' --output text | \
  python3 -m json.tool | grep -A3 "AWSCloudTrailWrite"

# 重新部署（通常可修复策略同步问题）
bash scripts/deploy.sh
```

---

### 1.6 KMS 加密部署循环依赖

**报错**：
```
Circular dependency between resources: [SecurityLogsKey, AccountTrail, TrailBucket]
```

**原因**：KMS Key Policy 中使用了 `!Ref AccountTrail` 获取 trail ARN——本模板通过使用 `TrailName` **参数**（而非资源引用）构造 ARN 来绕开此循环依赖。若手工修改模板引入了 `!Ref AccountTrail`，则会触发此错误。

**解决**：将 KMS Key Policy 中的 trail ARN 改回使用参数构造：
```yaml
aws:SourceArn: !Sub 'arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${TrailName}'
```

---

### 1.7 Budget 部署失败（账号未激活 Billing）

**报错**：
```
SubscriptionRequiredException: Your account must be subscribed to use AWS Budgets
```

**原因**：新账号或沙箱账号的 Billing 功能未激活。

**解决**：在 AWS Billing Console 激活 Cost Explorer，等待约 24 小时后重试。或将 `MONTHLY_BUDGET_AMOUNT` 保持为 0 跳过预算创建。

---

## 二、部署后运行异常

### 2.1 SNS 告警邮件收不到

**排查步骤**：

```bash
SNS_ARN=$(aws cloudformation describe-stacks \
  --stack-name aws-global-security-baseline \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'Stacks[0].Outputs[?OutputKey==`AlertTopicArn`].OutputValue' --output text)

# 检查订阅状态
aws sns list-subscriptions-by-topic --topic-arn "$SNS_ARN" \
  --query 'Subscriptions[].{Protocol:Protocol,Endpoint:Endpoint,SubscriptionArn:SubscriptionArn}'
```

| 症状 | 原因 | 解决 |
|------|------|------|
| `SubscriptionArn: PendingConfirmation` | 未点击邮件确认链接 | 检查垃圾邮件，或删除订阅后重新部署触发重发 |
| `SubscriptionArn: arn:aws:sns:...` 正常但无邮件 | EventBridge 规则未触发，或告警未进入 ALARM 状态 | 用告警联动测试（见测试手册 §3）验证链路 |
| 订阅不存在 | 堆栈部署时邮件地址参数传错 | 更新堆栈传入正确邮件：`bash scripts/deploy.sh` |

---

### 2.2 CloudWatch Alarm 持续 INSUFFICIENT_DATA

**原因**：MetricFilter 所依赖的 CloudTrail Log Group 尚未收到任何事件，Namespace 下还没有数据点。

**解决**：属正常状态，等待第一条管理事件写入 CloudWatch Logs（通常几分钟内）。可手工触发一次 API 调用产生事件：
```bash
aws iam get-account-summary > /dev/null
```
等待约 5 分钟后检查 Alarm 状态是否变为 `OK`。

---

### 2.3 Config Rules 状态为 INSUFFICIENT_DATA

**原因**：Config Recorder 刚启动，尚未完成首次资源快照（可能需要数分钟至 30 分钟）。

**解决**：等待后重查：
```bash
aws configservice describe-config-rule-evaluation-status \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'ConfigRulesEvaluationStatus[].{Name:ConfigRuleName,LastAttempt:LastSuccessfulEvaluationTime}'
```
若长时间（>1 小时）仍无评估结果，检查 Config Recorder 是否在录制（见运维手册 §4.2）。

---

### 2.4 Security Hub FSBP 标准长期 INCOMPLETE

**正常情况**：首次启用后扫描需 数分钟 ~ 数小时，`INCOMPLETE` 属正常过渡状态。

**异常情况**：超过 24 小时仍为 `INCOMPLETE`：

```bash
# 检查标准状态
aws securityhub get-enabled-standards --region "${AWS_REGION:-us-east-1}" \
  --query 'StandardsSubscriptions[].{Arn:StandardsSubscriptionArn,Status:StandardsStatus,Reason:StandardsStatusReason}'
```

若 `StatusReason` 包含权限错误，Security Hub 服务关联角色可能缺失：
```bash
aws iam get-role --role-name AWSServiceRoleForSecurityHub 2>&1
# 若不存在，Security Hub 在账号级别重新启用一次即可自动创建
```

---

### 2.5 幂等重跑后账号级 PAB / 密码策略被重置

**原因**：`deploy.sh` 每次运行都会调用 `s3control put-public-access-block` 和 `iam update-account-password-policy`，**这是预期行为**（确保漂移被修正）。

若账号其他系统依赖不同的密码策略，需在脚本顶部调整参数，或在 Control Tower SCP 层面统一管理，不由本脚本覆盖。

---

## 三、清理失败

### 3.1 delete-stack 卡在 DELETE_IN_PROGRESS

**原因**：日志桶非空，CFN 无法删除（`DeletionPolicy: Retain` 会跳过，但若 Policy 被手工改掉则会尝试删除并失败）。

**解决**：先手工清空桶，参考测试手册 §4.1 的清空步骤，再重试删除堆栈。

```bash
# 查看堆栈卡住的资源
aws cloudformation describe-stack-events \
  --stack-name aws-global-security-baseline \
  --region "${AWS_REGION:-us-east-1}" \
  --query 'StackEvents[?ResourceStatus==`DELETE_FAILED`].{Resource:LogicalResourceId,Reason:ResourceStatusReason}' \
  --output table
```

### 3.2 S3 桶删除报 BucketNotEmpty

桶版本控制开启后，`aws s3 rm --recursive` 只删除当前版本，历史版本和 delete markers 仍存在。

```bash
BUCKET=<bucket-name>
REGION="${AWS_REGION:-us-east-1}"

# 分页删除所有版本（含 delete markers）
python3 - <<'PY'
import subprocess, json, sys

BUCKET = sys.argv[1] if len(sys.argv) > 1 else ""
if not BUCKET:
    print("Usage: python3 script.py <bucket-name>"); sys.exit(1)

paginator_cmd = ["aws","s3api","list-object-versions","--bucket",BUCKET,"--output","json"]
r = subprocess.run(paginator_cmd, capture_output=True, text=True)
data = json.loads(r.stdout or '{}')
objs = []
for key in ("Versions","DeleteMarkers"):
    for item in (data.get(key) or []):
        objs.append({"Key": item["Key"], "VersionId": item["VersionId"]})

if objs:
    r2 = subprocess.run(
        ["aws","s3api","delete-objects","--bucket",BUCKET,"--delete",json.dumps({"Objects":objs}),"--output","json"],
        capture_output=True, text=True)
    result = json.loads(r2.stdout or '{}')
    print(f"Deleted: {len(result.get('Deleted',[]))}, Errors: {len(result.get('Errors',[]))}")
else:
    print("No versioned objects found")
PY
# 调用方式
python3 - $BUCKET <<< "" 2>/dev/null || python3 -c "
import subprocess,json
BUCKET='$BUCKET'
r=subprocess.run(['aws','s3api','list-object-versions','--bucket',BUCKET,'--output','json'],capture_output=True,text=True)
data=json.loads(r.stdout or '{}')
objs=[{\"Key\":i[\"Key\"],\"VersionId\":i[\"VersionId\"]} for k in ('Versions','DeleteMarkers') for i in (data.get(k) or [])]
if objs: subprocess.run(['aws','s3api','delete-objects','--bucket',BUCKET,'--delete',json.dumps({'Objects':objs})])
print(f'Cleared {len(objs)} objects')
"

aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" && echo "Deleted"
```
