# 设计文档：AWS Global Account Minimum Security Baseline

## 1. 背景与目标

新开通的 AWS Global 账号默认安全状态薄弱：无审计日志、无威胁检测、无配置合规检查、无告警。本项目以最小成本建立可观测的安全基线，满足以下目标：

- **可审计**：所有管理操作留有日志且不可篡改
- **可检测**：异常行为（root 使用、权限变更、网络变更）触发邮件告警
- **可合规**：覆盖 AWS FSBP 和 CIS 核心检查项
- **低成本**：基础版单账号单 Region 月均 5–30 USD
- **可重跑**：部署脚本幂等，多次运行结果一致

本项目不替代 Control Tower、Organizations SCP、集中日志账号或生产级 Landing Zone，定位为**单账号最小可行安全起点**。

---

## 2. 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Account                              │
│                                                                 │
│  ┌──────────────┐    Management Events    ┌──────────────────┐  │
│  │  CloudTrail  │────────────────────────▶│  S3 Trail Bucket │  │
│  │ (Multi-Reg.) │                         │  (Versioned,     │  │
│  └──────┬───────┘                         │   HTTPS-only,    │  │
│         │ CloudWatch Logs                 │   Glacier 90d)   │  │
│         ▼                                 └──────────────────┘  │
│  ┌──────────────┐   MetricFilters                               │
│  │  CloudWatch  │──────────────────────────────────┐            │
│  │  Log Group   │  root/IAM/CW/SG/NACL/RT/VPC变更  │            │
│  └──────────────┘                                  ▼            │
│                                           ┌──────────────────┐  │
│  ┌──────────────┐   Findings              │   SNS Topic      │  │
│  │  GuardDuty   │────────────────────────▶│  (Email Alerts)  │  │
│  └──────────────┘  severity >= 4          └─────┬────────────┘  │
│                                                 │               │
│  ┌──────────────┐   CRITICAL/HIGH FAILED        │               │
│  │ Security Hub │─────────────────────────────▶│               │
│  │  (FSBP std.) │                               │               │
│  └──────────────┘                               │               │
│                                        EventBridge Rules        │
│  ┌──────────────┐                               │               │
│  │    Config    │──Config Rules──▶ root-mfa,    │               │
│  │  Recorder    │                 s3-public-*   │               │
│  └──────┬───────┘                               │               │
│         │ Snapshots               ┌─────────────▼────────────┐  │
│         ▼                         │  CloudWatch Alarms (9条)  │  │
│  ┌──────────────┐                 └──────────────────────────┘  │
│  │  S3 Config   │                                               │
│  │   Bucket     │  ┌──────────────────────────────────────┐     │
│  └──────────────┘  │  IAM Access Analyzer (ACCOUNT type)  │     │
│                    └──────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

**多 Region 扩展**（可选）：`regional-security-services.yaml` 在额外 Region 独立部署 GuardDuty、Security Hub、Config、Access Analyzer，CloudTrail 的 `IsMultiRegionTrail=true` 确保主 Region 集中收集所有 Region 的管理事件。

---

## 3. 组件设计

### 3.1 CloudTrail

| 配置项 | 值 | 原因 |
|--------|----|------|
| `IsMultiRegionTrail` | `true` | 单 trail 覆盖所有已启用 Region，无需每 Region 各建一条 |
| `IncludeGlobalServiceEvents` | `true` | 捕获 IAM、STS、Route 53 等全球服务事件 |
| `EnableLogFileValidation` | `true` | SHA-256 哈希链，可检测日志是否被篡改 |
| `EventSelectors.ReadWriteType` | `All` | 读写事件全记录，满足合规审计要求 |
| CloudWatch Logs 集成 | 绑定 `/aws/cloudtrail/<name>` | 支持 MetricFilter 实时告警 |

**S3 日志桶加固**：`BucketOwnerEnforced`（禁用 ACL）、四项 Block Public Access、HTTPS-only 桶策略、`AWSCloudTrailWrite` 语句绑定 `aws:SourceArn` 防止 confused-deputy 攻击、Versioning 保留历史版本、90 天后自动转 GLACIER 降低存储成本。

### 3.2 CloudWatch MetricFilter + Alarms

实现 CIS AWS Foundations Benchmark 推荐的 9 类告警，每类触发阈值说明：

| 告警 | 阈值 | 说明 |
|------|------|------|
| `root-usage` | ≥1 次/5min | root 正常不应登录操作 |
| `iam-policy-changes` | ≥1 次/5min | 权限变更需即时感知 |
| `cloudtrail-changes` | ≥1 次/5min | 日志链路变更风险极高 |
| `console-login-failure` | ≥5 次/5min | 暴力破解特征 |
| `unauthorized-api-calls` | ≥5 次/5min | 凭证泄露或误配 |
| `security-group-changes` | ≥1 次/5min | 网络边界变更 |
| `network-acl-changes` | ≥1 次/5min | 网络边界变更 |
| `route-table-changes` | ≥1 次/5min | 路由异常（如数据外泄路径） |
| `vpc-changes` | ≥1 次/5min | VPC 拓扑变更 |

### 3.3 SNS Topic Policy

两条 Allow 语句均带 `aws:SourceAccount` 条件（EventBridge、CloudWatch），防止跨账号发布伪造告警。SNS 本身不加 KMS 加密——邮件通知场景中加密意义有限，且会引入 KMS 调用延迟。

### 3.4 GuardDuty

`FindingPublishingFrequency: FIFTEEN_MINUTES`，通过 EventBridge 规则过滤 `severity >= 4`（中危及以上）发送 SNS，低于此阈值的信息性 finding 不触发邮件，避免告警疲劳。

### 3.5 Security Hub

`EnableDefaultStandards: false`（避免自动开启 CIS v1.4 等可能不适用的标准），仅显式启用 FSBP（AWS Foundational Security Best Practices），覆盖面广且与 AWS 最佳实践保持同步。

### 3.6 AWS Config

`AllSupported: true, IncludeGlobalResourceTypes: true`（仅 Home Region 开启全局资源，额外 Region 设为 false 避免重复计费）。Config 交付通道将快照写入独立 ConfigBucket，`AWSConfigBucketDelivery` 语句绑定 `aws:SourceAccount` 防 confused-deputy。

### 3.7 IAM Access Analyzer

`Type: ACCOUNT`——分析账号内对外部实体（其他账号、匿名主体）开放访问的资源（S3、IAM Role、KMS Key 等），持续检测意外外部共享。

### 3.8 KMS 可选加固（`EnableKmsEncryption=true`）

单 CMK 加密 CloudTrail S3、Config S3、CloudWatch Logs。各服务 KMS 语句均收窄：
- CloudTrail：`aws:SourceArn` 绑定具体 trail ARN
- Config：`aws:SourceAccount` 绑定账号
- CloudWatch Logs：`kms:EncryptionContext:aws:logs:arn` 绑定具体 log group
- S3：`aws:SourceAccount` 绑定账号

同时启用 `BucketKeyEnabled: true`，减少 S3 到 KMS 的 API 调用次数（降低约 99% 的 KMS 请求费）。

---

## 4. 关键设计决策

### 4.1 为什么用 CloudFormation 而非 CDK/Terraform

本项目定位为"开箱即用的最小基线"，目标用户是刚开通账号的工程师。CloudFormation 无额外工具依赖，任何有 AWS CLI 的环境可直接运行，不引入语言运行时或状态文件管理问题。

### 4.2 为什么日志桶不设 Expiration

审计日志删除可能违反合规要求（如 SOC 2、PCI-DSS 要求保留 1–7 年）。仅设 Glacier 转换（90 天）降低存储成本，不设自动删除，由账号 owner 根据保留策略手工决定。

### 4.3 为什么 S3 PAB 和 IAM 密码策略用脚本而非 CFN

这两项是账号级设置（非 Region 级资源），CFN 目前无对应原生资源类型（`AWS::IAM::AccountPasswordPolicy` 不存在）。通过 CLI 设置后，`delete-stack` 不会撤销，清理时需手工执行（见测试手册）。

### 4.4 幂等性保障

部署脚本在 `set -euo pipefail` 下运行，通过：
1. `--no-fail-on-empty-changeset` 确保无变更重跑不中断
2. 部署前探测 GuardDuty/SecurityHub/AccessAnalyzer 是否已存在，避免重复创建报错

---

## 5. 不覆盖范围

以下安全能力超出本基线定位，需单独规划：

| 能力 | 推荐方案 |
|------|----------|
| 多账号集中治理 | AWS Organizations + Control Tower |
| 集中日志归档 | Log Archive 账号 + S3 跨账号复制 |
| 细粒度权限治理 | IAM Identity Center + Permission Sets |
| 网络分层隔离 | VPC + Transit Gateway + Network Firewall |
| 自动修复 | Security Hub 自定义 Action + Lambda |
| 漏洞管理 | Amazon Inspector |
| 数据分类 | Amazon Macie |
| SIEM | Amazon Security Lake + OpenSearch |
