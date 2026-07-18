# AWS Global Account Minimum Security Baseline

新开通 AWS Global 账号的最小安全基线。低成本启用审计、检测、配置合规和关键告警，不替代 Control Tower 或生产级 Landing Zone。

## 基线内容

| 类别 | 内容 |
| --- | --- |
| 审计 | CloudTrail（Multi-Region、日志完整性校验）→ S3 + CloudWatch Logs |
| 检测 | GuardDuty、Security Hub FSBP、IAM Access Analyzer |
| 配置合规 | AWS Config + root MFA 规则、S3 公开访问规则 |
| 告警 | 9 条 CloudWatch Alarm（root 使用、IAM 变更、网络变更等）→ SNS Email |
| S3 防护 | 日志桶 HTTPS-only、Versioning、90 天转 Glacier，账号级 Block Public Access |
| 身份 | IAM 密码策略（14 位、90 天、24 次复用限制） |

可选增强：`ENABLE_KMS_ENCRYPTION=true` 加密所有日志，`MONTHLY_BUDGET_AMOUNT=<N>` 开启预算告警，`ENABLE_REGIONS` 向多 Region 扩展。

## 快速开始

```bash
cd aws-global-security-baseline
aws sts get-caller-identity          # 确认账号身份

export AWS_REGION=us-east-1
export ALERT_EMAIL=your@email.com
bash scripts/deploy.sh
```

部署后**必须确认 SNS 邮件订阅**，否则告警邮件不会发出。

## 手工必做

1. Root 用户开启 MFA
2. 删除或确认不存在 root access key
3. 启用 IAM Identity Center，日常操作不使用 root 或长期 IAM 用户

## 目录结构

```
cloudformation/
  security-baseline.yaml          # Home Region 主基线
  regional-security-services.yaml # 额外 Region 扩展
scripts/
  deploy.sh                       # 部署主基线
  enable-regional-services.sh     # 扩展到额外 Region
docs/
  architecture.md                 # 架构图与整体拓扑
  design.md                       # 架构与设计决策
  testing.md                  # 验证与测试文档
  runbook.md                      # 告警响应与运维操作
  troubleshooting.md              # 常见问题排障
```

## 成本参考（单账号、单 Region、低流量）

基础版 **5–30 USD/月**；启用 KMS、增加 Region、Config 资源变更多时费用上浮。

## 清理

```bash
# 先手工清空日志桶（DeletionPolicy: Retain），再删除堆栈
aws cloudformation delete-stack \
  --stack-name aws-global-security-baseline \
  --region "${AWS_REGION:-us-east-1}"
```

详细清理步骤（含账号级密码策略和 PAB 回滚）见 [docs/testing.md](docs/testing.md)。

## 参考文档

- [架构文档](docs/architecture.md)
- [设计文档](docs/design.md)
- [测试文档](docs/testing.md)
- [Runbook（告警响应）](docs/runbook.md)
- [排障手册](docs/troubleshooting.md)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/framework/security.html)
- [Security Hub FSBP](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html)

## License

MIT - see the [LICENSE](LICENSE) file for details.

## 免责声明

- 本项目仅供学习与技术参考，不构成生产部署方案。
- 运行过程中会创建 AWS 资源并产生费用，请在实验结束后及时清理。
- 作者不对因使用本项目产生的任何费用或损失承担责任。
- 本项目与 Amazon Web Services 无官方关联，相关服务的可用性与定价以 AWS 官方文档为准。
- 生产环境使用前请根据实际需求进行安全评估与调整。
