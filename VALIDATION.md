# v0.1.0 验证记录

2026-10-23（Asia/Shanghai），在发布前完成：

- 管理器生命周期测试：多节点独立安装、指定节点更新、失败与中断自动回退、
  手动回退、通讯密钥变更失败恢复、证书变更失败恢复、保留配置卸载与恢复。
- 引导脚本真实执行测试：正确摘要可执行，篡改后的管理器在执行前被拒绝。
- 路径、URL、节点 ID、发布版本、协议识别、进程归属端口检查、凭据脱敏测试。
- 固定源码应用两个维护补丁后，config、cert、service、Xray、sing-box、tracker、
  panel 七个包的 `go test -race -count=1` 通过。
- Linux AMD64 与 ARM64 两个实际构建程序，分别在 `--network none` Docker 容器内
  测试 VLESS、VMess、Trojan、SS、HY2、TUIC、AnyTLS；每种协议的实际合成客户端
  都成功代理到容器内 HTTP 目标。TLS 使用容器内自签测试 CA/证书，由客户端显式
  信任；未关闭客户端证书校验，未使用真实客户 UUID 或证书。
- TLS 协议故意收到面板 `cert_config: none`，本地证书优先策略仍生效。
- 没有修改、重启正式 36 号节点、XBoard 面板、其他落地节点或 sign 应用。

GitHub Ubuntu CI 已完成全部 33 项管理器/引导检查，包括真实 systemd-analyze
解析服务单元；七个 Go 包竞态测试和双架构七协议合成请求均成功。
[首次发布运行](https://github.com/LUHANG0/xbnode-tools/actions/runs/39818982539)
的 build / publish 两个任务均成功，发布了 v0.1.0。

这些检查不等于新主机公网接入验收：云安全组、中转映射、运营商网络、真实客户
连接及生产域名的公开 CA 证书签发/续期，需要在目标主机核验。本轮没有申请真实
域名证书或联系外部 ACME CA。跨节点全局设备总数限制不在本次实现范围。
