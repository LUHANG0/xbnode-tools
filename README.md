# xbnode-tools

Xboard-Node 中文安装与管理工具。把本目录作为独立仓库根目录，运行自己的
GitHub Actions 构建，程序从自己的 GitHub Releases 下载。

支持 VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC、AnyTLS；每个节点
使用独立的 `xbnode-ID.service`。从面板只读识别协议、服务端口与可用用户，
不会创建客户、修改套餐、节点权限或面板数据库。

## 新机器安装

支持运行 systemd 247+ 的 Linux AMD64 / ARM64，例如 Debian 12、Ubuntu 22.04+。
安装前在面板创建一个新的节点 ID，设置好协议、服务端口、权限组，并至少有一个
可用用户。零用户时上游不会启动内核，本工具会在安装前说明并停止。

本版本为 [v0.2.1](https://github.com/LUHANG0/xbnode-tools/releases/tag/v0.2.1)；正式安装前先确认该 Release 的两架构资产与 SHA256SUMS 已完整发布。fork 后请先在自己的仓库完成发布，并替换仓库名称：

```bash
# Debian / Ubuntu，root 执行
apt-get update
apt-get install -y python3 curl ca-certificates iproute2

curl -fL --retry 3 \
  https://raw.githubusercontent.com/LUHANG0/xbnode-tools/main/install.sh \
  -o /root/install-xbnode.sh
bash /root/install-xbnode.sh --repo LUHANG0/xbnode-tools
```

安装器验证管理脚本和发布清单的 SHA-256，然后安装 `xbnode` 命令。
菜单选择「添加节点」，按提示选择/填写 HTTPS 面板根地址、隐藏输入服务器通讯
密钥、填写新节点数字 ID。面板地址不带 `/admin` 或 `#/` 后台路径。

系统没有 systemd、主机架构不支持、端口冲突、面板认证失败、协议不支持或缺少
必要 REALITY 参数时，会显示错误并停止；不会自动停掉 XrayR 或占用端口的程序。
安装失败的本工具服务会停用，配置保留排查。

安装完成后放行云安全组及系统防火墙的相应服务端口。有中转时，连接入口与后端
监听的转发关系由你配置；普通 Cloudflare 橙云不代理这些节点的原始 TCP/UDP。
最后用有权限的自用账号实际连接，验证访问、流量和设备更新。

## 日常管理

```bash
xbnode                    # 中文菜单
xbnode list               # 查看本工具管理的所有节点
xbnode add                # 同机继续添加节点
xbnode logs 41            # 最近 60 行，已对已知通讯密钥和认证 URL 脱敏
xbnode restart 41
xbnode stop 41
xbnode start 41
xbnode update 41 --release v0.2.1
xbnode update-all --release v0.2.1   # 逐个更新，首个失败即停止后续操作
xbnode rollback 41
xbnode diagnose 41 --json # 本机诊断，缺失数据为 null
xbnode prune              # 旧程序与快照清理预览
xbnode prune --apply      # 显示候选后仍须输入 yes 确认
xbnode connection 41      # 修改此节点面板连接，不改其他节点凭据
xbnode uninstall 41       # 卸载服务，保留配置、证书和恢复快照
xbnode restore 41
```

第一版卸载只提供保留配置模式，不自动清除证书/备份或面板记录。手工直接操作
systemctl 不受本工具事务锁保护，维护时请避免与 xbnode 并行更改同一服务。

菜单优先显示服务运行状态；运行状态不等于客户端已经可用。安装/更新会同时检查
用户加载和**属于该进程**的 TCP/UDP 监听，WS 与 REST 启动日志均可识别。
客户端连接、流量与设备上报仍需要实际使用验证。失败更新与被中断的更新会恢复
原程序和配置；只更新所选节点。

列表的协议/端口是安装时快照。第一版程序更新会在后台协议/端口与安装记录不同
时拒绝操作，避免把程序更新当成配置迁移。需要改变线路协议或端口时，建议新建
节点 ID 并接入，实测通过后再停用旧节点；同 ID 的配置迁移需单独维护。

## TLS 与证书

- REALITY 和不使用 TLS 的节点不用申请普通证书，REALITY 参数从面板读取。
- TLS 节点可使用已有 PEM 证书/私钥，文件会复制到本工具受限目录，由 systemd
  LoadCredential 交给非 root 服务。第一版文件模式是快照，外部原证书续期后需用
  `xbnode certificate ID` 更新本工具副本，不会自动读取外部变化。
- 自动签发使用 Let's Encrypt HTTP-01，需要正确域名解析、公网 TCP 80 可达且
  没有其他程序占用；在显示当前协议链接并获得用户明确同意后才开始签发。
  证书由节点内置 CertMagic 管理续期；运行数据目录需持久保留。
- `prefer_local` 维护补丁使安装时选择的证书策略保持明确，不受面板默认的
  `cert_config: none` 覆盖。第一版没有配置 DNS-01 签发或付费 DNS/CDN 服务。
- 云防火墙、外部证书可信链及真实域名的公网签发，需要在目标主机实际核验。

## 协议与内核

| 面板协议 | 默认内核 | 典型监听 |
| --- | --- | --- |
| VLESS / VMess / Trojan | Xray | TCP；KCP/QUIC 传输按 UDP 检查 |
| Shadowsocks | Xray | TCP + UDP |
| Hysteria2 / TUIC | sing-box | UDP |
| AnyTLS | sing-box | TCP |

一个 ID 只能在本工具中安装一次；同机多协议应创建多个面板节点并使用不同端口。
不要复用另一台机器正在运行的节点 ID。面板明确指定不一致的 `kernel_type` 时，
先在后台核对，安装器不会猜测或悄悄覆盖。

在线设备按来源 IP 去重，不是物理设备/UDID。保留 v0.1.1 的 TCP/UDP 原子名额、同 IP 多连接和会话结束释放能力。`device_limit=0` 为不限，降低限额不会主动踢掉存量连接；面板设备快照仅作附加限制，不承诺跨节点原子总数。

v0.2.1 在用户被权威有效列表/删除事件撤销或 UUID 更换时，结束该旧身份的活动代理流，保留其他用户。HY2/TUIC 使用固定用户名作为 QUIC 会话身份，关闭被撤销的 QUIC 会话，重排用户不会把旧会话记到另一用户。Xray 保留 mux/XUDP 的原 Reader 类型，通过原句柄中断被撤销的用户。面板超时、503、无效响应及 WS 断线不当作全员撤销。

退役统计先把流量交给可重试的上报链路，再释放注册表；迟到的计数回调仍归入原用户。发送前写本地 0600 待发送文件，失败恢复并可在重启后继续。面板没有幂等键，服务端已接收但响应丢失时可能重复上报；这是至少一次交付，不保证 exactly-once。硬杀前尚未采样的内核流量仍可能丢失。不要手工删除运行目录中的 `pending-traffic-*.json`。

本机诊断读取实际 `/proc/PID/exe` 的版本与摘要、CPU、RSS/PSS/cgroup、句柄、监听归属和本轮日志的加载/上报时间；仅输出允许字段。没有权限或日志不足显示未知/JSON null，服务 active 不表示客户连接已验收。可只读诊断手工部署的服务：

```bash
python3 xbnode.py diagnose --service xboard-node-36.service --port 30000 --transport tcp --json
```

诊断不接管服务、不显示环境变量/客户端地址/UUID/原日志，不增加监听或常驻采样进程，不设置压低 RSS 的内存限制。AnyTLS 已有会话池可能等到其空闲结束，已撤销身份的代理流会结束，新流会被拒绝；池中的空闲传输不能再获得有效代理权限。

清理默认只预览，默认至少保留最近 2 个版本、每节点最近 3 份快照；可用 `--keep-releases`、`--keep-snapshots`、重复的 `--pin vX.Y.Z` 或 settings.json 的 `pinned_releases` 调整保护。运行程序、服务文件、当前配置及所有快照中的回退引用始终优先保护，引用链可能使保留量高于给定数量。读取不完整/引用异常时停止或保护全部版本，不跟随管理目录外的符号链接。只清理本工具的程序/快照，不处理运行状态、证书或业务数据；本轮没有在生产清理历史文件。

已用旧版管理器安装的节点，先更新到新版管理器以获得诊断/清理入口；原管理器仍可执行单节点程序升级：

```bash
xbnode update 41 --release v0.2.1
```

原配置、凭据、证书及失败/中断恢复保持。该命令只操作 `xbnode-ID.service`；手工部署的 36 号服务需要独立备份和受控替换，不自动接管。

## 自己发布首个版本

1. 将整个目录（含 `.github`、`.gitignore`）上传到一个独立公开仓库根目录。
2. 默认分支使用 `main`。代码推送触发管理器测试。
3. 创建并推送未使用的标签 `v0.2.1`。Actions 会校验固定源码、应用补丁、跑 Go 竞态测试，
   构建 AMD64/ARM64，并在无外网容器内跑七协议的合成客户端请求、同 IP 继续连接、
   新 IP 超额拒绝和断开后名额复用，另有真实 UDP 目标、用户重排/撤销/UUID 更换、mux/XUDP 与 REALITY+Vision。
4. 检查 `Build and publish xbnode` 全部成功，Release 出现后才使用安装命令。

手动运行 workflow_dispatch 并选择 main 时只构建和测试；选择已存在的版本标签
也可以发布对应版本。标签发布不覆盖已有 Release
资产；修复后发新版本。无需把自己的服务器通讯密钥放进 GitHub Secrets。

Release 包含：两个架构程序、管理脚本、安装入口、清单、SHA256SUMS、许可证、
来源说明和完整修改后的源码归档。第一版在线引导仅支持公开 Releases；私有仓库
需要另行设计认证下载，不要把个人访问令牌写进安装 URL。

## 本地开发与验证

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
python3 tools/build.py        # 需要 Go 1.26.10、Git 和 C 编译器（竞态测试）
bash tools/test-protocols.sh  # 需要 Docker，无外网容器，合成面板/账号/证书
python3 tools/package.py /tmp/xbnode-tools-source.tar.gz
```

当前验证范围与证据见 [VALIDATION.md](VALIDATION.md)。`tests/stability_soak.py` 支持固定 1800 秒原生 ARM64 旧/新版本对照，采样内存、CPU、句柄、连接/对象与流量，期间模拟面板和上报 503/恢复。只在 `--network none` 容器中用合成材料运行，不访问生产客户。

`release.json` 固定上游提交与 Go 工具链；原四份维护补丁继续保留，新增生命周期补丁。`overlays/lock.json` 固定受影响依赖的版本和每个原文件摘要，构建把它们复制到独立源码目录后应用替换文件；不修改共享模块缓存。`go.mod`/`go.sum` 保持上游原文件，专用 `maintenance.mod` 仅用相对路径指向包内完整修改后的依赖。发布源码归档可以用 `go build -modfile=maintenance.mod` 配合 manifest 的 tags/版本参数重建。原 v0.1.0/v0.1.1 标签和资产保持。

更新版本时同步 `release.json`、`xbnode.py` 的 VERSION、`install.sh` 的固定版本和发布说明，不追随 upstream latest 覆盖维护补丁。

## 本机文件

```text
/etc/xbnode/settings.json             # 默认下载仓库
/etc/xbnode/panels/                   # 面板凭据，root 受限访问
/etc/xbnode/node-ID/                  # 节点配置和凭据
/etc/xbnode/backups/                  # 更新/卸载恢复快照
/usr/local/lib/xbnode/releases/       # 按版本保存的程序
/usr/local/bin/xbnode                 # 本地入口
/var/lib/xbnode-ID/                   # 持久运行数据、ACME 状态
```

配置采用 JSON 文本保存为 `.yml`，JSON 是上游 YAML 解码器接受的格式；使用标准
JSON 转义，避免把配置值插入 Shell。运行服务采用 DynamicUser、LoadCredential、
只读系统、独立状态目录，只有低端口/HTTP-01 才授予绑定低端口的 capability。
不开放额外公网健康端口，不修改共享主机防火墙、DNS 或已有其他节点服务。

本工具是新机器接入工具，不会自动接管先前手工部署的 36 号节点或其他 XrayR。
真实主机迁移应另行备份、映射端口及验证客户连接。

许可证和上游来源见 [LICENSE](LICENSE)、[NOTICE](NOTICE)。
