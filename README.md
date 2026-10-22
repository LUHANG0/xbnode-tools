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

先发布下面所述的 `v0.1.0` Release。当前仓库为 `LUHANG0/xbnode-tools`；fork 后请替换为自己的仓库：

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
xbnode update 41 --release v0.2.0    # 示例：只有目标 Release 发布后才可使用
xbnode update-all --release v0.2.0   # 逐个更新，首个失败即停止后续操作
xbnode rollback 41
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

在线设备按来源 IP 去重，不是物理设备/UDID。维护补丁保留在线 IP 周期刷新和
单节点限额修复，没有新增跨节点全局设备总数限制。

## 自己发布首个版本

1. 将整个目录（含 `.github`、`.gitignore`）上传到一个独立公开仓库根目录。
2. 默认分支使用 `main`。代码推送触发管理器测试。
3. 创建并推送标签 `v0.1.0`。Actions 会校验固定源码、应用补丁、跑 Go 竞态测试，
   构建 AMD64/ARM64，并在无外网容器内跑七协议的合成客户端请求。
4. 检查 `Build and publish xbnode` 全部成功，Release 出现后才使用安装命令。

手动运行 workflow_dispatch 只构建和测试，不发布。标签发布不覆盖已有 Release
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

`release.json` 固定上游提交、Go 工具链与构建选项；`patches/` 保存维护变更。
更新版本时同步修改 `release.json`、`xbnode.py` 的 VERSION、`install.sh` 的固定
版本和发布说明。不得静默追随 upstream latest 覆盖维护补丁。

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
