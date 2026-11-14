# ssh-key-policy-auditor

Python SSH 公钥授权静态审计库。输入用户清单、主目录、sshd_config（含 Include
拆分文件）、authorized_keys 授权文件和待审计的连接上下文，计算出**某个用户从
指定来源连接时 sshd 真正会加载哪些 key 文件、每把 key 的最终能力**，并把同一
把 key 在不同账户 / 不同文件中的出现关联起来。

## 快速开始

```python
from ssh_key_policy_auditor import Auditor, ConnectionContext, UserRecord

users = [
    UserRecord("alice", "/home/alice", groups=("ops",)),
    UserRecord("root", "/root"),
]
auditor = Auditor(users, "/etc/ssh/sshd_config")
report = auditor.audit([
    ConnectionContext("alice", source_address="192.0.2.10",
                      source_host="ws.example.com"),
    ConnectionContext("root", source_address="203.0.113.9"),
])
data = report.to_dict()   # 稳定、可 JSON 序列化
```

`report.to_dict()` 包含：

- `users[]`：每个连接上下文的生效配置（`effective_config`）、实际加载的
  key 文件（`loaded_files`）、解析出的 key（含逐处 options）和风险列表。
- `fingerprint_index`：指纹 → 出现位置（用户 / 文件 / 行号 / 是否受限），
  基于哈希索引，不做两两字符串比较，也不缓存原始行。
- `diagnostics`：结构化诊断（见下）。

## 支持的 sshd_config 指令

| 指令 | 说明 |
| --- | --- |
| `Include` | 支持 glob、相对路径（相对于包含它的文件）、多级嵌套；悬空 Include 与循环 Include 进入诊断 |
| `Match` | 支持 `User` / `Group` / `Host` / `Address` / `LocalAddress` / `LocalPort` 条件、`all`、逗号分隔模式、`!` 取反、CIDR 网段 |
| `AuthorizedKeysFile` | 多路径；展开 `%%`、`%h`、`%u`、`%r`；相对路径落到用户主目录；默认值 `.ssh/authorized_keys .ssh/authorized_keys2` |
| `PubkeyAuthentication` | yes/no，默认 yes |
| `PermitRootLogin` | 默认 `prohibit-password`；`no` 时 root 公钥登录判定为不允许 |
| `AllowAgentForwarding` | yes/no，默认 yes |
| `AllowTcpForwarding` | yes/no/local/remote，默认 yes |

语义遵循 OpenSSH：**标量指令首次出现的值生效**（first obtained value wins），
因此文件顶部的全局设置会压过后面的 Match 块——这正是生产上"Match 块必须放
文件末尾"的原因。未知指令记为 info 级诊断后忽略，不影响其余解析。

## authorized_keys 解析

- 完整的 options 解析器：正确处理引号、反斜杠转义、逗号分隔、带空白的
  `command="..."`，绝不按空白粗暴切分。
- 支持 `@cert-authority` / `@revoked` 行首标记与 `cert-authority` 选项。
- 支持 `ssh-ed25519`、`ssh-rsa`、`ecdsa-sha2-nistp256/384/521`；解码 base64
  blob 后计算 OpenSSH 风格 `SHA256:` 指纹。
- 同一指纹在不同账户 / 文件中分别保留各自的 options，并聚合进指纹索引。

## 风险规则

| 代码 | 含义 |
| --- | --- |
| `NO_COMMAND` | key 无 `command=` 强制命令约束 |
| `BROAD_SOURCE` | 无 `from=` 或来源范围过宽（`*`、`0.0.0.0/0`、小于 /8（v4）或 /32（v6）的网段） |
| `PERMITOPEN_ANY` | `permitopen` 允许任意目标（`*`、空主机或通配端口） |
| `AGENT_FORWARDING` | 该 key 最终允许 agent forwarding（配置与 key options 共同判定） |
| `TCP_FORWARDING` | 该 key 最终允许 TCP 转发且未被 `permitopen` 限定 |
| `ROOT_LOGIN` | `PermitRootLogin` 允许 root 公钥登录 |
| `CERT_AUTHORITY` | key 被当作证书颁发机构信任 |
| `CROSS_ACCOUNT` | 同一指纹出现在多个账户 |
| `MIXED_RESTRICTION` | 同一指纹同时存在受限与不受限版本 |

key 级转发能力按顺序折叠：`restrict` 先全部关闭，后续显式选项再逐项打开，
并与全局 `AllowAgentForwarding` / `AllowTcpForwarding` 取与。

## 诊断代码

`BAD_BASE64`、`UNKNOWN_ALGORITHM`、`UNKNOWN_MARKER`、`BAD_OPTION`、
`PARSE_ERROR`、`DANGLING_INCLUDE`、`INCLUDE_CYCLE`、`INVALID_MATCH`、
`MISSING_CONFIG`、`MISSING_AUTH_FILE`、`UNKNOWN_TOKEN`、`INVALID_VALUE`、
`UNKNOWN_DIRECTIVE`(info)、`UNKNOWN_USER`。单个坏文件 / 坏行只会产生诊断，
不会吞掉其他结果。

## 与真实 SSH 行为的差异

- 相对路径的 `Include` 相对于**包含它的文件**解析；真实 sshd 对系统配置
  相对于 `/etc/ssh` 解析。
- `AuthorizedKeysFile` 额外支持 `%r`（按用户名展开）；真实 sshd 此处仅支持
  `%%`、`%h`、`%u`。
- 不实现 `Match canonical` / `Match final` / `Match exec`，也不做主机名
  正反向 DNS 解析；`Host` 匹配依赖调用方提供的 `source_host`。
- 不支持证书主体（principals）求值、`AuthorizedKeysCommand`、
  `AuthenticationMethods` 等；未列出的指令一律忽略并记 info 诊断。
- `AllowTcpForwarding local/remote` 只区分 `no` 与非 `no`，不细分方向。
- 文件权限 / 属主（StrictModes）不在审计范围内。

## 测试

```sh
python -m unittest
```

覆盖多级 Include、相互覆盖的 Match、带引号 options、from 网段、重复指纹、
跨账户复用、CertAuthority、10 万级 key 的线性性能与输出稳定性。
