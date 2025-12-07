# eCapture SSL模块Hook函数快速参考

## Hook函数速查表

### 用户空间libssl函数（uprobe）

| 函数名 | Hook类型 | 用途 | 适用模式 |
|--------|---------|------|----------|
| `SSL_write` | uprobe + uretprobe | 捕获发送的明文数据 | Text |
| `SSL_read` | uprobe + uretprobe | 捕获接收的明文数据 | Text |
| `SSL_set_fd` | uprobe | 关联SSL对象与文件描述符 | Text |
| `SSL_set_rfd` | uprobe | 设置读文件描述符 | Text |
| `SSL_set_wfd` | uprobe | 设置写文件描述符 | Text |
| `SSL_get_wbio` | uprobe | 捕获TLS主密钥（首选） | Keylog, Pcap |
| `SSL_in_before` | uprobe | 捕获TLS主密钥（备选） | Keylog, Pcap |
| `SSL_do_handshake` | uprobe | 捕获TLS主密钥（备选） | Keylog, Pcap |
| `SSL_in_init` | uprobe | 捕获TLS主密钥（BoringSSL） | Keylog, Pcap |

### 内核函数（kprobe）

| 函数名 | Hook类型 | 用途 | 适用模式 |
|--------|---------|------|----------|
| `__sys_connect` | kprobe + kretprobe | 追踪客户端连接 | Text |
| `inet_stream_connect` | kprobe | inet层连接追踪 | Text |
| `__sys_accept4` | kprobe + kretprobe | 追踪服务端接受连接 | Text |
| `inet_accept` | kprobe | inet层accept追踪 | Text |
| `tcp_v4_destroy_sock` | kprobe | 追踪连接销毁 | Text |
| `tcp_sendmsg` | kprobe | 捕获TCP发送包 | Pcap |
| `udp_sendmsg` | kprobe | 捕获UDP发送包（DTLS） | Pcap |

### TC程序

| 类型 | 用途 | 适用模式 |
|------|------|----------|
| TC Egress | 捕获出口流量 | Pcap |
| TC Ingress | 捕获入口流量 | Pcap |

## 按模式分类

### Text模式 - 捕获明文数据

**核心Hook函数**：
- `SSL_write` / `SSL_read` - 数据捕获
- `SSL_set_fd` 系列 - 文件描述符映射
- `__sys_connect` / `__sys_accept4` - 连接追踪
- `tcp_v4_destroy_sock` - 连接清理

### Keylog模式 - 导出密钥

**核心Hook函数**：
- `SSL_get_wbio` - 主密钥捕获（首选）
- `SSL_in_before` - 主密钥捕获（备选）
- `SSL_do_handshake` - 主密钥捕获（备选）

**特殊版本**：
- BoringSSL: `SSL_in_init`
- OpenSSL 1.0.x: `SSL_state` (替代 `SSL_in_before`)

### Pcap模式 - 流量+密钥

**核心Hook函数**：
- `SSL_get_wbio` / `SSL_in_before` / `SSL_do_handshake` - 密钥捕获
- `tcp_sendmsg` / `udp_sendmsg` - 流量捕获
- TC Egress / Ingress - 网络接口流量捕获

## 主密钥捕获函数选择逻辑

```
                      是BoringSSL?
                     /           \
                   是              否
                   |               |
            SSL_in_init     是OpenSSL 1.0.x?
                              /         \
                            是           否
                            |            |
                       SSL_state    SSL_get_wbio
                                    SSL_in_before
                                    SSL_do_handshake
```

## 重要代码位置

### Go代码
- 主模块: `user/module/probe_openssl.go`
- Text模式: `user/module/probe_openssl_text.go`
- Keylog模式: `user/module/probe_openssl_keylog.go`
- Pcap模式: `user/module/probe_openssl_pcap.go`
- 常量定义: `user/module/const.go`

### eBPF代码
- 通用头文件: `kern/openssl.h`
- 主密钥捕获: `kern/openssl_masterkey.h`
- 版本相关: `kern/openssl_*.c`, `kern/boringssl_*.c`

## 性能考虑

### 高频函数（避免过度hook）
- ❌ `SSL_write` / `SSL_read` - 仅在必须时使用（Text模式）
- ✅ `SSL_get_wbio` - 低频，每连接调用一次

### eBPF映射大小
- `active_ssl_read_args_map`: 1024
- `active_ssl_write_args_map`: 1024
- `ssl_st_fd`: 10240
- `tcp_fd_infos`: 10240

## 支持的库版本

### OpenSSL
- 1.0.2系列 ✓
- 1.1.0系列 ✓
- 1.1.1系列 ✓
- 3.0~3.5系列 ✓

### BoringSSL
- Android 13/14/15 ✓
- 非Android版本 ✓

## 快速诊断

**问题**: 捕获不到明文数据
- 检查是否hook了 `SSL_write` 和 `SSL_read`
- 确认模式是 Text 模式
- 检查目标进程是否使用了预期的SSL库

**问题**: 导出的密钥无效
- 检查是否hook了 `SSL_get_wbio` 等密钥捕获函数
- 确认模式是 Keylog 或 Pcap 模式
- 检查OpenSSL/BoringSSL版本是否匹配

**问题**: 无法关联数据到连接
- 检查是否hook了 `SSL_set_fd` 系列函数
- 检查是否hook了 `__sys_connect` / `__sys_accept4`
- 确认网络连接追踪函数正常工作

## 更多信息

详细文档请参考: `docs/ssl_hooked_functions_zh.md`
