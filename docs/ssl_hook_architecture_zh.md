# eCapture SSL模块Hook架构图

## 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用程序进程                                │
│                                                                 │
│    ┌──────────────┐         ┌──────────────┐                    │
│    │   libssl.so  │         │  应用代码     │                    │
│    │  (OpenSSL/   │◄────────┤              │                    │
│    │  BoringSSL)  │         │              │                    │
│    └──────┬───────┘         └──────────────┘                    │
│           │                                                      │
└───────────┼──────────────────────────────────────────────────────┘
            │
            │ uprobe hook
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       eBPF 用户空间Hook                           │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  SSL_write()    │  │  SSL_read()     │  │ SSL_set_fd()    │ │
│  │  SSL数据捕获     │  │  SSL数据捕获     │  │ FD映射          │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ SSL_get_wbio()  │  │ SSL_in_before() │  │SSL_do_handshake││ │
│  │ 主密钥捕获       │  │ 主密钥捕获       │  │ 主密钥捕获      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
└─────────────┬───────────────────────────────────────────────────┘
              │
              │ perf event / BPF maps
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       内核空间                                    │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ __sys_connect() │  │ __sys_accept4() │  │tcp_v4_destroy_  │ │
│  │ 连接追踪         │  │ 连接追踪         │  │sock() 连接清理  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐                      │
│  │ tcp_sendmsg()   │  │  TC Egress/     │                      │
│  │ 流量捕获         │  │  Ingress        │                      │
│  └─────────────────┘  │  流量捕获        │                      │
│                       └─────────────────┘                      │
│                                                                 │
└─────────────┬───────────────────────────────────────────────────┘
              │
              │ perf event
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   eCapture 用户空间程序                           │
│                                                                 │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐   │
│  │  Text模式       │  │  Keylog模式     │  │  Pcap模式       │   │
│  │  输出明文数据    │  │  导出主密钥     │  │  生成pcapng     │   │
│  └────────────────┘  └────────────────┘  └────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 三种模式的Hook函数对比

### Text模式 - 明文数据捕获
```
用户空间 uprobe:
  ├─ SSL_write (uprobe + uretprobe)   → 捕获发送数据
  ├─ SSL_read (uprobe + uretprobe)    → 捕获接收数据
  ├─ SSL_set_fd                       → FD映射
  ├─ SSL_set_rfd                      → FD映射
  └─ SSL_set_wfd                      → FD映射

内核空间 kprobe:
  ├─ __sys_connect                    → 连接追踪
  ├─ inet_stream_connect              → 连接追踪
  ├─ __sys_accept4                    → 连接追踪
  ├─ inet_accept                      → 连接追踪
  └─ tcp_v4_destroy_sock              → 连接清理
```

### Keylog模式 - 密钥导出
```
用户空间 uprobe:
  ├─ SSL_get_wbio                     → 主密钥捕获（首选）
  ├─ SSL_in_before                    → 主密钥捕获（备选）
  ├─ SSL_do_handshake                 → 主密钥捕获（备选）
  └─ SSL_in_init (BoringSSL)          → 主密钥捕获（BoringSSL专用）

内核空间 kprobe:
  └─ 无
```

### Pcap模式 - 流量包+密钥
```
用户空间 uprobe:
  ├─ SSL_get_wbio                     → 主密钥捕获
  ├─ SSL_in_before                    → 主密钥捕获
  ├─ SSL_do_handshake                 → 主密钥捕获
  └─ SSL_in_init (BoringSSL)          → 主密钥捕获

内核空间 kprobe:
  ├─ tcp_sendmsg                      → TCP流量捕获
  └─ udp_sendmsg                      → UDP流量捕获（DTLS）

TC程序:
  ├─ TC Egress                        → 出口流量捕获
  └─ TC Ingress                       → 入口流量捕获
```

## 数据流向图

### Text模式数据流
```
应用程序
  │
  ├─ SSL_write(data) ────┐
  │                      │ uprobe hook
  │                      ▼
  │                  记录data指针
  │                      │
  │                      │ uretprobe
  │                      ▼
  │                  读取明文data
  │                      │
  │                      ▼
  │                  perf event
  │                      │
  │                      ▼
  │                eCapture用户空间
  │                      │
  │                      ▼
  │                  格式化输出
  │
  └─ SSL_set_fd(ssl, fd) ────┐
                              │ uprobe hook
                              ▼
                          建立SSL→FD映射
                              │
                              ▼
                          BPF map存储
```

### Keylog模式数据流
```
应用程序执行TLS握手
  │
  ├─ TLS握手完成
  │     │
  │     ▼
  ├─ SSL_get_wbio() ────┐
  │                      │ uprobe hook
  │                      ▼
  │                  读取SSL对象
  │                      │
  │                      ├─ client_random
  │                      ├─ master_key (TLS 1.2)
  │                      └─ traffic_secrets (TLS 1.3)
  │                      │
  │                      ▼
  │                  perf event
  │                      │
  │                      ▼
  │                eCapture用户空间
  │                      │
  │                      ▼
  │              格式化为NSS Key Log格式
  │                      │
  │                      ▼
  │                写入keylog文件
  │
  └─ 继续正常通信
```

### Pcap模式数据流
```
网络接口
  │
  ├─ 入口流量 ──────────┐
  │                     │ TC Ingress
  │                     ▼
  │              捕获加密包
  │                     │
  │                     ▼
  │              perf event
  │
  └─ 出口流量 ──────────┐
                        │ TC Egress
                        ▼
                 捕获加密包
                        │
                        ▼
                 perf event
                        │
                        └─────┐
                              │
应用程序执行TLS握手            │
  │                          │
  ├─ SSL_get_wbio() ────┐   │
  │                      │   │
  │                      ▼   │
  │              捕获主密钥    │
  │                      │   │
  │                      ▼   │
  │              perf event  │
  │                      │   │
  │                      ▼   ▼
  │                eCapture用户空间
  │                      │
  │                      ├─ 流量包数据
  │                      ├─ 主密钥数据
  │                      │
  │                      ▼
  │              生成pcapng文件
  │                (包含DSB密钥块)
  │                      │
  │                      ▼
  │              可用Wireshark解密
  │
  └─ 继续正常通信
```

## 版本特定Hook策略

```
SSL库版本检测
  │
  ├─ 是 BoringSSL?
  │   │
  │   ├─ 是 ──→ 使用 SSL_in_init
  │   │          └─ 原因: SSL_write调用SSL_do_handshake时握手可能未完成
  │   │
  │   └─ 否 ──→ 继续检测
  │
  ├─ 是 OpenSSL 1.0.x?
  │   │
  │   ├─ 是 ──→ 使用 SSL_state 替代 SSL_in_before
  │   │          └─ 原因: SSL_in_before在1.0.x是宏定义
  │   │
  │   └─ 否 ──→ 使用默认策略
  │
  └─ 默认策略:
      ├─ SSL_get_wbio (首选)
      ├─ SSL_in_before (备选)
      └─ SSL_do_handshake (备选)
```

## 性能优化策略

### 高频vs低频函数选择
```
函数调用频率:
  ┌────────────────────────────────┐
  │ SSL_write / SSL_read           │ 高频 (每次数据传输)
  │                                │ ✗ 仅在Text模式必须时使用
  ├────────────────────────────────┤
  │ SSL_do_handshake               │ 中频 (每次连接握手)
  │                                │ ○ 作为备选
  ├────────────────────────────────┤
  │ SSL_get_wbio                   │ 低频 (握手完成后)
  │ SSL_in_before                  │ ✓ 首选用于密钥捕获
  └────────────────────────────────┘
```

### eBPF Map大小配置
```
active_ssl_read_args_map:   1,024 entries  (临时数据)
active_ssl_write_args_map:  1,024 entries  (临时数据)
ssl_st_fd:                 10,240 entries  (SSL→FD映射)
tcp_fd_infos:              10,240 entries  (TCP连接信息)
bpf_context:                2,048 entries  (主密钥上下文)
```

## 支持矩阵

```
┌──────────────┬─────────┬─────────┬─────────┬─────────┐
│   库版本     │ Text    │ Keylog  │  Pcap   │  状态   │
├──────────────┼─────────┼─────────┼─────────┼─────────┤
│OpenSSL 1.0.2 │   ✓     │   ✓*    │   ✓*    │  支持   │
│OpenSSL 1.1.0 │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 1.1.1 │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 3.0   │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 3.1   │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 3.2   │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 3.3   │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 3.4   │   ✓     │   ✓     │   ✓     │  支持   │
│OpenSSL 3.5   │   ✓     │   ✓     │   ✓     │  支持   │
├──────────────┼─────────┼─────────┼─────────┼─────────┤
│BoringSSL A13 │   ✓     │   ✓**   │   ✓**   │  支持   │
│BoringSSL A14 │   ✓     │   ✓**   │   ✓**   │  支持   │
│BoringSSL A15 │   ✓     │   ✓**   │   ✓**   │  支持   │
│BoringSSL NA  │   ✓     │   ✓**   │   ✓**   │  支持   │
└──────────────┴─────────┴─────────┴─────────┴─────────┘

注释:
  *  使用 SSL_state 替代 SSL_in_before
  ** 使用 SSL_in_init 替代其他主密钥捕获函数
```

## Hook函数调用时序

### Text模式典型时序
```
时间轴:
  │
  ▼ 连接建立
  ├─ __sys_connect() 或 __sys_accept4()
  │     └─ 记录: socket, 地址, 端口
  │
  ▼ SSL初始化
  ├─ SSL_set_fd()
  │     └─ 建立映射: SSL对象 → 文件描述符
  │
  ▼ SSL数据传输
  ├─ SSL_write()
  │     ├─ uprobe: 记录data指针
  │     └─ uretprobe: 读取明文数据
  │
  ├─ SSL_read()
  │     ├─ uprobe: 记录buffer指针
  │     └─ uretprobe: 读取明文数据
  │
  ▼ 连接关闭
  └─ tcp_v4_destroy_sock()
        └─ 清理: 删除映射关系
```

### Keylog模式典型时序
```
时间轴:
  │
  ▼ TLS握手开始
  ├─ TLS ClientHello
  ├─ TLS ServerHello
  ├─ TLS Certificate
  ├─ TLS Key Exchange
  │
  ▼ 握手完成
  ├─ SSL_get_wbio() 或 SSL_in_before()
  │     ├─ 读取: client_random
  │     ├─ 读取: master_key (TLS 1.2)
  │     └─ 读取: traffic_secrets (TLS 1.3)
  │
  ▼ 密钥导出
  └─ 写入keylog文件
        └─ 格式: CLIENT_RANDOM <随机数> <密钥>
```

## 参考资料

完整文档请参考:
- 详细文档: [ssl_hooked_functions_zh.md](ssl_hooked_functions_zh.md)
- 快速参考: [ssl_hooked_functions_quick_ref_zh.md](ssl_hooked_functions_quick_ref_zh.md)
