# eCapture SSL模块Hook的libssl函数分析

## 概述

eCapture的SSL模块通过eBPF技术对OpenSSL/BoringSSL库的关键函数进行hook，以实现TLS流量捕获和分析。本文档详细说明了SSL模块hook的所有libssl函数及其用途。

## Hook函数分类

根据不同的捕获模式，SSL模块hook的函数有所不同。eCapture支持三种主要的捕获模式：

1. **Text模式** - 捕获明文TLS数据流
2. **Keylog模式** - 导出TLS主密钥用于解密
3. **Pcap模式** - 捕获加密流量包并导出密钥

---

## 一、用户空间uprobe Hook函数

### 1. SSL数据读写函数

这些函数用于捕获TLS加密前的明文数据或解密后的明文数据。

#### `SSL_write`
- **函数签名**: `int SSL_write(SSL *ssl, const void *buf, int num)`
- **Hook类型**: uprobe + uretprobe
- **用途**: 
  - 捕获应用程序通过SSL连接发送的明文数据
  - 在数据被SSL加密之前进行拦截
- **适用模式**: Text模式
- **eBPF程序**:
  - `probe_entry_SSL_write` - 入口探针，记录待发送的数据指针和长度
  - `probe_ret_SSL_write` - 返回探针，读取实际发送的数据内容
- **实现位置**: 
  - Go: `user/module/probe_openssl_text.go:50-60`
  - eBPF: `kern/openssl.h:247` (uprobe), `kern/openssl.h` (uretprobe)

#### `SSL_read`
- **函数签名**: `int SSL_read(SSL *ssl, void *buf, int num)`
- **Hook类型**: uprobe + uretprobe
- **用途**: 
  - 捕获应用程序从SSL连接接收的明文数据
  - 在SSL解密之后进行拦截
- **适用模式**: Text模式
- **eBPF程序**:
  - `probe_entry_SSL_read` - 入口探针，记录接收数据的缓冲区指针
  - `probe_ret_SSL_read` - 返回探针，读取接收到的明文数据
- **实现位置**: 
  - Go: `user/module/probe_openssl_text.go:62-72`
  - eBPF: `kern/openssl.h:365` (uprobe), `kern/openssl.h` (uretprobe)

### 2. SSL文件描述符设置函数

这些函数用于追踪SSL对象与文件描述符的关联关系。

#### `SSL_set_fd`
- **函数签名**: `int SSL_set_fd(SSL *s, int fd)`
- **Hook类型**: uprobe
- **用途**: 
  - 建立SSL对象与文件描述符的映射关系
  - 用于后续将捕获的数据关联到正确的网络连接
- **适用模式**: Text模式
- **eBPF程序**: `probe_SSL_set_fd`
- **实现位置**: 
  - Go: `user/module/probe_openssl_text.go:131-136`
  - eBPF: `kern/openssl.h:665`

#### `SSL_set_rfd`
- **函数签名**: `int SSL_set_rfd(SSL *s, int fd)`
- **Hook类型**: uprobe
- **用途**: 
  - 设置SSL对象的读文件描述符
  - 建立SSL读操作与socket的关联
- **适用模式**: Text模式
- **eBPF程序**: `probe_SSL_set_fd`（与SSL_set_fd共用）
- **实现位置**: Go: `user/module/probe_openssl_text.go:137-143`

#### `SSL_set_wfd`
- **函数签名**: `int SSL_set_wfd(SSL *s, int fd)`
- **Hook类型**: uprobe
- **用途**: 
  - 设置SSL对象的写文件描述符
  - 建立SSL写操作与socket的关联
- **适用模式**: Text模式
- **eBPF程序**: `probe_SSL_set_fd`（与SSL_set_fd共用）
- **实现位置**: Go: `user/module/probe_openssl_text.go:144-150`

### 3. TLS主密钥捕获函数

这些函数用于捕获TLS握手过程中生成的主密钥，以便后续解密TLS流量。

#### `SSL_get_wbio`
- **函数签名**: `BIO *SSL_get_wbio(const SSL *s)`
- **Hook类型**: uprobe
- **用途**: 
  - 在TLS握手完成后被调用
  - 此时SSL对象中的client_random和master_key已经生成
  - 用于导出TLS 1.2/1.3的密钥材料
- **适用模式**: Keylog模式、Pcap模式
- **选择原因**: 
  - 在TLS握手完成后调用（满足密钥已生成的条件）
  - 在动态链接库符号表中是导出状态
  - 调用频率较低（相比SSL_write/SSL_read）
- **实现位置**: 
  - Go: `user/module/const.go:71-78`
  - Go: `user/module/probe_openssl_keylog.go:65-72`
  - eBPF: `kern/openssl_masterkey.h:81-82`

#### `SSL_in_before` (或 `SSL_state`)
- **函数签名**: `int SSL_in_before(const SSL *s)` 或 `int SSL_state(const SSL *s)`
- **Hook类型**: uprobe
- **用途**: 
  - 支持异步SSL连接的密钥捕获
  - 在SSL状态机的不同阶段捕获密钥
  - **注意**: OpenSSL 1.0.x版本中`SSL_in_before`是宏定义，需要替换为`SSL_state`函数
- **适用模式**: Keylog模式、Pcap模式
- **实现位置**: 
  - Go: `user/module/const.go:53,76`
  - Go: `user/module/probe_openssl.go:186-195` (版本检测和替换逻辑)

#### `SSL_do_handshake`
- **函数签名**: `int SSL_do_handshake(SSL *s)`
- **Hook类型**: uprobe
- **用途**: 
  - 捕获TLS握手过程中的密钥信息
  - 作为备用hook点，确保能捕获到密钥
- **适用模式**: Keylog模式、Pcap模式
- **实现位置**: Go: `user/module/const.go:77`

#### `SSL_in_init` (仅BoringSSL)
- **函数签名**: `int SSL_in_init(const SSL *s)`
- **Hook类型**: uprobe
- **用途**: 
  - **专门用于BoringSSL**的密钥捕获
  - 在BoringSSL库中，`SSL_write`函数会调用`SSL_do_handshake`
  - `SSL_do_handshake`执行时握手可能未完成，所以改用`SSL_in_init`
- **适用模式**: Keylog模式、Pcap模式
- **实现位置**: 
  - Go: `user/module/const.go:52`
  - Go: `user/module/probe_openssl.go:183`

---

## 二、内核空间kprobe Hook函数

### 1. 网络连接追踪函数

这些内核函数用于追踪TCP连接的建立和销毁，以便将SSL数据关联到正确的网络连接。

#### `__sys_connect`
- **Hook类型**: kprobe + kretprobe
- **用途**: 
  - 追踪客户端发起的TCP连接
  - 捕获目标地址、端口等连接信息
- **适用模式**: Text模式
- **eBPF程序**:
  - `probe_connect` - 入口探针
  - `retprobe_connect` - 返回探针
- **实现位置**: Go: `user/module/probe_openssl_text.go:76-92`

#### `inet_stream_connect`
- **Hook类型**: kprobe
- **用途**: 
  - 在inet层追踪TCP流连接
  - 获取socket相关信息
- **适用模式**: Text模式
- **eBPF程序**: `probe_inet_stream_connect`
- **实现位置**: Go: `user/module/probe_openssl_text.go:82-86`

#### `__sys_accept4`
- **Hook类型**: kprobe + kretprobe
- **用途**: 
  - 追踪服务端接受的TCP连接
  - 捕获新建立连接的socket信息
- **适用模式**: Text模式
- **eBPF程序**:
  - `probe_connect` - 入口探针（复用）
  - `retprobe_accept4` - 返回探针
- **实现位置**: Go: `user/module/probe_openssl_text.go:94-110`

#### `inet_accept`
- **Hook类型**: kprobe
- **用途**: 
  - 在inet层追踪accept操作
  - 获取接受连接的详细信息
- **适用模式**: Text模式
- **eBPF程序**: `probe_inet_accept`
- **实现位置**: Go: `user/module/probe_openssl_text.go:100-104`

#### `tcp_v4_destroy_sock`
- **Hook类型**: kprobe
- **用途**: 
  - 追踪TCP连接的销毁
  - 清理与该连接相关的SSL数据结构
- **适用模式**: Text模式
- **eBPF程序**: `probe_tcp_v4_destroy_sock`
- **实现位置**: Go: `user/module/probe_openssl_text.go:112-116`

### 2. 网络流量捕获函数（仅Pcap模式）

#### `tcp_sendmsg`
- **Hook类型**: kprobe
- **用途**: 
  - 捕获TCP发送的数据包
  - 用于生成pcapng格式的流量文件
- **适用模式**: Pcap模式
- **实现位置**: Go: `user/module/probe_openssl_pcap.go:108-111`

#### `udp_sendmsg`
- **Hook类型**: kprobe
- **用途**: 
  - 捕获UDP发送的数据包（用于DTLS）
  - 用于生成pcapng格式的流量文件
- **适用模式**: Pcap模式
- **实现位置**: Go: `user/module/probe_openssl_pcap.go:113-116`

### 3. TC (Traffic Control) Hook（仅Pcap模式）

这些是基于TC的eBPF程序，用于在网络接口层面捕获流量。

#### TC Egress
- **Hook类型**: classifier/egress
- **用途**: 
  - 在网络接口的出口方向捕获流量
  - 捕获加密后的TLS数据包
- **适用模式**: Pcap模式
- **实现位置**: Go: `user/module/probe_openssl_pcap.go:94-99`

#### TC Ingress
- **Hook类型**: classifier/ingress
- **用途**: 
  - 在网络接口的入口方向捕获流量
  - 捕获接收到的加密TLS数据包
- **适用模式**: Pcap模式
- **实现位置**: Go: `user/module/probe_openssl_pcap.go:100-105`

---

## 三、Hook函数选择策略

### 主密钥捕获函数的选择逻辑

为了读取TLS握手完成后的`client_random`和主密钥，eCapture需要选择合适的hook函数。选择标准如下：

1. **必须在TLS握手完成后调用** - 确保密钥材料已经生成
2. **函数在动态链接库符号表中导出** - 能够被uprobe hook
3. **调用频率较低** - 避免性能问题（排除了`SSL_write`/`SSL_read`）

**默认策略**（`user/module/const.go:71-78`）：
```go
masterKeyHookFuncs = []string{
    "SSL_get_wbio",      // 首选：OpenSSL同步调用场景
    "SSL_in_before",     // 备选：支持异步调用场景
    "SSL_do_handshake",  // 备选：确保密钥捕获
}
```

**特殊情况处理**：

1. **BoringSSL**: 使用`SSL_in_init`替代上述函数
   - 原因：BoringSSL的`SSL_write`会调用`SSL_do_handshake`，此时握手可能未完成
   - 代码：`user/module/probe_openssl.go:183`

2. **OpenSSL 1.0.x**: 将`SSL_in_before`替换为`SSL_state`
   - 原因：OpenSSL 1.0.x中`SSL_in_before`是宏定义，不是导出函数
   - 代码：`user/module/probe_openssl.go:186-195`

---

## 四、不同模式下的Hook函数汇总

### Text模式
**用户空间函数**：
- `SSL_write` (uprobe + uretprobe)
- `SSL_read` (uprobe + uretprobe)
- `SSL_set_fd` (uprobe)
- `SSL_set_rfd` (uprobe)
- `SSL_set_wfd` (uprobe)

**内核空间函数**：
- `__sys_connect` (kprobe + kretprobe)
- `inet_stream_connect` (kprobe)
- `__sys_accept4` (kprobe + kretprobe)
- `inet_accept` (kprobe)
- `tcp_v4_destroy_sock` (kprobe)

### Keylog模式
**用户空间函数**：
- `SSL_get_wbio` (uprobe)
- `SSL_in_before` 或 `SSL_state` (uprobe)
- `SSL_do_handshake` (uprobe)
- `SSL_in_init` (uprobe，仅BoringSSL)

**内核空间函数**：无

### Pcap模式
**用户空间函数**：
- `SSL_get_wbio` (uprobe)
- `SSL_in_before` 或 `SSL_state` (uprobe)
- `SSL_do_handshake` (uprobe)
- `SSL_in_init` (uprobe，仅BoringSSL)

**内核空间函数**：
- `tcp_sendmsg` (kprobe)
- `udp_sendmsg` (kprobe)

**TC程序**：
- TC Egress (classifier)
- TC Ingress (classifier)

---

## 五、支持的SSL/TLS库版本

eCapture针对不同版本的OpenSSL和BoringSSL使用不同的eBPF字节码，因为结构体偏移量在不同版本中有差异。

### OpenSSL版本支持
- **1.0.2系列**: `openssl_1_0_2a_kern.o`
- **1.1.0系列**: `openssl_1_1_0a_kern.o`
- **1.1.1系列**: 
  - `openssl_1_1_1a_kern.o`
  - `openssl_1_1_1b_kern.o`
  - `openssl_1_1_1d_kern.o`
  - `openssl_1_1_1j_kern.o`
- **3.0系列**: `openssl_3_0_0_kern.o`, `openssl_3_0_12_kern.o`
- **3.1系列**: `openssl_3_1_0_kern.o`
- **3.2系列**: `openssl_3_2_0_kern.o`, `openssl_3_2_3_kern.o`, `openssl_3_2_4_kern.o`
- **3.3系列**: `openssl_3_3_0_kern.o`, `openssl_3_3_2_kern.o`, `openssl_3_3_3_kern.o`
- **3.4系列**: `openssl_3_4_0_kern.o`, `openssl_3_4_1_kern.o`
- **3.5系列**: `openssl_3_5_0_kern.o`

### BoringSSL版本支持
- **Android 13**: `boringssl_a_13_kern.o`
- **Android 14**: `boringssl_a_14_kern.o`
- **Android 15**: `boringssl_a_15_kern.o`
- **非Android版本**: `boringssl_na_kern.o`

版本映射定义在：`user/module/probe_openssl_lib.go:73-186`

---

## 六、数据流程

### Text模式数据流程

1. **连接建立**：
   - kprobe hook `__sys_connect`/`__sys_accept4` 捕获连接信息
   - 获取socket、地址、端口等信息

2. **SSL对象关联**：
   - uprobe hook `SSL_set_fd`系列函数
   - 建立SSL对象与文件描述符的映射

3. **数据捕获**：
   - uprobe hook `SSL_write`/`SSL_read` 入口，记录数据指针
   - uretprobe 读取实际的明文数据
   - 数据通过perf event发送到用户空间

4. **连接销毁**：
   - kprobe hook `tcp_v4_destroy_sock`
   - 清理相关的映射数据

### Keylog模式数据流程

1. **TLS握手监测**：
   - uprobe hook `SSL_get_wbio`等函数
   - 在握手完成后触发

2. **密钥提取**：
   - 从SSL对象中读取`client_random`
   - 根据TLS版本读取相应的密钥材料：
     - TLS 1.2: `master_key`
     - TLS 1.3: `handshake_secret`, `client_app_traffic_secret`, `server_app_traffic_secret`, `exporter_master_secret`

3. **密钥导出**：
   - 将密钥以NSS Key Log格式写入文件
   - 格式：`CLIENT_RANDOM <client_random> <master_key>`

### Pcap模式数据流程

1. **流量捕获**：
   - TC程序在网络接口捕获所有进出流量
   - kprobe hook `tcp_sendmsg`/`udp_sendmsg` 获取额外信息

2. **密钥导出**：
   - 与Keylog模式相同的方式捕获密钥
   - 密钥以DSB（Decryption Secrets Block）格式嵌入pcapng文件

3. **文件生成**：
   - 创建pcapng格式文件
   - 包含流量包和解密密钥
   - 可直接用Wireshark打开并自动解密

---

## 七、性能考虑

### Hook点选择的性能影响

1. **高频函数避免**：
   - `SSL_write`/`SSL_read`在Text模式必须hook，但在Keylog/Pcap模式中避免
   - 参考issue: https://github.com/gojue/ecapture/issues/463

2. **低频函数优先**：
   - 选择`SSL_get_wbio`作为主密钥捕获点
   - 每个连接仅在握手完成后调用一次

3. **映射表大小**：
   - `active_ssl_read_args_map`: 1024条目
   - `active_ssl_write_args_map`: 1024条目
   - `ssl_st_fd`: 10240条目
   - `tcp_fd_infos`: 10240条目

### eBPF程序优化

1. **栈空间限制**：
   - eBPF程序限制512字节栈
   - 使用`BPF_MAP_TYPE_PERCPU_ARRAY`作为堆内存
   - 代码：`kern/openssl.h:116-121`

2. **数据传输**：
   - 使用perf event数组高效传输数据
   - 避免在内核空间做大量数据处理

---

## 八、相关文件索引

### 用户空间（Go）
- **主模块**: `user/module/probe_openssl.go`
- **Text模式**: `user/module/probe_openssl_text.go`
- **Keylog模式**: `user/module/probe_openssl_keylog.go`
- **Pcap模式**: `user/module/probe_openssl_pcap.go`
- **版本检测**: `user/module/probe_openssl_lib.go`
- **常量定义**: `user/module/const.go`

### 内核空间（eBPF C）
- **通用头文件**: `kern/openssl.h`
- **主密钥捕获**: `kern/openssl_masterkey.h`
- **版本特定**:
  - OpenSSL 1.0.2: `kern/openssl_1_0_2a_kern.c`
  - OpenSSL 1.1.1: `kern/openssl_1_1_1j_kern.c`
  - OpenSSL 3.0: `kern/openssl_3_0_0_kern.c`
  - BoringSSL: `kern/boringssl_a_13_kern.c`

### 事件处理
- **事件定义**: `user/event/event_openssl.go`
- **主密钥事件**: `user/event/event_mastersecret.go`

---

## 九、总结

eCapture的SSL模块通过精心设计的hook策略，实现了对OpenSSL/BoringSSL库的无侵入式监控：

1. **数据捕获**：通过hook `SSL_write`/`SSL_read`捕获明文数据
2. **密钥导出**：通过hook握手完成后的低频函数导出TLS密钥
3. **连接追踪**：通过hook内核网络函数关联数据与连接
4. **流量捕获**：通过TC程序捕获完整的网络流量

这种多层次的hook策略既保证了功能的完整性，又尽可能降低了对目标程序性能的影响。

---

## 参考资料

1. OpenSSL官方文档: https://www.openssl.org/docs/
2. BoringSSL源码: https://github.com/google/boringssl
3. eCapture项目: https://github.com/gojue/ecapture
4. TLS 1.3规范: https://wiki.openssl.org/index.php/TLS1.3
5. NSS Key Log格式: https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
