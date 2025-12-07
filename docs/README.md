# eCapture 文档

本目录包含 eCapture 项目的技术文档。

## 文档列表

### SSL模块分析

1. **[ssl_hooked_functions_zh.md](ssl_hooked_functions_zh.md)** - eCapture SSL模块Hook函数详细分析
   - 完整的libssl函数hook分析
   - 不同捕获模式的详细说明（Text/Keylog/Pcap）
   - 用户空间和内核空间hook函数的完整列表
   - 支持的OpenSSL/BoringSSL版本信息
   - 性能考虑和优化策略
   - 数据流程详解

2. **[ssl_hooked_functions_quick_ref_zh.md](ssl_hooked_functions_quick_ref_zh.md)** - SSL模块Hook函数快速参考
   - Hook函数速查表
   - 按模式分类的函数列表
   - 快速诊断指南
   - 关键代码位置索引

3. **[ssl_hook_architecture_zh.md](ssl_hook_architecture_zh.md)** - SSL模块Hook架构图解
   - 整体架构可视化
   - 三种模式的Hook函数对比图
   - 数据流向图（Text/Keylog/Pcap模式）
   - 版本特定Hook策略
   - 性能优化策略图解
   - Hook函数调用时序图

## 使用说明

如果你想了解 eCapture SSL模块 hook了哪些 libssl 函数：

- **快速查阅**: 查看 `ssl_hooked_functions_quick_ref_zh.md`
- **架构总览**: 查看 `ssl_hook_architecture_zh.md`
- **详细了解**: 查看 `ssl_hooked_functions_zh.md`

## 贡献

欢迎补充和完善文档！如有错误或建议，请提交 issue 或 pull request。
