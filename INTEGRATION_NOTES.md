# Windows Redirector Integration

## 概述

本次集成将 `mitmproxy-windows` 模块的功能直接集成到了 `mitmproxy-rs` 中，消除了对外部 `windows-redirector.exe` 进程的依赖。

## 主要变化

### 1. 依赖更新
- **移除**: `mitmproxy-rs` 不再依赖 `mitmproxy_windows` Python 包
- **添加**: 在 `mitmproxy-rs/Cargo.toml` 中添加了 Windows 特定的依赖项：
  - `windivert = "0.6.0"`
  - `lru_time_cache = "0.11.11"`
  - `env_logger = "0.11.5"`
  - `prost = "0.14.1"`
  - `internet-packet = { version = "0.2.2", features = ["checksums"] }`

### 2. 新增模块
- **`mitmproxy-rs/src/server/windows_redirector.rs`**: 集成的 Windows redirector 实现
- 提供了 `WindowsRedirector` 结构体，可通过 Python 接口访问

### 3. 架构改进
- **之前**: `mitmproxy-rs` → 启动外部 `windows-redirector.exe` → 通过命名管道通信
- **现在**: `mitmproxy-rs` → 内置 Windows redirector 功能 → 直接在进程内处理

### 4. Python API 变化
- `WindowsRedirector` 现在可以直接从 `mitmproxy_rs.local` 导入
- 不再需要 `mitmproxy_windows.executable_path()` 函数
- 集成的 redirector 提供相同的功能接口

## 优势

1. **减少进程数量**: 不再需要单独的 `windows-redirector.exe` 进程
2. **简化部署**: 减少了一个外部依赖
3. **提高性能**: 进程内通信比进程间通信更高效
4. **简化维护**: 所有 Windows 相关代码都在一个地方

## 兼容性

- 保持了与现有 Python API 的兼容性
- `LocalRedirector` 的行为保持不变
- 在非 Windows 平台上，`WindowsRedirector` 会返回适当的错误

## 文件结构变化

```
mitmproxy-rs/
├── src/
│   ├── server/
│   │   ├── windows_redirector.rs  # 新增：集成的 Windows redirector
│   │   ├── local_redirector.rs    # 修改：使用集成的 redirector
│   │   └── mod.rs                 # 修改：导出 WindowsRedirector
│   └── lib.rs                     # 修改：移除 mitmproxy_windows 导入
├── Cargo.toml                     # 修改：添加 Windows 依赖
└── pyproject.toml                 # 修改：移除 mitmproxy_windows 依赖
```

## 测试

运行 `python test_integration.py` 来验证集成是否成功。

## 注意事项

1. 当前实现是一个基础版本，主要功能已集成但可能需要进一步优化
2. WinDivert 库文件仍然需要，但现在作为 Rust 依赖管理
3. 在开发环境中，确保有适当的权限来使用 WinDivert 功能
