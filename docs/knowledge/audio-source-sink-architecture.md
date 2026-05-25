# Source-Sink双端架构知识

本文只记录 Source端（主控端）和 Sink端（被控端）的 IPC 架构和交互。设备生命周期见 `audio-device-lifecycle.md`，事件类型见 `audio-event-pipeline.md`。

## 双端角色

| 角色 | SA服务 | 管理器 | 设备抽象 | 职责 |
| --- | --- | --- | --- | --- |
| Source（主控端） | DAudioSourceService | DAudioSourceManager | DAudioSourceDev | 发送指令、管理远端设备抽象 |
| Sink（被控端） | DAudioSinkService | DAudioSinkManager | DAudioSinkDev | 接收指令、提供本地音频外设 |

服务锚点：`services/audiomanager/servicesource/daudio_source_service.h` / `servicesink/daudio_sink_service.h`

## IPC 调用链

| 场景 | Source端调用 | Sink端响应 | 事件流向 |
| --- | --- | --- | --- |
| 启用设备 | RegisterDistributedHardware | SubscribeLocalHardware | Source → Sink |
| 禁用设备 | UnregisterDistributedHardware | UnsubscribeLocalHardware | Source → Sink |
| 状态通知 | DAudioNotify | DAudioNotify | 双向对称 |

IPC代理锚点：`interfaces/inner_kits/native_cpp/audio_source/daudio_source_proxy.h` / `audio_sink/daudio_sink_proxy.h`

## 启动顺序

| 步骤 | 动作 | 锚点 | 说明 |
| --- | --- | --- | --- |
| 1 | Sink服务启动 | `daudio_sink_service.cpp:OnStart` | 被控端先启动，等待指令 |
| 2 | Source服务启动 | `daudio_source_service.cpp:OnStart` | 主控端后启动，主动发起 |
| 3 | Source初始化 | `daudio_source_manager.cpp:Init` | 加载AVEngineProvider |
| 4 | Sink初始化 | `daudio_sink_manager.cpp:Init` | 加载AVEngineProvider |

顺序错误：Source先启动而Sink未就绪会导致IPC调用失败。

## 崩溃恢复

| 场景 | 检测机制 | 处理逻辑 | 锚点 |
| --- | --- | --- | --- |
| Sink服务崩溃 | DeathRecipient | 清理audioDevMap对应设备 | `daudio_source_manager.cpp:OnRemoteDied` |
| Source服务崩溃 | DeathRecipient | 清理本地设备状态 | `daudio_sink_manager.cpp:OnRemoteDied` |

关键：崩溃时必须清理对应的audioDevMap条目，否则残留设备对象导致状态不一致。

## 反模式/修改前检查

- **禁止**直接调用远端服务的内部方法。必须通过IPC Proxy（DAudioSourceProxy/DAudioSinkProxy）。
- **禁止**在Source端未初始化SinkProxy时调用RegisterDistributedHardware。检查sinkServiceMap是否包含目标设备。
- **禁止**跳过DAudioNotify直接发送事件。必须通过IPC通道保证可靠性。
- **禁止**在崩溃恢复中遗漏清理audioDevMap。检查对应devId的条目是否已移除。

## 测试指引

- IPC调用变更：使用 `DAudioSourceProxyTest` / `DAudioSinkProxyTest`。
- 服务启动变更：使用 `DAudioSourceServiceTest` / `DAudioSinkServiceTest`。
- 管理器变更：使用 `DAudioSourceManagerTest` / `DAudioSinkManagerTest`。