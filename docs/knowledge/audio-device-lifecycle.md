# 设备生命周期知识

本文只记录 Speaker/Mic 设备的创建、启用、禁用、销毁流程。Source/Sink 双端 IPC 交互见 `audio-source-sink-architecture.md`，事件类型定义见 `audio-event-pipeline.md`。

## 设备状态机

| 状态 | 枚举值 | 触发条件 | 允许操作 |
| --- | --- | --- | --- |
| STATUS_IDLE | 0 | 初始化/销毁完成 | EnableDevice |
| STATUS_READY | 1 | SetUp完成 | Start |
| STATUS_START | 2 | Start完成 | Pause/Stop |
| STATUS_STOP | 3 | Stop完成 | Restart/Release |

状态流转锚点：`services/common/audioparam/audio_status.h:21-26`

## 启用流程（EnableDevice）

| 阶段 | Source端锚点 | Sink端锚点 | 关键动作 |
| --- | --- | --- | --- |
| 注册设备 | `managersource/daudio_source_manager.cpp:CreateAudioDevice` | `managersink/daudio_sink_manager.cpp:CreateAudioDevice` | 创建DAudioSourceDev/DAudioSinkDev |
| 建立控制通道 | `audiocontrol/controlsource/daudio_source_dev_ctrl_mgr.cpp:SetUp` | `audiocontrol/controlsink/daudio_sink_dev_ctrl_mgr.cpp:SetUp` | 创建DAudioSourceCtrlTrans |
| 建立数据通道 | `managersource/dspeaker_dev.cpp:SetUp` | `audioclient/spkclient/dspeaker_client.cpp:SetUp` | 创建AudioRenderer/Capturer |
| 通知HDF | `audiohdiproxy/daudio_hdi_handler.cpp:RegisterAudioDevice` | 同上 | 注册分布式音频驱动 |

正确顺序：CreateDevice → SetUp控制通道 → SetUp数据通道 → RegisterHDF。顺序错误会导致设备不可用。

## 禁用流程（DisableDevice）

| 阶段 | Source端锚点 | Sink端锚点 | 关键动作 |
| --- | --- | --- | --- |
| 释放数据通道 | `managersource/dspeaker_dev.cpp:Release` | `audioclient/spkclient/dspeaker_client.cpp:Release` | 停止AudioRenderer/Capturer |
| 释放控制通道 | `audiocontrol/controlsource/daudio_source_dev_ctrl_mgr.cpp:Release` | `audiocontrol/controlsink/daudio_sink_dev_ctrl_mgr.cpp:Release` | 关闭控制传输 |
| 注销HDF | `audiohdiproxy/daudio_hdi_handler.cpp:UnRegisterAudioDevice` | 同上 | 移除分布式音频驱动 |
| 删除设备 | `managersource/daudio_source_manager.cpp:DeleteAudioDevice` | `managersink/daudio_sink_manager.cpp:ClearAudioDev` | 从audioDevMap移除 |

## 反模式/修改前检查

- **禁止**在设备未完全启用时调用Start。检查AudioStatus是否为STATUS_READY。
- **禁止**跳过控制通道直接建立数据通道。检查CTRL_OPENED事件是否已收到。
- **禁止**在销毁流程中遗漏UnRegisterAudioDevice。检查HDF驱动是否已移除。
- **禁止**直接删除audioDevMap中的设备对象。必须通过EventHandler异步删除。

## 测试指引

- 启用流程变更：使用 `DAudioSourceDevTest` / `DAudioSinkDevTest`。
- 控制通道变更：使用 `DAudioSourceCtrlTransTest` / `DAudioSinkCtrlTransTest`。
- HDF交互变更：使用 `DAudioHdiHandlerTest`。
- 涉及真实设备组网时，补充两台设备间Speaker/Mic启用验证证据。