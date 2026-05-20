# 音频传输管道知识

本文只记录音频数据传输和控制通道的实现。设备类型差异见 `audio-device-taxonomy.md`，事件流转见 `audio-event-pipeline.md`。

## 双通道架构

| 通道类型 | 职责 | 实现模块 | 建立时机 |
| --- | --- | --- | --- |
| 控制通道 | 事件指令传输 | DAudioCtrlTrans | 设备启用时首先建立 |
| 数据通道 | 音频流传输 | AVEngineTransport | 控制通道建立后建立 |

顺序约束：必须先建立控制通道（收到CTRL_OPENED），再建立数据通道。

## 控制通道

| 端侧 | 实现类 | 锚点 | 事件回调 |
| --- | --- | --- | --- |
| Source | DAudioSourceCtrlTrans | `audiotransport/audioctrltransport/daudio_source_ctrl_trans.h` | OnCtrlTransEvent |
| Sink | DAudioSinkCtrlTrans | `audiotransport/audioctrltransport/daudio_sink_ctrl_trans.h` | OnCtrlTransEvent |

控制通道生命周期：SetUp → Start → Stop → Release。锚点：`audiocontrol/controlsource/daudio_source_dev_ctrl_mgr.cpp`

## 数据传输引擎

| 引擎类型 | 职责 | 使用场景 | 锚点 |
| --- | --- | --- | --- |
| SenderEngine | 编码并发送音频数据 | Source端Speaker / Sink端Mic | `audiotransport/senderengine/av_sender_engine_transport.h` |
| ReceiverEngine | 接收并解码音频数据 | Source端Mic / Sink端Speaker | `audiotransport/receiverengine/av_receiver_engine_transport.h` |

### SenderEngine管道（发送端）

| 阶段 | 方法 | 输入 | 输出 |
| --- | --- | --- | --- |
| 配置 | SetUp | AudioParam本地/远端参数 | 创建编码器 |
| 启动 | Start | 无 | 开始编码发送 |
| 输入数据 | FeedAudioData | 原始音频数据 | 编码后发送 |
| 停止 | Stop | 无 | 停止编码 |

### ReceiverEngine管道（接收端）

| 阶段 | 方法 | 输入 | 输出 |
| --- | --- | --- | --- |
| 配置 | SetUp | AudioParam本地/远端参数 | 创建解码器 |
| 启动 | Start | 无 | 开始接收解码 |
| 接收数据 | OnEngineTransDataAvailable | 编码音频数据 | 解码后回调OnDecodeTransDataDone |
| 停止 | Stop | 无 | 停止解码 |

## 数据流管道

Speaker播放（Source→Sink）：
```
[Source] AudioRenderer回调 → FeedAudioData → SenderEngine编码 → SoftBus传输
    ↓
[Sink] ReceiverEngine接收 → OnDecodeTransDataDone → dataQueue → PlayThread播放
```

Mic录音（Sink→Source）：
```
[Sink] AudioCapturer回调 → OnReadData → SenderEngine编码 → SoftBus传输
    ↓
[Source] ReceiverEngine接收 → OnDecodeTransDataDone → 本地音频框架
```

## 反模式/修改前检查

- **禁止**跳过控制通道直接建立数据通道。检查IsOpened()返回true后再建立数据通道。
- **禁止**在编码线程直接操作AudioRenderer/AudioCapturer。必须通过回调异步处理。
- **禁止**修改FeedAudioData的数据格式。必须匹配AudioParam中定义的codecType。
- **禁止**遗漏dataQueue的线程安全保护。dataQueueMtx必须保护dataQueue操作。

## 测试指引

- 控制通道变更：使用 `DAudioSourceCtrlTransTest` / `DAudioSinkCtrlTransTest`。
- 发送引擎变更：使用 `AVSenderEngineTransportTest` / `AVSenderEngineAdapterTest`。
- 接收引擎变更：使用 `AVReceiverEngineTransportTest` / `AVReceiverEngineAdapterTest`。