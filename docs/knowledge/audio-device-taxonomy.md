# 设备类型分类知识

本文只记录 Speaker 和 Mic 设备的类型差异和处理路径。事件类型定义见 `audio-event-pipeline.md`，设备生命周期见 `audio-device-lifecycle.md`。

## 设备类型对比

| 属性 | Speaker（播放设备） | Mic（录音设备） |
| --- | --- | --- |
| 设备编号（dhId） | 1 | 2 |
| Source端实现 | DSpeakerDev | DMicDev |
| Sink端实现 | DSpeakerClient | DMicClient |
| 音频框架类 | AudioRenderer | AudioCapturer |
| 传输方向 | Source编码发送 → Sink解码播放 | Sink编码发送 → Source解码接收 |
| 数据流向 | Source → Sink | Sink → Source |

实现锚点：`managersource/dspeaker_dev.h` / `managersource/dmic_dev.h`

## 端侧差异

### Source端（主控端）

| 设备类型 | 数据流向 | 编解码引擎 | 传输锚点 |
| --- | --- | --- | --- |
| DSpeakerDev | 本地音频流 → 编码 → 发送到Sink | SenderEngine | `audiotransport/senderengine` |
| DMicDev | 从Sink接收 → 解码 → 本地音频流 | ReceiverEngine | `audiotransport/receiverengine` |

### Sink端（被控端）

| 设备类型 | 数据流向 | 编解码引擎 | 传输锚点 |
| --- | --- | --- | --- |
| DSpeakerClient | 从Source接收 → 解码 → AudioRenderer播放 | ReceiverEngine | `audioclient/spkclient` |
| DMicClient | AudioCapturer采集 → 编码 → 发送到Source | SenderEngine | `audioclient/micclient` |

## 事件编号规则

| 设备类型 | 事件编号范围 | 打开事件 | 打开成功事件 | 关闭事件 |
| --- | --- | --- | --- | --- |
| Speaker | 11-17 | OPEN_SPEAKER(11) | SPEAKER_OPENED(13) | CLOSE_SPEAKER(12) |
| Mic | 21-27 | OPEN_MIC(21) | MIC_OPENED(23) | CLOSE_MIC(22) |

编号规则锚点：`services/common/audioparam/audio_event.h:34-48`

## 处理路径差异

| 操作 | Speaker路径 | Mic路径 |
| --- | --- | --- |
| Source端启用 | EnableDSpeaker → CreateSpkEngine | EnableDMic → CreateMicEngine |
| Source端打开 | TaskOpenDSpeaker → OpenDSpeakerInner | TaskOpenDMic |
| Sink端打开 | TaskOpenDSpeaker → SetUp renderer | TaskOpenDMic → SetUp capturer |
| Sink端启动 | StartRender | StartCapture |

关键判断：通过dhId区分设备类型，dhId=1为Speaker，dhId=2为Mic。

## 反模式/修改前检查

- **禁止**混淆Speaker和Mic的事件编号。Speaker用11开头，Mic用21开头。
- **禁止**在Speaker路径使用SenderEngine（Source端应为Mic专用）。检查引擎类型是否匹配数据流向。
- **禁止**在Mic路径使用ReceiverEngine（Source端应为Speaker专用）。
- **禁止**遗漏dhId判断逻辑。修改设备处理代码时必须检查dhId值。

## 测试指引

- Speaker设备变更：使用 `DSpeakerDevTest` / `DSpeakerClientTest`。
- Mic设备变更：使用 `DMicDevTest` / `DMicClientTest`。