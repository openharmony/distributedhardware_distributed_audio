# 音频事件流转知识

本文只记录 AudioEventType 定义和事件处理路由。设备生命周期见 `audio-device-lifecycle.md`，Source/Sink架构见 `audio-source-sink-architecture.md`。

## 事件类型分类

| 分类 | 编号范围 | 关键事件 | 处理模块 |
| --- | --- | --- | --- |
| 控制通道 | 1-8 | OPEN_CTRL(1), CTRL_OPENED(3), CLOSE_CTRL(2), CTRL_CLOSED(4) | DAudioCtrlTrans |
| Speaker设备 | 11-17 | OPEN_SPEAKER(11), SPEAKER_OPENED(13), CLOSE_SPEAKER(12), SPEAKER_CLOSED(14) | DSpeakerDev/DSpeakerClient |
| Mic设备 | 21-27 | OPEN_MIC(21), MIC_OPENED(23), CLOSE_MIC(22), MIC_CLOSED(24) | DMicDev/DMicClient |
| 音量控制 | 31-36 | VOLUME_SET(31), VOLUME_CHANGE(33), VOLUME_MUTE_SET(36) | DAudioCtrlMgr |
| 音频焦点 | 41-42 | AUDIO_FOCUS_CHANGE(41), AUDIO_RENDER_STATE_CHANGE(42) | DAudioCtrlMgr |
| 参数设置 | 51-53 | SET_PARAM(51), ENHANCE_PARAM_CHANGE(53) | DAudioClient |
| 编解码错误 | 61-62 | AUDIO_ENCODER_ERR(61), AUDIO_DECODER_ERR(62) | AVEngine |
| MMAP模式 | 81-86 | MMAP_SPK_START(81), MMAP_MIC_START(83), AUDIO_START(85) | DAudioIoDev |

事件枚举锚点：`services/common/audioparam/audio_event.h:23-76`

## 事件处理路由

Source端事件处理函数映射：

| 事件类型 | 处理函数 | 锚点 |
| --- | --- | --- |
| OPEN_SPEAKER | HandleOpenDSpeaker | `managersource/daudio_source_dev.cpp` |
| SPEAKER_OPENED | HandleDSpeakerOpened | 同上 |
| CLOSE_SPEAKER | HandleCloseDSpeaker | 同上 |
| VOLUME_SET | HandleVolumeSet | 同上 |
| VOLUME_CHANGE | HandleVolumeChange | 同上 |

Source端路由通过memberFuncMap_实现：`managersource/daudio_source_dev.h:213-214`

Sink端事件处理函数映射：

| 事件类型 | 处理函数 | 锚点 |
| --- | --- | --- |
| OPEN_SPEAKER | TaskOpenDSpeaker | `managersink/daudio_sink_dev.cpp` |
| SPEAKER_OPENED | NotifySpeakerOpened | SinkEventHandler |
| VOLUME_SET | TaskSetVolume | 同上 |

## 事件流转管道

```
[发送端] NotifyEvent → SendAudioEventToRemote → IAudioCtrlTransport → SoftBus
    ↓
[接收端] OnCtrlTransEvent → EventHandler → ProcessEvent → 处理函数
```

关键：所有事件必须经过EventHandler异步处理，禁止在回调线程直接处理。

## 反模式/修改前检查

- **禁止**新增事件类型时使用已有编号。Speaker用11-17，Mic用21-27，避免编号冲突。
- **禁止**在回调线程（OnCtrlTransEvent）直接修改设备状态。必须通过EventHandler转发。
- **禁止**遗漏事件处理函数注册。检查memberFuncMap_是否包含新事件类型。
- **禁止**发送未定义的事件类型。检查AudioEventType枚举是否包含。

## 测试指引

- 事件处理变更：使用 `DAudioSourceDevTest` / `DAudioSinkDevTest`。
- 控制通道变更：使用 `DAudioCtrlChannelListenerTest`。