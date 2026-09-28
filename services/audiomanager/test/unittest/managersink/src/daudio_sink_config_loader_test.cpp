/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "daudio_sink_config_loader_test.h"

#include "cJSON.h"
#include "daudio_constants.h"
#include "daudio_errorcode.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioSinkCfgLoaderTest"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr const char *COMPONENT_ENABLE_CONFIG = "component_enable_config";
constexpr const char *AUDIO_TYPE_NAME = "AUDIO";
}

void DAudioSinkConfigLoaderTest::SetUpTestCase(void) {}
void DAudioSinkConfigLoaderTest::TearDownTestCase(void) {}
void DAudioSinkConfigLoaderTest::SetUp()
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    loader.isInitialized_ = false;
}
void DAudioSinkConfigLoaderTest::TearDown()
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    loader.isInitialized_ = false;
}

struct SubtypeConfig {
    bool present = false;
    bool isBool = false;
    bool sinkVal = false;
};

static cJSON *BuildEnableConfigJson(const SubtypeConfig &micCfg, const SubtypeConfig &spkCfg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    if (micCfg.present) {
        if (micCfg.isBool) {
            cJSON_AddBoolToObject(audioEntry, MIC.c_str(), micCfg.sinkVal);
        } else {
            cJSON *micObj = cJSON_CreateObject();
            cJSON_AddBoolToObject(micObj, "sink", micCfg.sinkVal);
            cJSON_AddBoolToObject(micObj, "source", true);
            cJSON_AddItemToObject(audioEntry, MIC.c_str(), micObj);
        }
    }
    if (spkCfg.present) {
        if (spkCfg.isBool) {
            cJSON_AddBoolToObject(audioEntry, SPEAKER.c_str(), spkCfg.sinkVal);
        } else {
            cJSON *spkObj = cJSON_CreateObject();
            cJSON_AddBoolToObject(spkObj, "sink", spkCfg.sinkVal);
            cJSON_AddBoolToObject(spkObj, "source", true);
            cJSON_AddItemToObject(audioEntry, SPEAKER.c_str(), spkObj);
        }
    }
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    return root;
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_001, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    cJSON *root = BuildEnableConfigJson({true, false, false}, {true, false, false});
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_002, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    cJSON *root = BuildEnableConfigJson({true, true, false}, {true, true, true});
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_TRUE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_003, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    cJSON *root = BuildEnableConfigJson({true, false, true}, {true, false, true});
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_TRUE(loader.micSinkEnabled_);
    EXPECT_TRUE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_004, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = BuildEnableConfigJson({false, false, false}, {false, false, false});
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_005, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_006, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_007, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_008, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    cJSON *root = BuildEnableConfigJson({true, false, false}, {false, false, false});
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_TRUE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_009, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    loader.speakerSinkEnabled_ = true;
    cJSON *root = BuildEnableConfigJson({false, false, false}, {true, false, false});
    ASSERT_NE(root, nullptr);
    loader.ParseAudioEnableConfig(root);
    EXPECT_TRUE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_nullptr, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    loader.ParseAudioEnableConfig(nullptr);
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
}

HWTEST_F(DAudioSinkConfigLoaderTest, Init_already_initialized, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.isInitialized_ = true;
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    EXPECT_EQ(DH_SUCCESS, loader.Init());
    EXPECT_FALSE(loader.micSinkEnabled_);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
}

HWTEST_F(DAudioSinkConfigLoaderTest, Init_not_initialized, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.isInitialized_ = false;
    EXPECT_EQ(DH_SUCCESS, loader.Init());
    EXPECT_TRUE(loader.isInitialized_);
}

HWTEST_F(DAudioSinkConfigLoaderTest, IsMicSinkEnabled_default, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = true;
    EXPECT_TRUE(loader.IsMicSinkEnabled());
}

HWTEST_F(DAudioSinkConfigLoaderTest, IsMicSinkEnabled_disabled, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    EXPECT_FALSE(loader.IsMicSinkEnabled());
}

HWTEST_F(DAudioSinkConfigLoaderTest, IsSpeakerSinkEnabled_default, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.speakerSinkEnabled_ = true;
    EXPECT_TRUE(loader.IsSpeakerSinkEnabled());
}

HWTEST_F(DAudioSinkConfigLoaderTest, IsSpeakerSinkEnabled_disabled, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.speakerSinkEnabled_ = false;
    EXPECT_FALSE(loader.IsSpeakerSinkEnabled());
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_mic_not_bool_not_object, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON_AddNumberToObject(audioEntry, MIC.c_str(), 123);
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_mic_object_no_sink, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON *micObj = cJSON_CreateObject();
    cJSON_AddBoolToObject(micObj, "source", true);
    cJSON_AddItemToObject(audioEntry, MIC.c_str(), micObj);
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_mic_object_sink_not_bool, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON *micObj = cJSON_CreateObject();
    cJSON_AddNumberToObject(micObj, "sink", 123);
    cJSON_AddItemToObject(audioEntry, MIC.c_str(), micObj);
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.micSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_spk_not_bool_not_object, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON_AddNumberToObject(audioEntry, SPEAKER.c_str(), 123);
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_spk_object_no_sink, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON *spkObj = cJSON_CreateObject();
    cJSON_AddBoolToObject(spkObj, "source", true);
    cJSON_AddItemToObject(audioEntry, SPEAKER.c_str(), spkObj);
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}

HWTEST_F(DAudioSinkConfigLoaderTest, ParseAudioEnableConfig_spk_object_sink_not_bool, TestSize.Level1)
{
    auto &loader = DAudioSinkConfigLoader::GetInstance();
    loader.micSinkEnabled_ = false;
    loader.speakerSinkEnabled_ = false;
    cJSON *root = cJSON_CreateObject();
    cJSON *enableConfig = cJSON_CreateObject();
    cJSON *audioEntry = cJSON_CreateObject();
    cJSON *spkObj = cJSON_CreateObject();
    cJSON_AddNumberToObject(spkObj, "sink", 123);
    cJSON_AddItemToObject(audioEntry, SPEAKER.c_str(), spkObj);
    cJSON_AddItemToObject(enableConfig, AUDIO_TYPE_NAME, audioEntry);
    cJSON_AddItemToObject(root, COMPONENT_ENABLE_CONFIG, enableConfig);
    loader.ParseAudioEnableConfig(root);
    EXPECT_FALSE(loader.speakerSinkEnabled_);
    cJSON_Delete(root);
}
} // namespace DistributedHardware
} // namespace OHOS
