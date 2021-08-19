/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <immer/map.hpp>
#include <immer/flex_vector.hpp>

namespace Kazv
{
    struct DeviceKeyInfo;

    using DeviceMap = immer::map<std::string, DeviceKeyInfo>;
    using DeviceIdList = immer::flex_vector<std::string>;
    using UserIdToDeviceIdMap = immer::map<std::string, DeviceIdList>;
}
