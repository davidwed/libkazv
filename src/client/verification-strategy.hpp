/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <libkazv-config.hpp>

#include <immer/flex_vector.hpp>
#include <immer/map.hpp>

#include "device-list-tracker.hpp"

namespace Kazv
{
    using DeviceMap = immer::map<std::string, DeviceKeyInfo>;

    enum VerificationStrategy
    {
        TrustAllStrategy,
        VerifyAllStrategy,
        TrustIfNeverVerifiedStrategy,
    };

    immer::flex_vector<std::string> devicesToSend(VerificationStrategy strategy, DeviceMap devices);
}
