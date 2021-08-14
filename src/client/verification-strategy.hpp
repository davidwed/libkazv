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
    /**
     * A map from device id to DeviceKeyInfo
     */
    using DeviceMap = immer::map<std::string, DeviceKeyInfo>;

    enum VerificationStrategy
    {
        /**
         * Send to every not-blocked device, no device is unknown.
         */
        TrustAllStrategy,
        /**
         * Send to every verified device, unseen devices are unknown.
         */
        VerifyAllStrategy,
        /**
         * If we have not verified any device of a particular user,
         * send to every non-blocked device, no device is unknown.
         *
         * If we have verified any device of a particular user,
         * send to every verified device, unseen devices are unknown.
         */
        TrustIfNeverVerifiedStrategy,
    };

    /**
     * Return the devices we should send messages to without making the user confirm manually
     * among `devices`, according to `strategy`.
     */
    immer::flex_vector<std::string> devicesToSend(VerificationStrategy strategy, DeviceMap devices);

    /**
     * Return the devices we should make the user confirm manually before sending any messages
     * among `devices`, according to `strategy`.
     */
    immer::flex_vector<std::string> unknownDevices(VerificationStrategy strategy, DeviceMap devices);
}
