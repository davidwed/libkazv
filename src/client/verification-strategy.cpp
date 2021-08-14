/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <immer/algorithm.hpp>

#include "cursorutil.hpp"

#include "verification-strategy.hpp"

namespace Kazv
{
    immer::flex_vector<std::string> devicesToSend(VerificationStrategy strategy, DeviceMap devMap)
    {
        auto extractDevInfoF = [](auto node) { return node.second; };
        auto extractDevInfo = zug::map(extractDevInfoF);
        auto notBlockedP = [](auto dev) {
                               return dev.trustLevel > Blocked;
                           };
        auto verifiedP = [](auto dev) {
                             return dev.trustLevel >= Verified;
                         };

        auto notVerifiedP = [verifiedP](auto dev) { return !verifiedP(std::move(dev)); };

        auto devInfoToId = zug::map([](auto dev) { return dev.deviceId; });

        if (strategy == TrustAllStrategy) {
            return intoImmer(immer::flex_vector<std::string>{},
                             extractDevInfo | zug::filter(notBlockedP) | devInfoToId,
                             devMap);
        } else if (strategy == VerifyAllStrategy) {
            return intoImmer(immer::flex_vector<std::string>{},
                             extractDevInfo | zug::filter(verifiedP) | devInfoToId,
                             devMap);
        } else if (strategy == TrustIfNeverVerifiedStrategy) {
            if (std::all_of(devMap.begin(), devMap.end(),
                            [=](auto node) {
                                return notVerifiedP(extractDevInfoF(std::move(node)));
                            })) {
                return intoImmer(immer::flex_vector<std::string>{},
                                 extractDevInfo | zug::filter(notBlockedP) | devInfoToId, devMap);
            } else {
                return intoImmer(immer::flex_vector<std::string>{},
                                 extractDevInfo | zug::filter(verifiedP) | devInfoToId, devMap);
            }
        } else {
            assert(false);
            return {};
        }
    }

    immer::flex_vector<std::string> unknownDevices(VerificationStrategy strategy, DeviceMap devMap)
    {
        auto extractDevInfoF = [](auto node) { return node.second; };
        auto extractDevInfo = zug::map(extractDevInfoF);
        auto notBlockedP = [](auto dev) {
            return dev.trustLevel > Blocked;
        };
        auto verifiedP = [](auto dev) {
            return dev.trustLevel >= Verified;
        };
        auto unseenP = [](auto dev) {
            return dev.trustLevel == Unseen;
        };

        auto notVerifiedP = [verifiedP](auto dev) { return !verifiedP(std::move(dev)); };

        auto devInfoToId = zug::map([](auto dev) { return dev.deviceId; });

        if (strategy == TrustAllStrategy) {
            return {};
        } else if (strategy == VerifyAllStrategy) {
            return intoImmer(
                immer::flex_vector<std::string>{},
                extractDevInfo | zug::filter(unseenP) | devInfoToId,
                devMap
            );
        } else if (strategy == TrustIfNeverVerifiedStrategy) {
            if (std::all_of(devMap.begin(), devMap.end(),
                [=](auto node) {
                    return notVerifiedP(extractDevInfoF(std::move(node)));
                })) {
                return {};
            } else {
                return intoImmer(
                    immer::flex_vector<std::string>{},
                    extractDevInfo | zug::filter(unseenP) | devInfoToId,
                    devMap
                );
            }
        } else {
            assert(false);
            return {};
        }
    }
}
