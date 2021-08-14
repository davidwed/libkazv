/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch.hpp>

#include <verification-strategy.hpp>
#include <client-model.hpp>

using namespace Kazv;

using DeviceMapT = immer::map<std::string, DeviceKeyInfo>;
using DeviceIdList = immer::flex_vector<std::string>;

static DeviceKeyInfo genInfo(std::string id, DeviceTrustLevel level)
{
    return {id, "", "", std::nullopt, level};
}

static bool isSuperset(DeviceIdList set, DeviceIdList pattern)
{
    return immer::all_of(set.begin(), set.end(),
                         [pattern](std::string id) {
                             return std::find(pattern.begin(), pattern.end(), id) != pattern.end();
                         });
}

static bool isEquiv(DeviceIdList set, DeviceIdList pattern)
{
    return isSuperset(set, pattern) && isSuperset(pattern, set);
}

static DeviceMapT devMap1 =
    DeviceMapT()
    .set("foo", genInfo("foo", Unseen))
    .set("bar", genInfo("bar", Seen))
    .set("baz", genInfo("baz", Blocked))
    .set("doge", genInfo("doge", Verified));

static DeviceMapT devMap2 =
    DeviceMapT()
    .set("foo", genInfo("foo", Unseen))
    .set("bar", genInfo("bar", Seen))
    .set("baz", genInfo("baz", Blocked));

static DeviceMapT devMap3 =
    DeviceMapT()
    .set("bar", genInfo("bar", Seen))
    .set("baz", genInfo("baz", Blocked))
    .set("doge", genInfo("doge", Verified));

static DeviceMapT devMap4 =
    DeviceMapT()
    .set("bar", genInfo("bar", Seen))
    .set("baz", genInfo("baz", Blocked));


TEST_CASE("verification strategies should work", "[client][verification]")
{
    REQUIRE(isEquiv(devicesToSend(TrustAllStrategy, devMap1), {"foo", "bar", "doge"}));

    REQUIRE(isEquiv(devicesToSend(VerifyAllStrategy, devMap1), {"doge"}));

    REQUIRE(isEquiv(devicesToSend(TrustIfNeverVerifiedStrategy, devMap1), {"doge"}));

    REQUIRE(isEquiv(devicesToSend(TrustIfNeverVerifiedStrategy, devMap2), {"foo", "bar"}));

    REQUIRE(isEquiv(unknownDevices(TrustAllStrategy, devMap1), {}));

    REQUIRE(isEquiv(unknownDevices(VerifyAllStrategy, devMap1), {"foo"}));

    REQUIRE(isEquiv(unknownDevices(TrustIfNeverVerifiedStrategy, devMap1), {"foo"}));

    REQUIRE(isEquiv(unknownDevices(TrustIfNeverVerifiedStrategy, devMap2), {}));
}
