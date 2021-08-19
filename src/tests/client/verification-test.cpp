/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch.hpp>

#include <boost/asio.hpp>
#include <asio-promise-handler.hpp>

#include <verification-strategy.hpp>
#include <client-model.hpp>

#include <client-types.hpp>

#include "client-test-util.hpp"

using namespace Kazv;

using DeviceMapT = DeviceMap;

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

TEST_CASE("check unknown sessions according to trust level and verification strategy", "[client][verification]")
{
    ClientModel c;
    c.deviceLists.deviceLists = immer::map<std::string, DeviceMapT>()
        .set("@u1:e.o", devMap1)
        .set("@u2:e.o", devMap2)
        .set("@u3:e.o", devMap3)
        .set("@u4:e.o", devMap4);

    c.verificationStrategy = TrustAllStrategy;
    REQUIRE(isEquiv(c.devicesToSendKeys("@u1:e.o"), {"foo", "bar", "doge"}));
    REQUIRE(isEquiv(c.unknownDevices("@u1:e.o"), {}));

    c.verificationStrategy = VerifyAllStrategy;
    REQUIRE(isEquiv(c.devicesToSendKeys("@u1:e.o"), {"doge"}));
    REQUIRE(isEquiv(c.unknownDevices("@u1:e.o"), {"foo"}));

    c.verificationStrategy = TrustIfNeverVerifiedStrategy;
    REQUIRE(isEquiv(c.devicesToSendKeys("@u1:e.o"), {"doge"}));
    REQUIRE(isEquiv(c.devicesToSendKeys("@u2:e.o"), {"foo", "bar"}));
    REQUIRE(isEquiv(c.unknownDevices("@u1:e.o"), {"foo"}));
    REQUIRE(isEquiv(c.unknownDevices("@u2:e.o"), {}));
}

TEST_CASE("SetVerificationStrategyAction should work", "[client][verification]")
{
    ClientModel c;
    auto [c1, _ignore] = ClientModel::update(c, SetVerificationStrategyAction{TrustAllStrategy});
    REQUIRE(c1.verificationStrategy == TrustAllStrategy);

    auto [c2, _ignore2] = ClientModel::update(c1, SetVerificationStrategyAction{VerifyAllStrategy});
    REQUIRE(c2.verificationStrategy == VerifyAllStrategy);
}

static void addRoomMember(RoomModel &r, std::string userId)
{
    auto memberEv = Event{json{
        {"state_key", userId},
        {"type", "m.room.member"},
        {"origin_server_ts", 1},
        {"room_id", r.roomId},
        {"content", {
            {"membership", "join"},
            {"displayname", userId},
        }},
        {"sender", userId},
        {"event_id", "$" + userId},
    }};
    r.stateEvents = std::move(r.stateEvents)
        .set(keyOfState(memberEv), memberEv);
}

TEST_CASE("Check for unknown sessions in Room", "[client][verification]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto initModel = ClientModel{};

    initModel.deviceLists.deviceLists =
        immer::map<std::string, DeviceMapT>()
        .set("@u1:e.o", devMap1)
        .set("@u2:e.o", devMap2)
        .set("@u3:e.o", devMap3)
        .set("@u4:e.o", devMap4);

    auto exampleRoom = RoomModel{};

    auto roomId = std::string("!example:room.org");
    exampleRoom.roomId = roomId;
    addRoomMember(exampleRoom, "@u1:e.o");
    addRoomMember(exampleRoom, "@u2:e.o");
    addRoomMember(exampleRoom, "@u3:e.o");
    addRoomMember(exampleRoom, "@u4:e.o");

    initModel.roomList.rooms = initModel.roomList.rooms.set(
        roomId, exampleRoom);

    initModel.verificationStrategy = TrustIfNeverVerifiedStrategy;

    auto store = createTestClientStoreFrom(initModel, ph);

    auto client = clientFromStoreWithoutDeps(store);

    auto r = client.room("!example:room.org");

    REQUIRE(+r.hasUnknownDevices());

    auto expectedUnknownDevices =
        UserIdToDeviceIdMap{}
        .set("@u1:e.o", DeviceIdList{"foo"});

    REQUIRE(+r.unknownDevices() == expectedUnknownDevices);
}
