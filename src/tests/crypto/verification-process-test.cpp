/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch.hpp>

#include <iostream>

#include <verification-process.hpp>
#include <verification-tracker.hpp>

#include <debug.hpp>

using namespace Kazv;

// Taken from https://matrix.org/docs/spec/client_server/r0.6.1
static auto requestEvent = R"({
    "content": {
        "from_device": "AliceDevice2",
        "methods": [
            "m.sas.v1"
        ],
        "timestamp": 1559598944869,
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.request"
})"_json;

static auto requestEventUnsupportedMethod = R"({
    "content": {
        "from_device": "AliceDevice2",
        "methods": [
            "moe.kazv.mxc.fake-method"
        ],
        "timestamp": 1559598944869,
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.request"
})"_json;

static auto requestEventMultiMethods = R"({
    "content": {
        "from_device": "AliceDevice2",
        "methods": [
            "m.sas.v1",
            "moe.kazv.mxc.fake-method"
        ],
        "timestamp": 1559598944869,
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.request"
})"_json;

static auto startEvent = R"({
    "content": {
        "from_device": "BobDevice1",
        "method": "m.sas.v1",
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.start"
})"_json;

static auto startEventUnsupportedMethod = R"({
    "content": {
        "from_device": "BobDevice1",
        "method": "moe.kazv.mxc.fake-method",
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.start"
})"_json;

static auto cancelEvent = R"({
    "content": {
        "code": "m.user",
        "reason": "User rejected the key verification request",
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.cancel"
})"_json;

static auto sasStartEvent = R"({
    "content": {
        "from_device": "BobDevice1",
        "hashes": [
            "sha256"
        ],
        "key_agreement_protocols": [
            "curve25519"
        ],
        "message_authentication_codes": [
            "hkdf-hmac-sha256"
        ],
        "method": "m.sas.v1",
        "short_authentication_string": [
            "decimal",
            "emoji"
        ],
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.start"
})"_json;

static auto sasAcceptEvent = R"({
    "content": {
        "commitment": "fQpGIW1Snz+pwLZu6sTy2aHy/DYWWTspTJRPyNp0PKkymfIsNffysMl6ObMMFdIJhk6g6pwlIqZ54rxo8SLmAg",
        "hash": "sha256",
        "key_agreement_protocol": "curve25519",
        "message_authentication_code": "hkdf-hmac-sha256",
        "method": "m.sas.v1",
        "short_authentication_string": [
            "decimal",
            "emoji"
        ],
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.accept"
})"_json;

static auto sasKeyEvent = R"({
    "content": {
        "key": "fQpGIW1Snz+pwLZu6sTy2aHy/DYWWTspTJRPyNp0PKkymfIsNffysMl6ObMMFdIJhk6g6pwlIqZ54rxo8SLmAg",
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.key"
})"_json;

static auto sasMacEvent = R"({
    "content": {
        "keys": "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA",
        "mac": {
            "ed25519:ABCDEF": "fQpGIW1Snz+pwLZu6sTy2aHy/DYWWTspTJRPyNp0PKkymfIsNffysMl6ObMMFdIJhk6g6pwlIqZ54rxo8SLmAg"
        },
        "transaction_id": "S0meUniqueAndOpaqueString"
    },
    "type": "m.key.verification.mac"
})"_json;

static auto unknownEvent = R"({
    "content": {
        "transaction_id": "xxx"
    },
    "type": "moe.kazv.mxc.key.verification.unknown"
})"_json;

static auto malformedEvent = R"({
    "type": "moe.kazv.mxc.key.verification.unknown"
})"_json;

static bool displays(const VerificationTrackerAction &action)
{
    return
        std::holds_alternative<VerificationTrackerActions::DisplayCodes>(action)
        || std::holds_alternative<VerificationTrackerActions::ShowStatus>(action);
}

static bool displaysCode(const VerificationTrackerAction &action)
{
    return std::holds_alternative<VerificationTrackerActions::DisplayCodes>(action);
}

static bool displaysNothing(VerificationTrackerResult res)
{
    return std::all_of(res.begin(), res.end(), [](const auto &action) {
        return !displays(action);
    });
}

static bool sendsEventOfType(VerificationTrackerResult res, std::string type)
{
    return std::any_of(res.begin(), res.end(), [=](const auto &action) {
        return std::holds_alternative<VerificationTrackerActions::SendEvent>(action)
            && std::get<VerificationTrackerActions::SendEvent>(action)
            .event
            .at("type")
            .template get<std::string>() == type;
    });
}

static bool sendsCancellation(VerificationTrackerResult res)
{
    return sendsEventOfType(res, "m.key.verification.cancel");
}

static bool sendsRequest(VerificationTrackerResult res)
{
    return sendsEventOfType(res, "m.key.verification.request");
}

static bool sendsStart(VerificationTrackerResult res)
{
    return sendsEventOfType(res, "m.key.verification.start");
}

static bool sendsAccept(VerificationTrackerResult res)
{
    return sendsEventOfType(res, "m.key.verification.accept");
}

static bool sendsKey(VerificationTrackerResult res)
{
    return sendsEventOfType(res, "m.key.verification.key");
}

static bool sendsMac(VerificationTrackerResult res)
{
    return sendsEventOfType(res, "m.key.verification.mac");
}

static nlohmann::json firstEventSent(VerificationTrackerResult res)
{
    auto it = std::find_if(res.begin(), res.end(), [](const auto &action) {
        return std::holds_alternative<VerificationTrackerActions::SendEvent>(action);
    });
    return std::get<VerificationTrackerActions::SendEvent>(*it).event;
}

static nlohmann::json firstEventSentOfType(VerificationTrackerResult res, std::string type)
{
    auto it = std::find_if(res.begin(), res.end(), [type](const auto &action) {
        auto isEvent = std::holds_alternative<VerificationTrackerActions::SendEvent>(action);
        if (!isEvent) {
            return false;
        }

        auto event = std::get<VerificationTrackerActions::SendEvent>(action).event;
        return event.contains("type") && event["type"] == type;
    });
    return std::get<VerificationTrackerActions::SendEvent>(*it).event;
}


static bool sendsNothing(VerificationTrackerResult res)
{
    return std::all_of(res.begin(), res.end(), [](const auto &action) {
        return !std::holds_alternative<VerificationTrackerActions::SendEvent>(action);
    });
}

// TEST_CASE("Construct sas verification process", "[client][verification-proc]")
// {
//     auto proc1 = SASVerificationProcess();

//     REQUIRE(!proc1.valid());

//     auto proc2 = SASVerificationProcess(RandomTag{}, );
// }

TEST_CASE("VerificationTracker is a value type", "[client][verification-proc]")
{
    auto tracker = VerificationTracker{};

    auto tracker2 = tracker;
    (void) tracker2;

    auto tracker3 = std::move(tracker);
    (void) tracker3;
}

TEST_CASE("VerificationTracker processRandomSize", "[client][verification-proc]")
{
    auto sasConstructRandomSize = SASVerificationProcess::constructRandomSize();
    REQUIRE(sasConstructRandomSize != 0);

    REQUIRE(VerificationTracker::processRandomSize(requestEvent) == sasConstructRandomSize);
    REQUIRE(VerificationTracker::processRandomSize(requestEventUnsupportedMethod) == 0);
    REQUIRE(VerificationTracker::processRandomSize(requestEventMultiMethods) == sasConstructRandomSize);

    REQUIRE(VerificationTracker::processRandomSize(startEvent) == sasConstructRandomSize);
    REQUIRE(VerificationTracker::processRandomSize(sasStartEvent) == sasConstructRandomSize);
    REQUIRE(VerificationTracker::processRandomSize(startEventUnsupportedMethod) == 0);

    REQUIRE(VerificationTracker::processRandomSize(cancelEvent) == 0);

    REQUIRE(VerificationTracker::processRandomSize(sasAcceptEvent) == 0);

    REQUIRE(VerificationTracker::processRandomSize(sasKeyEvent) == 0);

    REQUIRE(VerificationTracker::processRandomSize(sasMacEvent) == 0);

    REQUIRE(VerificationTracker::processRandomSize(unknownEvent) == 0);
    REQUIRE(VerificationTracker::processRandomSize(malformedEvent) == 0);
}

TEST_CASE("VerificationTracker process() error handling", "[client][verification-proc]")
{
    auto reqRandomSize = VerificationTracker::processRandomSize(requestEvent);
    auto random = genRandomData(reqRandomSize);

    auto tracker = VerificationTracker{};

    auto afterReasonablyShortTime = requestEvent["content"]["timestamp"].template get<Timestamp>() + 1;
    auto uid = std::string("@u:a.b");

    WHEN ("processing a request way long ago") {
        auto afterTenMins = requestEvent["content"]["timestamp"].template get<Timestamp>() + 10 * 60 * 1000 + 1;
        auto res = tracker.process(uid, requestEvent, random, afterTenMins);

        THEN ("we should ignore and send cancellation") {
            REQUIRE(displaysNothing(res));
            REQUIRE(sendsCancellation(res));
        }
    }

    WHEN ("processing a request way in the future") {
        auto beforeFiveMins = requestEvent["content"]["timestamp"].template get<Timestamp>() - 5 * 60 * 1000 - 1;
        auto res = tracker.process(uid, requestEvent, random, beforeFiveMins);

        THEN ("we should ignore and send cancellation") {
            REQUIRE(displaysNothing(res));
            REQUIRE(sendsCancellation(res));
        }
    }

    WHEN ("processing a non-request, non-cancel event whose transaction id is never encountered") {
        auto res = tracker.process(uid, sasAcceptEvent, random, afterReasonablyShortTime);
        THEN ("we should ignore and send cancellation") {
            REQUIRE(displaysNothing(res));
            REQUIRE(sendsCancellation(res));
        }
    }

    WHEN ("processing a cancel event whose transaction id is never encountered") {
        auto res = tracker.process(uid, cancelEvent, random, afterReasonablyShortTime);
        THEN ("we should ignore only") {
            REQUIRE(displaysNothing(res));
            REQUIRE(sendsNothing(res));
        }
    }
}

TEST_CASE("VerificationTracker full process", "[client][verification-proc]")
{
    auto aliceUid = std::string("@alice:example.org");
    auto bobUid = std::string("@bob:example.org");
    auto alice = VerificationTracker(aliceUid, "AliceDevice1");
    auto bob = VerificationTracker(bobUid, "BobDevice1");

    auto ts = 1000;
    auto requestRes = alice.requestVerification(bobUid, {"BobDevice1"}, ts);

    THEN ("Alice should send a request event and notify") {
        REQUIRE(sendsRequest(requestRes));
    }
    auto requestEvent = firstEventSent(requestRes);

    auto processRequestRes = bob.process(aliceUid, requestEvent,
        genRandomData(VerificationTracker::processRandomSize(requestEvent)), ts);
    THEN ("Bob should notify first and start sas") {
        REQUIRE(displays(processRequestRes.at(0)));
        REQUIRE(sendsStart(processRequestRes));
    }
    auto startEvent = firstEventSentOfType(processRequestRes, "m.key.verification.start");
    kzo.crypto.dbg() << "startEvent is " << startEvent.dump() << std::endl;

    auto processStartRes = alice.process(bobUid, startEvent,
        genRandomData(VerificationTracker::processRandomSize(startEvent)), ts);
    THEN ("Alice should notify first and accept sas") {
        REQUIRE(displays(processStartRes.at(0)));
        REQUIRE(sendsAccept(processStartRes));
    }
    auto acceptEvent = firstEventSent(processStartRes);

    auto processAcceptRes = bob.process(aliceUid, acceptEvent,
        genRandomData(VerificationTracker::processRandomSize(acceptEvent)), ts);
    THEN ("Bob should notify and send key") {
        REQUIRE(!displaysNothing(processAcceptRes));
        REQUIRE(sendsKey(processAcceptRes));
    }
    auto bobKeyEvent = firstEventSent(processAcceptRes);

    auto aliceProcessKeyRes = alice.process(bobUid, bobKeyEvent,
        genRandomData(VerificationTracker::processRandomSize(bobKeyEvent)), ts);
    THEN ("Alice should send key and display code") {
        REQUIRE(!displaysNothing(aliceProcessKeyRes));
        REQUIRE(sendsKey(aliceProcessKeyRes));
    }
    auto aliceKeyEvent = firstEventSent(aliceProcessKeyRes);

    auto bobProcessKeyRes = bob.process(aliceUid, aliceKeyEvent,
        genRandomData(VerificationTracker::processRandomSize(aliceKeyEvent)), ts);
    THEN ("Bob should display code first and send mac") {
        REQUIRE(displaysCode(bobProcessKeyRes.at(0)));
        REQUIRE(sendsMac(bobProcessKeyRes));
    }
    auto bobMacEvent = firstEventSent(bobProcessKeyRes);

    auto aliceProcessMacRes = alice.process(bobUid, bobMacEvent,
        genRandomData(VerificationTracker::processRandomSize(bobMacEvent)), ts);
    THEN ("Alice should send mac and show success") {
        REQUIRE(sendsMac(aliceProcessMacRes));
        REQUIRE(!displaysNothing(aliceProcessMacRes));
    }
    auto aliceMacEvent = firstEventSent(aliceProcessMacRes);

    auto bobProcessMacRes = bob.process(aliceUid, aliceMacEvent,
        genRandomData(VerificationTracker::processRandomSize(aliceMacEvent)), ts);
    THEN ("Bob should show success") {
        REQUIRE(sendsNothing(bobProcessMacRes));
        REQUIRE(!displaysNothing(bobProcessMacRes));
    }
}
