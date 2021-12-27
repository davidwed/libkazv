/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <immer/flex_vector.hpp>
#include <nlohmann/json.hpp>

#include <copy-helper.hpp>
#include <event.hpp>

#include "crypto-util.hpp"

namespace Kazv
{
    namespace VerificationTrackerActions
    {
        struct SendEvent
        {
            std::string userId;
            immer::flex_vector<std::string> deviceIds;
            nlohmann::json event;
        };

        struct DisplayCodes
        {
            std::string emojiCode;
            std::string decimalCode;
        };

        struct ShowStatus
        {
            enum Status
            {
                Cancelled,
                Verified,
                VerificationFailed,
                Requested
            };

            std::string userId;
            std::string deviceId;
            Status status;
        };
    }

    std::string idealMethod(immer::flex_vector<std::string> methods);

    using VerificationTrackerAction =
        std::variant<VerificationTrackerActions::SendEvent,
                     VerificationTrackerActions::DisplayCodes,
                     VerificationTrackerActions::ShowStatus>;

    using VerificationTrackerResult = immer::flex_vector<VerificationTrackerAction>;

    class VerificationTracker
    {
    public:
        /**
         * Construct an invalid verification tracker.
         */
        VerificationTracker();

        /**
         * Construct an verification tracker for a specific device.
         *
         * @param userId The user id for the current user.
         * @param deviceId the device id for the current device.
         */
        VerificationTracker(std::string userId, std::string deviceId);

        KAZV_DECLARE_COPYABLE(VerificationTracker);

        ~VerificationTracker();

        /**
         * @return The random size needed for process().
         */
        static std::size_t processRandomSize(const nlohmann::json &event);

        /**
         * Process the event.
         *
         * @param userId The user id of the sender of the event.
         * @param event A json of the m.key.verification.* event.
         * @param random Random data needed to process the event.
         * @param ts The current timestamp.
         */
        VerificationTrackerResult process(std::string userId, const nlohmann::json &event, RandomData random, Timestamp ts);

        /**
         * Create a new verification request.
         *
         * @param userId The user id of the user to verify.
         * @param deviceIds The device ids of the devices to verify.
         * @param ts The current timestamp.
         */
        VerificationTrackerResult requestVerification(std::string userId, immer::flex_vector<std::string> deviceIds, Timestamp ts);

    private:
        struct Private;
        std::unique_ptr<Private> m_d;
    };
}
