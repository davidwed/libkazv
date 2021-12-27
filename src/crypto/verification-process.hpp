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
    class SASVerificationProcess
    {
    public:
        /**
         * The initiator of the process.
         *
         * The one who sends the m.key.verification.start event is considered the initiator.
         *
         * The other party than the initiator will send a commitment hash.
         */
        enum Initiator
        {
            Us,
            Them
        };

        /**
         * Indicate to create an incoming process.
         *
         * A process is incoming iff. the initiator is us.
         */
        struct IncomingTag {};

        /**
         * Indicate to create an outgoing process.
         *
         * A process in outgoing iff. the initiator is them.
         */
        struct OutgoingTag {};

        inline static immer::flex_vector<std::string> defaultShortAuthenticationString = {"emoji", "decimal"};

        /**
         * The random size needed to construct an instance.
         */
        static std::size_t constructRandomSize();

        /**
         * Construct an empty SASVerificationProcess.
         */
        SASVerificationProcess();

        /**
         * Construct an incoming SASVerificationProcess using provided random data to
         * generate an ephemeral key pair.
         *
         * @param random The random data to generate the key pair.
         * @param event The `m.key.verification.start` event json we received from the other party.
         * @param shortAuthenticationString The type of short authentication strings this client can accept.
         * Default to both emoji and decimal.
         */
        SASVerificationProcess(RandomTag, IncomingTag, RandomData random,
            const nlohmann::json &event,
            immer::flex_vector<std::string> shortAuthenticationString = defaultShortAuthenticationString);

        /**
         * Construct an outgoing SASVerificationProcess using provided random data to
         * generate an ephemeral key pair.
         *
         * @param random The random data to generate the key pair.
         * @param shortAuthenticationString The type of short authentication strings this client can accept.
         * Default to both emoji and decimal.
         */
        SASVerificationProcess(RandomTag, OutgoingTag, RandomData random,
            immer::flex_vector<std::string> shortAuthenticationString = defaultShortAuthenticationString);

        KAZV_DECLARE_COPYABLE(SASVerificationProcess)

        ~SASVerificationProcess();

        /**
         * Check whether this is valid.
         *
         * One constructed from the defualt constructor is invalid.
         * One copy- or move-constructed from an invalid object is invalid.
         * All other `SASVerificationProcess`es are valid.
         *
         * @return Whether this is valid.
         */
        bool valid() const;

        // immer::flex_vector<std::string> hashes() const;

        // std::string selectedHash() const;

        // immer::flex_vector<std::string> keyAgreementProtocols() const;

        // std::string selectedKeyAgreementProtocols() const;

        // immer::flex_vector<std::string> shortAuthenticationString() const;

        // std::string ourKey() const;

        // std::string theirKey() const;

        Initiator initiator() const;

        // std::string ourCommitment() const;

        // std::string theirCommitment() const;

        std::string setTheirCommitment();

        /**
         * Get the json of the m.verification.start event to send.
         * Only available if this is outgoing.
         *
         * @return The json of the m.verification.start event to send.
         */
        nlohmann::json startEvent() const;

    private:
        struct Private;
        std::unique_ptr<Private> m_d;
    };

    class VerificationProcess
    {
    public:
        struct ToDeviceTag {};

        struct ToRoomTag {};

        VerificationProcess();

        /**
         * Construct a VerificationProcess that is to send via a to-device message.
         */
        VerificationProcess(ToDeviceTag, Timestamp ts, std::string txnId, immer::flex_vector<std::string> methods);

        KAZV_DECLARE_COPYABLE(VerificationProcess)

        ~VerificationProcess();

        /**
         * The methods this process supports.
         */
        immer::flex_vector<std::string> methods() const;

    private:
        struct Private;
        std::unique_ptr<Private> m_d;
    };
}
