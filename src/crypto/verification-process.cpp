/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <lager/util.hpp>

#include <olm/sas.h>

#include "verification-process.hpp"
#include "verification-tracker.hpp"

namespace Kazv
{
    std::size_t SASVerificationProcess::constructRandomSize()
    {
        static std::size_t size = [] {
            auto sas = ByteArray(olm_sas_size(), 0);
            auto sasPointer = olm_sas(sas.data());
            return olm_create_sas_random_length(sasPointer);
        }();

        return size;
    }

    struct SASVerificationProcess::Private
    {
        Initiator initiator;
        std::string hash;
        std::string keyAgreementProtocol;
        std::string messageAuthenticationCode;
        immer::flex_vector<std::string> sas;
    };

    SASVerificationProcess::SASVerificationProcess()
        : m_d(new Private)
    {
    }

    SASVerificationProcess::SASVerificationProcess(RandomTag, OutgoingTag, RandomData random,
        immer::flex_vector<std::string> shortAuthenticationString)
        : m_d(new Private{
            Us,
            supportedHashes[0],
            supportedKeyAgreementProtocols[0],
            supportedMessageAuthenticationCodes[0],
            shortAuthenticationString
        })
    {
    }

    KAZV_DEFINE_COPYABLE_UNIQUE_PTR(SASVerificationProcess, m_d)

    SASVerificationProcess::~SASVerificationProcess() = default;

    nlohmann::json SASVerificationProcess::startEventContent() const
    {
        return {
            {"hashes", supportedHashes},
            {"key_agreement_protocols", supportedKeyAgreementProtocols},
            {"message_authentication_codes", supportedMessageAuthenticationCodes},
            {"method", name()},
            {"short_authentication_string", m_d->sas}
        };
    }

    using VerificationMethodProcess = std::variant<SASVerificationProcess>;

    struct VerificationProcess::Private
    {
        Timestamp startingTs;
        std::string txnId;
        immer::flex_vector<std::string> availableMethods;
        std::string chosenMethod;
        VerificationMethodProcess methodProcess;

        VerificationMethodProcess createMethodProcess(RandomData random) const;
    };

    VerificationMethodProcess VerificationProcess::Private::createMethodProcess(RandomData random) const
    {
        if (chosenMethod == SASVerificationProcess::name()) {
            // We are to send start event, so we are outgoing
            return SASVerificationProcess(
                RandomTag{},
                SASVerificationProcess::OutgoingTag{},
                std::move(random)
            );
        }

        return {};
    }

    VerificationProcess::VerificationProcess()
        : m_d(new Private)
    {}

    VerificationProcess::VerificationProcess(ToDeviceTag, Timestamp ts, std::string txnId, immer::flex_vector<std::string> methods)
        : m_d(new Private{ts, txnId, methods, {}, {}})
    {
    }

    KAZV_DEFINE_COPYABLE_UNIQUE_PTR(VerificationProcess, m_d)

    VerificationProcess::~VerificationProcess() = default;

    immer::flex_vector<std::string> VerificationProcess::methods() const
    {
        return m_d->availableMethods;
    }

    void VerificationProcess::restrictMethods(immer::flex_vector<std::string> newMethods)
    {
        m_d->availableMethods = newMethods;
    }

    nlohmann::json VerificationProcess::obtainStartEventContent(RandomData random)
    {
        m_d->chosenMethod = idealMethod(m_d->availableMethods);

        m_d->methodProcess = m_d->createMethodProcess(std::move(random));

        return lager::match(m_d->methodProcess)(
            [](auto &&proc) {
                return std::forward<decltype(proc)>(proc).startEventContent();
            }
        );
    }
}
