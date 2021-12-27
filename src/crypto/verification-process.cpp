/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <olm/sas.h>

#include "verification-process.hpp"

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
    };


    SASVerificationProcess::~SASVerificationProcess() = default;

    struct VerificationProcess::Private
    {
    };

    VerificationProcess::VerificationProcess()
        : m_d(new Private)
    {}

    VerificationProcess::VerificationProcess(ToDeviceTag, Timestamp ts, std::string txnId, immer::flex_vector<std::string> methods)
        : m_d(new Private)
    {
    }

    KAZV_DEFINE_COPYABLE_UNIQUE_PTR(VerificationProcess, m_d)

    VerificationProcess::~VerificationProcess() = default;
}
