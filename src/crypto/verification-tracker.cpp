/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <algorithm>

#include <immer/set.hpp>

#include <types.hpp>
#include <debug.hpp>

#include "verification-tracker.hpp"

#include "verification-process.hpp"

namespace Kazv
{
    static const auto supportedVerificationMethods =
        immer::set<std::string>{}.insert("m.sas.v1");

    static bool methodSupported(immer::flex_vector<std::string> methods)
    {
        return std::any_of(methods.begin(), methods.end(),
            [](auto method) { return supportedVerificationMethods.count(method); });
    }

    static std::string idealMethod(immer::flex_vector<std::string> /* methods */)
    {
        return "m.sas.v1";
    }

    static std::size_t processRequestRandomSize(std::string method)
    {
        if (method == "m.sas.v1") {
            return SASVerificationProcess::constructRandomSize();
        }

        return 0;
    }

    static std::size_t processStartRandomSize(std::string method)
    {
        if (method == "m.sas.v1") {
            return SASVerificationProcess::constructRandomSize();
        }

        return 0;
    }

    static bool isEventWellFormed(const nlohmann::json &event)
    {
        return event.is_object()
            && event.contains("content")
            && event["content"].is_object()
            && event.contains("type")
            && event["type"].is_string()
            && (event["content"].contains("transaction_id")
                && event["content"]["transaction_id"].is_string());
    }

    std::size_t VerificationTracker::processRandomSize(const nlohmann::json &event)
    {
        if (!isEventWellFormed(event)) {
            return 0;
        }

        kzo.crypto.dbg() << "event: " << event.dump() << std::endl;

        if (event["type"].template get<std::string>() == "m.key.verification.request") {
            if (!(event["content"].contains("methods") && event["content"]["methods"].is_array())) {
                kzo.crypto.dbg() << "methods not an array" << std::endl;
                return 0;
            }

            auto methods = event["content"]["methods"]
                .template get<immer::flex_vector<std::string>>();
            if (methodSupported(methods)) {
                kzo.crypto.dbg() << "methods supported" << std::endl;
                return processRequestRandomSize(idealMethod(methods));
            }
            kzo.crypto.dbg() << "methods not supported" << std::endl;
            return 0;
        }

        if (event["type"].template get<std::string>() == "m.key.verification.start") {
            if (!(event["content"].contains("method") && event["content"]["method"].is_string())) {
                return 0;
            }

            auto method = event["content"]["method"]
                .template get<std::string>();
            if (methodSupported({ method })) {
                return processStartRandomSize(method);
            }
            return 0;
        }

        return 0;
    }
}
