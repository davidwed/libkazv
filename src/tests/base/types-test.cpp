/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch.hpp>

#include <types.hpp>

using namespace Kazv;

TEST_CASE("immer::map<std::string, X> should convert to json object", "[base][types]")
{
    immer::map<std::string, int> m;
    json j = m;

    REQUIRE(j.is_object());
}

TEST_CASE("immer::map<non-std::string, X> should convert to json array", "[base][types]")
{
    immer::map<int, int> m;
    json j = m;

    REQUIRE(j.is_array());
}
