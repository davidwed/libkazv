/*
 * Copyright (C) 2020 Tusooa Zhu <tusooa@vista.aero>
 *
 * This file is part of libkazv.
 *
 * libkazv is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * libkazv is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with libkazv.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <string>
#include <random>
#include <algorithm>
#include <vector>

namespace Kazv
{
    using ByteArray = std::vector<char>;

    [[nodiscard]] inline ByteArray genRandom(int len)
    {
        auto rd = std::random_device{};
        auto ret = ByteArray(len, '\0');
        std::generate(ret.begin(), ret.end(), [&] { return rd(); });
        return ret;
    }

    namespace CryptoConstants
    {
        inline const std::string ed25519{"ed25519"};
        inline const std::string curve25519{"curve25519"};
        inline const std::string signedCurve25519{"signed_curve25519"};

        inline const std::string olmAlgo{"m.olm.v1.curve25519-aes-sha2"};
        inline const std::string megOlmAlgo{"m.megolm.v1.aes-sha2"};
    }
}
