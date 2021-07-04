/*
 * Copyright (C) 2021 Tusooa Zhu <tusooa@kazv.moe>
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
#include <libkazv-config.hpp>

#include "client-model.hpp"

#include "csapi/keys.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, UploadIdentityKeysAction a);
    ClientResult updateClient(ClientModel m, GenerateAndUploadOneTimeKeysAction a);
    ClientResult processResponse(ClientModel m, UploadKeysResponse r);

    ClientModel tryDecryptEvents(ClientModel m);

    std::optional<BaseJob> clientPerform(ClientModel m, QueryKeysAction a);
    ClientResult updateClient(ClientModel m, QueryKeysAction a);
    ClientResult processResponse(ClientModel m, QueryKeysResponse r);

    ClientResult updateClient(ClientModel m, ClaimKeysAndSendSessionKeyAction a);
    ClientResult processResponse(ClientModel m, ClaimKeysResponse r);

    ClientResult updateClient(ClientModel m, EncryptMegOlmEventAction a);

    ClientResult updateClient(ClientModel m, EncryptOlmEventAction a);
}
