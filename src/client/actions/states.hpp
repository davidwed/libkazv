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
#include <libkazv-config.hpp>

#include <csapi/rooms.hpp>
#include <csapi/room_state.hpp>

#include "client-model.hpp"

namespace Kazv
{
    BaseJob clientPerform(ClientModel m, GetRoomStatesAction a);
    ClientResult updateClient(ClientModel m, GetRoomStatesAction a);
    ClientResult processResponse(ClientModel m, GetRoomStateResponse r);
    ClientResult updateClient(ClientModel m, GetStateEventAction a);
    ClientResult processResponse(ClientModel m, GetRoomStateWithKeyResponse r);
    ClientResult updateClient(ClientModel m, SendStateEventAction a);
    ClientResult processResponse(ClientModel m, SetRoomStateWithKeyResponse r);
}
