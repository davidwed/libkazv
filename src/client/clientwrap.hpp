/*
 * Copyright (C) 2020 Tusooa Zhu
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

#include <lager/reader.hpp>
#include <immer/box.hpp>
#include <immer/map.hpp>
#include <immer/flex_vector.hpp>
#include <immer/flex_vector_transient.hpp>

#include "client/client.hpp"
#include "room/roomwrap.hpp"

namespace Kazv
{
    class ClientWrap
    {
    public:
        inline ClientWrap(lager::reader<Client> client,
                          lager::context<Client::Action> ctx)
            : m_client(std::move(client))
            , m_ctx(std::move(ctx)) {}

        /* lager::reader<immer::map<std::string, Room>> */
        inline auto rooms() const {
            return m_client
                [&Client::roomList]
                [&RoomList::rooms];
        }

        /* lager::reader<RangeT<std::string>> */
        inline auto roomIds() const {
            return rooms().xform(
                zug::map([](auto m) {
                             return intoImmer(
                                 immer::flex_vector<std::string>{},
                                 zug::map([](auto val) { return val.first; }),
                                 m);
                         }));
        }

        KAZV_WRAP_ATTR(Client, m_client, serverUrl)
        KAZV_WRAP_ATTR(Client, m_client, loggedIn)
        KAZV_WRAP_ATTR(Client, m_client, userId)
        KAZV_WRAP_ATTR(Client, m_client, token)
        KAZV_WRAP_ATTR(Client, m_client, deviceId)

        /* RoomWrap */
        inline auto room(std::string id) const {
            return RoomWrap(rooms()[std::move(id)]
                            [lager::lenses::or_default].make(),
                            m_ctx);
        }

        inline void passwordLogin(std::string homeserver, std::string username,
                                  std::string password, std::string deviceName) const {
            m_ctx.dispatch(LoginAction{
                    homeserver, username, password, deviceName});
        }

        inline void tokenLogin(std::string homeserver, std::string username,
                               std::string token, std::string deviceId) const {
            m_ctx.dispatch(LoadUserInfoAction{
                    homeserver, username, token, deviceId, /* loggedIn = */ true});
        }

        inline void createRoom(RoomVisibility v,
                               std::string name,
                               std::string alias = {},
                               immer::array<std::string> invite = {},
                               std::optional<bool> isDirect = {},
                               bool allowFederate = true,
                               std::string topic = {}) const {
            CreateRoomAction a;
            a.visibility = v;
            a.name = name;
            a.roomAliasName = alias;
            a.invite = invite;
            a.isDirect = isDirect;
            a.topic = topic;
            // Synapse won't buy it if we do not provide
            // a creationContent object.
            a.creationContent = json{
                {"m.federate", allowFederate}
            };
            m_ctx.dispatch(std::move(a));
        }

    private:
        lager::reader<Client> m_client;
        lager::context<Client::Action> m_ctx;
    };

}
