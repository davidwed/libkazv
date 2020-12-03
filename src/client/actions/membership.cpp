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

#include <csapi/create_room.hpp>
#include <csapi/inviting.hpp>
#include <csapi/joining.hpp>
#include <debug.hpp>

#include "client-model.hpp"
#include "clientutil.hpp"
#include "cursorutil.hpp"

#include "membership.hpp"

namespace Kazv
{
    static std::string visibilityToStr(CreateRoomAction::Visibility v)
    {
        using V = CreateRoomAction::Visibility;
        switch (v) {
        case V::Private:
            return "private";
        case V::Public:
            return "public";
        default:
            // should not happen
            return "";
        }
    }

    static std::string presetToStr(CreateRoomAction::Preset p)
    {
        using P = CreateRoomAction::Preset;
        switch (p) {
        case P::PrivateChat:
            return "private_chat";
        case P::PublicChat:
            return "public_chat";
        case P::TrustedPrivateChat:
            return "trusted_private_chat";
        default:
            // should not happen
            return "";
        }
    }

    ClientResult updateClient(ClientModel m, CreateRoomAction a)
    {
        auto visibility = visibilityToStr(a.visibility);
        auto preset = a.preset
            ? presetToStr(a.preset.value())
            : ""s;

        using StateEvT = Kazv::CreateRoomJob::StateEvent;
        auto initialState = intoImmer(
            immer::array<StateEvT>{},
            zug::map(
                [](Event e) {
                    return StateEvT{e.type(), e.stateKey(), e.content()};
                }),
            a.initialState);

        auto job = m.job<CreateRoomJob>().make(
            visibility,
            a.roomAliasName,
            a.name,
            a.topic,
            a.invite,
            DEFVAL, // invite3pid, not supported yet
            a.roomVersion,
            a.creationContent,
            initialState,
            preset,
            a.isDirect,
            a.powerLevelContentOverride);

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, CreateRoomResponse r)
    {
        if (! r.success()) {
            dbgClient << "Create room failed" << std::endl;
            m.addTrigger(CreateRoomFailed{r.errorCode(), r.errorMessage()});
            return { std::move(m), lager::noop };
        }

        m.addTrigger(CreateRoomSuccessful{r.roomId()});
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, InviteToRoomAction a)
    {
        auto job = m.job<InviteUserJob>()
            .make(a.roomId, a.userId)
            .withData(json{
                    {"roomId", a.roomId},
                    {"userId", a.userId},
                });
        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, InviteUserResponse r)
    {
        auto roomId = r.dataStr("roomId");
        auto userId = r.dataStr("userId");

        if (! r.success()) {
            // Error
            dbgClient << "Error inviting user" << std::endl;

            m.addTrigger(InviteUserFailed{roomId, userId, r.errorCode(), r.errorMessage()});
            return { std::move(m), lager::noop };
        }

        dbgClient << "Inviting user successful" << std::endl;
        m.addTrigger(InviteUserSuccessful{roomId, userId});
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, JoinRoomAction a)
    {
        auto job = m.job<JoinRoomJob>()
            .make(a.roomIdOrAlias, a.serverName)
            .withData(json{{"roomIdOrAlias", a.roomIdOrAlias}});

        m.addJob(std::move(job));
        return { m, lager::noop };
    }

    ClientResult processResponse(ClientModel m, JoinRoomResponse r)
    {
        auto roomIdOrAlias = r.dataStr("roomIdOrAlias");
        if (! r.success()) {
            m.addTrigger(JoinRoomFailed{
                    roomIdOrAlias,
                    r.errorCode(),
                    r.errorMessage()
                });
            dbgClient << "Error joining room" << std::endl;
            return { std::move(m), lager::noop};
        }

        dbgClient << "Successfully joined room" << std::endl;
        m.addTrigger(JoinRoomSuccessful{roomIdOrAlias});
        return { std::move(m), lager::noop};
    }

    ClientResult updateClient(ClientModel m, JoinRoomByIdAction a)
    {
        auto job = m.job<JoinRoomByIdJob>()
            .make(a.roomId)
            .withData(json{{"roomIdOrAlias", a.roomId}});

        m.addJob(std::move(job));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, JoinRoomByIdResponse r)
    {
        auto roomIdOrAlias = r.dataStr("roomIdOrAlias");
        if (! r.success()) {
            m.addTrigger(JoinRoomFailed{
                    roomIdOrAlias,
                    r.errorCode(),
                    r.errorMessage()
                });
            dbgClient << "Error joining room" << std::endl;
            return { std::move(m), lager::noop};
        }

        dbgClient << "Successfully joined room" << std::endl;
        m.addTrigger(JoinRoomSuccessful{roomIdOrAlias});
        return { std::move(m), lager::noop};
    }

};