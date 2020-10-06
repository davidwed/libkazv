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


#include <lager/util.hpp>
#include <zug/transducer/map.hpp>

#include "csapi/sync.hpp"
#include "job/jobinterface.hpp"
#include "debug.hpp"

#include "client/cursorutil.hpp"

#include "sync.hpp"

static const int syncInterval = 2000; // ms

namespace Kazv
{
    // Atomicity guaranteed: if the sync action is created
    // before an action that reasonably changes Client
    // (e.g. roll back to an earlier state, obtain other
    // events), but executed
    // after that action, the sync will still give continuous
    // data about the events. (Sync will not "skip" events)
    // This is because this function takes the sync token
    // from the Client model it is passed.
    ClientResult updateClient(Client m, SyncAction)
    {
        return {
            m,
            [=](auto &&ctx) {
                dbgClient << "Start syncing with token " << m.syncToken << std::endl;
                SyncJob job(m.serverUrl,
                            m.token,
                            {}, // filter
                            m.syncToken);
                auto &jobHandler = lager::get<JobInterface &>(ctx);
                jobHandler.fetch(
                    job,
                    [=](BaseJob::Response r) {
                        if (!SyncJob::success(r)) {
                            dbgClient << "Sync failed" << std::endl;
                            dbgClient << r.statusCode << std::endl;
                            if (BaseJob::isBodyJson(r.body)) {
                                auto j = jsonBody(r);
                                dbgClient << "Json says: " << j.get().dump() << std::endl;
                            } else {
                                dbgClient << "Response body: "
                                          << std::get<BaseJob::BytesBody>(r.body) << std::endl;
                            }
                            return;
                        }
                        dbgClient << "Sync successful" << std::endl;

                        auto rooms = SyncJob::rooms(r);
                        auto accountData = SyncJob::accountData(r);
                        auto presence = SyncJob::presence(r);
                        // load the info that has been sync'd

                        ctx.dispatch(
                            LoadSyncResultAction{
                                SyncJob::nextBatch(r),
                                rooms,
                                presence,
                                accountData,
                                SyncJob::toDevice(r),
                                SyncJob::deviceLists(r),
                                SyncJob::deviceOneTimeKeysCount(r),
                            });

                        // emit events
                        auto &eventEmitter = lager::get<EventInterface &>(ctx);

                        if (accountData) {
                            auto events = accountData.value().events;
                            for (auto e : events) {
                                eventEmitter.emit(ReceivingAccountDataEvent{e});
                            }
                        }

                        if (presence) {
                            for (auto e : presence.value().events) {
                                eventEmitter.emit(ReceivingPresenceEvent{e});
                            }
                        }

                        if (rooms) {
                            for (auto [id, room] : rooms.value().join) {
                                for (auto e : room.timeline.events) {
                                    eventEmitter.emit(ReceivingRoomTimelineEvent{e, id});
                                }
                            }
                        }

                        // kick off next sync
                        auto &jobHandler = lager::get<JobInterface &>(ctx);
                        jobHandler.setTimeout(
                            [=]() {
                                ctx.dispatch(SyncAction{});
                            }, syncInterval);
                    });
            }
        };
    }


    static void loadRoomsFromSyncInPlace(Client &m, SyncJob::Rooms rooms)
    {
        auto l = m.roomList;

        auto updateRoomImpl =
            [&l](auto id, auto a) {
                l = RoomList::update(
                    std::move(l),
                    RoomList::UpdateRoomAction{id, a});
            };
        auto updateSingleRoom =
            [updateRoomImpl](auto id, auto room, auto membership) {
                updateRoomImpl(id, Room::ChangeMembershipAction{membership});
                updateRoomImpl(id, Room::AppendTimelineAction{room.timeline.events});
                if (room.state) {
                    updateRoomImpl(id, Room::AddStateEventsAction{room.state.value().events});
                }
                if (room.accountData) {
                    updateRoomImpl(id, Room::AddAccountDataAction{room.accountData.value().events});
                }
            };

        auto updateJoinedRoom =
            [=](auto id, auto room) {
                updateSingleRoom(id, room, Room::Membership::Join);
            };

        auto updateInvitedRoom =
            [=](auto id, auto room) {
                updateRoomImpl(id, Room::ChangeMembershipAction{Room::Membership::Invite});
                if (room.inviteState) {
                    auto events = intoImmer(EventList{},
                                            zug::map([](StrippedState s) {
                                                json j(s);
                                                return Event(j);
                                            }),
                                            room.inviteState.value().events);
                    updateRoomImpl(id, Room::ChangeInviteStateAction{events});
                }
            };

        auto updateLeftRoom =
            [=](auto id, auto room) {
                updateSingleRoom(id, room, Room::Membership::Leave);
            };

        for (auto &&[id, room]: rooms.join) {
            updateJoinedRoom(id, room);
            // TODO update other info such as
            // ephemeral, notification and summary
        }

        // TODO update info for invited rooms
        for (auto &&[id, room]: rooms.invite) {
            updateInvitedRoom(id, room);
        }

        for (auto &&[id, room]: rooms.leave) {
            updateLeftRoom(id, room);
        }

        m.roomList = l;
    }

    static void loadPresenceFromSyncInPlace(Client &m, EventList presence)
    {
        m.presence = merge(std::move(m.presence), presence, keyOfPresence);
    }

    static void loadAccountDataFromSyncInPlace(Client &m, EventList accountData)
    {
        m.accountData = merge(std::move(m.accountData), accountData, keyOfAccountData);
    }

    ClientResult updateClient(Client m, LoadSyncResultAction a)
    {
        m.syncToken = a.syncToken;
        if (a.rooms) {
            loadRoomsFromSyncInPlace(m, a.rooms.value());
        }

        if (a.presence) {
            loadPresenceFromSyncInPlace(m, a.presence.value().events);
        }

        if (a.accountData) {
            loadAccountDataFromSyncInPlace(m, a.accountData.value().events);
        }

        return { std::move(m), lager::noop };
    }
}
