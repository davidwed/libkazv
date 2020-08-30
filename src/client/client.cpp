
#include <lager/util.hpp>
#include <lager/context.hpp>
#include <functional>

#include "client.hpp"
#include "csapi/login.hpp"
#include "types.hpp"
#include "debug.hpp"
#include "job/jobinterface.hpp"
#include "client/util.hpp"

namespace Kazv
{
    Client::Effect loginEffect(Client::LoginAction a)
    {
        return
            [=](auto &&ctx) {
                LoginJob job(a.serverUrl,
                             "m.login.password"s, // type
                             UserIdentifier{ "m.id.user"s, json{{"user", a.username}} }, // identifier
                             a.password,
                             {}, // token, not used
                             {}, // device id, not used
                             a.deviceName.value_or("libkazv"));
                auto &jobHandler = lager::get<JobInterface &>(ctx);
                jobHandler.fetch(
                    job,
                    [=](std::shared_future<BaseJob::Response> res) {
                        auto r = res.get();
                        if (LoginJob::success(r)) {
                            dbgClient << "Job success" << std::endl;
                            const json &j = jsonBody(r).get();
                            std::string serverUrl = j.contains("well_known")
                                ? j.at("well_known").at("m.homeserver").at("base_url").get<std::string>()
                                : a.serverUrl;
                            ctx.dispatch(Client::LoadUserInfoAction{
                                    serverUrl,
                                    j.at("user_id"),
                                    j.at("access_token"),
                                    j.at("device_id"),
                                    /* loggedIn = */ true
                                });
                            // after user info is loaded, do first sync
                            ctx.dispatch(Client::SyncAction{});
                        }
                    });
            };
    }

    lager::effect<Client::Action> logoutEffect(Client::LogoutAction)
    {
        return
            [=](auto &&ctx) {
                ctx.dispatch(Client::LoadUserInfoAction{
                        ""s,
                        ""s,
                        ""s,
                        ""s,
                        /* loggedIn = */ true
                    });
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

    auto Client::update(Client m, Action a) -> Result
    {
        return lager::match(std::move(a))(
            [=](Error::Action a) mutable -> Result {
                m.error = Error::update(m.error, a);
                return {std::move(m), lager::noop};
            },

            [=](RoomList::Action a) mutable -> Result {
                m.roomList = RoomList::update(std::move(m.roomList), a);
                return {std::move(m), lager::noop};
            },

            [=](LoginAction a) mutable -> Result {
                return {std::move(m), loginEffect(std::move(a))};
            },

            [=](LogoutAction a) mutable -> Result {
                return {std::move(m), logoutEffect(std::move(a))};
            },

            [=](SyncAction a) -> Result {
                return {m, syncEffect(m, a)};
            },

            [=](LoadUserInfoAction a) mutable -> Result {
                dbgClient << "LoadUserInfoAction: " << a.userId << std::endl;

                m.serverUrl = a.serverUrl;
                m.userId = a.userId;
                m.token = a.token;
                m.deviceId = a.deviceId;
                m.loggedIn = a.loggedIn;

                return { std::move(m),
                         [](auto &&ctx) {
                             ctx.dispatch(Error::SetErrorAction{Error::NoError{}});
                         }
                };
            },

            [=](LoadSyncResultAction a) mutable -> Result {
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
            );

    }
}
