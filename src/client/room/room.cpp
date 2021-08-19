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

#include <libkazv-config.hpp>

#include <immer/algorithm.hpp>
#include <debug.hpp>

#include "room.hpp"

namespace Kazv
{
    Room::Room(lager::reader<SdkModel> sdk,
               lager::reader<std::string> roomId,
               Context<ClientAction> ctx,
               DepsT deps)
        : m_sdk(sdk)
        , m_roomId(roomId)
        , m_ctx(ctx)
        , m_deps(deps)
    {
    }

    Room::Room(lager::reader<SdkModel> sdk,
               lager::reader<std::string> roomId,
               Context<ClientAction> ctx)
        : m_sdk(sdk)
        , m_roomId(roomId)
        , m_ctx(ctx)
        , m_deps(std::nullopt)
    {
    }

    Room::Room(InEventLoopTag, std::string roomId, ContextT ctx, DepsT deps)
        : m_sdk(std::nullopt)
        , m_roomId(roomId)
        , m_ctx(ctx)
        , m_deps(deps)
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
        , KAZV_ON_EVENT_LOOP_VAR(true)
#endif
    {
    }

    Room Room::toEventLoop() const
    {
        assert(m_deps.has_value());
        return Room(InEventLoopTag{}, currentRoomId(), m_ctx, m_deps.value());
    }

    const lager::reader<SdkModel> &Room::sdkCursor() const
    {
        if (m_sdk.has_value()) { return m_sdk.value(); }

        assert(m_deps.has_value());

        return *lager::get<SdkModelCursorKey>(m_deps.value());
    }

    lager::reader<RoomModel> Room::roomCursor() const
    {
        return lager::match(m_roomId)(
            [&](const lager::reader<std::string> &roomId) -> lager::reader<RoomModel> {
                return lager::with(sdkCursor().map(&SdkModel::c)[&ClientModel::roomList], roomId)
                    .map([](auto rooms, auto id) {
                             return rooms[id];
                         }).make();
            },
            [&](const std::string &roomId) -> lager::reader<RoomModel> {
                return sdkCursor().map(&SdkModel::c)[&ClientModel::roomList].map([roomId](auto rooms) { return rooms[roomId]; }).make();
            });
    }

    std::string Room::currentRoomId() const
    {
        return lager::match(m_roomId)(
            [&](const lager::reader<std::string> &roomId) {
                return roomId.get();
            },
            [&](const std::string &roomId) {
                return roomId;
            });
    }

    auto Room::setLocalDraft(std::string localDraft) const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(UpdateRoomAction{+roomId(), SetLocalDraftAction{localDraft}});
    }

    auto Room::sendMessage(Event msg) const
        -> PromiseT
    {
        using namespace CursorOp;
        auto hasCrypto = ~sdkCursor().map([](const auto &sdk) -> bool {
                                        return sdk.c().crypto.has_value();
                                    });
        auto roomEncrypted = ~roomCursor()[&RoomModel::encrypted];
        auto noFullMembers = ~roomCursor()[&RoomModel::membersFullyLoaded]
            .map([](auto b) { return !b; });

        auto rid = +roomId();

        // Don't use m_ctx directly in the callbacks
        // as `this` may have been destroyed when
        // the callbacks are called.
        auto ctx = m_ctx;

        auto promise = ctx.createResolvedPromise(true);

        // If we do not need encryption just send it as-is
        if (! +allCursors(hasCrypto, roomEncrypted)) {
            return promise
                .then([ctx, rid, msg](auto succ) {
                          if (! succ) {
                              return ctx.createResolvedPromise(false);
                          }
                          return ctx.dispatch(SendMessageAction{rid, msg});
                      });
        }

        if (! m_deps) {
            return ctx.createResolvedPromise({false, json{{"error", "missing-deps"}}});
        }

        auto deps = m_deps.value();

        // If the room member list is not complete, load it fully first.
        if (+allCursors(hasCrypto, roomEncrypted, noFullMembers)) {
            kzo.client.dbg() << "The members of " << rid
                             << " are not fully loaded." << std::endl;

            promise = promise
                .then([ctx, rid](auto) {
                          return ctx.dispatch(GetRoomStatesAction{rid});
                      })
                .then([ctx, rid](auto succ) {
                          if (! succ) {
                              kzo.client.warn() << "Loading members of " << rid
                                                << " failed." << std::endl;
                              return ctx.createResolvedPromise(false);
                          } else {
                              // XXX remove the hard-coded initialSync parameter
                              return ctx.dispatch(QueryKeysAction{true})
                                  .then([](auto succ) {
                                            if (! succ) {
                                                kzo.client.warn() << "Query keys failed" << std::endl;
                                            }
                                            return succ;
                                        });
                          }
                      });
        }

        return promise
            // Encrypt the event and see whether the session was rotated.
            .then([ctx, rid, msg, deps](auto &&status) {
                      if (! status) { return ctx.createResolvedPromise(status); }

                      kzo.client.dbg() << "encrypting megolm" << std::endl;

                      auto &rg = lager::get<RandomInterface &>(deps);

                      return ctx.dispatch(EncryptMegOlmEventAction{
                              rid,
                              msg,
                              currentTimeMs(),
                              rg.generateRange<RandomData>(EncryptMegOlmEventAction::maxRandomSize())
                          });
                  })
            // If the session was rotated, send the corresponding session key to other devices
            .then([ctx, rid, r=toEventLoop(), deps](auto status) {
                      if (! status) { return ctx.createResolvedPromise(status); }

                      auto encryptedEvent = status.dataJson("encrypted");
                      auto content = encryptedEvent.at("content");

                      auto ret = ctx.createResolvedPromise({});
                      if (status.data().get().contains("key")) {
                          kzo.client.dbg() << "megolm session rotated, sending session key" << std::endl;

                          auto key = status.dataStr("key");
                          ret = ret
                              .then([rid, r, key, ctx, deps, sessionId=content.at("session_id")](auto &&) {
                                        auto members = (+r.roomCursor()).joinedMemberIds();
                                        auto client = (+r.sdkCursor()).c();
                                        using DeviceMapT = immer::map<std::string, immer::flex_vector<std::string>>;

                                        auto devicesToSend = accumulate(
                                            members, DeviceMapT{}, [client](auto map, auto uid) {
                                                                       return std::move(map)
                                                                           .set(uid, client.devicesToSendKeys(uid));
                                                                   });
                                        auto &rg = lager::get<RandomInterface &>(deps);

                                        return ctx.dispatch(ClaimKeysAction{
                                                rid, sessionId, key, devicesToSend,
                                                rg.generateRange<RandomData>(ClaimKeysAction::randomSize(devicesToSend))
                                            })
                                            .then([ctx, deps, devicesToSend](auto status) {
                                                      if (! status) { return ctx.createResolvedPromise({}); }

                                                      kzo.client.dbg() << "olm-encrypting key event" << std::endl;

                                                      auto keyEv = status.dataJson("keyEvent");
                                                      auto &rg = lager::get<RandomInterface &>(deps);

                                                      return ctx.dispatch(EncryptOlmEventAction{
                                                              devicesToSend, keyEv,
                                                              rg.generateRange<RandomData>(EncryptOlmEventAction::randomSize(devicesToSend))
                                                          });
                                                  })
                                            .then([ctx, devicesToSend](auto status) {
                                                      if (! status) { return ctx.createResolvedPromise({}); }

                                                      kzo.client.dbg() << "sending key event as to-device message" << std::endl;

                                                      auto event = Event(status.dataJson("encrypted"));
                                                      return ctx.dispatch(SendToDeviceMessageAction{event, devicesToSend});
                                                  });
                                    });
                      }
                      return ret
                          .then([ctx, prevStatus=status](auto status) {
                                    if (! status) { return status; }
                                    return prevStatus;
                                });
                  })
            // Send the just encrypted event
            .then([ctx, rid](auto status) {
                      if (! status) { return ctx.createResolvedPromise(status); }

                      kzo.client.dbg() << "sending encrypted message" << std::endl;

                      auto ev = Event(status.dataJson("encrypted"));

                      return ctx.dispatch(SendMessageAction{rid, ev});
                  });
    }

    auto Room::sendTextMessage(std::string text) const
        -> PromiseT
    {
        json j{
            {"type", "m.room.message"},
            {"content", {
                    {"msgtype", "m.text"},
                    {"body", text}
                }
            }
        };
        Event e{j};
        return sendMessage(e);
    }

    auto Room::refreshRoomState() const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(GetRoomStatesAction{+roomId()});
    }

    auto Room::getStateEvent(std::string type, std::string stateKey) const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(GetStateEventAction{+roomId(), type, stateKey});
    }

    auto Room::sendStateEvent(Event state) const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(SendStateEventAction{+roomId(), state});
    }

    auto Room::setName(std::string name) const
        -> PromiseT
    {
        json j{
            {"type", "m.room.name"},
            {"content", {
                    {"name", name}
                }
            }
        };
        Event e{j};
        return sendStateEvent(e);
    }

    auto Room::setTopic(std::string topic) const
        -> PromiseT
    {
        json j{
            {"type", "m.room.topic"},
            {"content", {
                    {"topic", topic}
                }
            }
        };
        Event e{j};
        return sendStateEvent(e);
    }

    auto Room::invite(std::string userId) const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(InviteToRoomAction{+roomId(), userId});
    }

    auto Room::setTyping(bool typing, std::optional<int> timeoutMs) const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(SetTypingAction{+roomId(), typing, timeoutMs});
    }

    auto Room::leave() const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(LeaveRoomAction{+roomId()});
    }

    auto Room::forget() const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(ForgetRoomAction{+roomId()});
    }

    auto Room::setPinnedEvents(immer::flex_vector<std::string> eventIds) const
        -> PromiseT
    {
        json j{
            {"type", "m.room.pinned_events"},
            {"content", {
                    {"pinned", eventIds}
                }
            }
        };
        Event e{j};
        return sendStateEvent(e);
    }

    auto Room::timelineGaps() const
        -> lager::reader<immer::map<std::string /* eventId */,
                                    std::string /* prevBatch */>>
    {
        return roomCursor()[&RoomModel::timelineGaps];
    }

    auto Room::paginateBackFromEvent(std::string eventId) const
        -> PromiseT
    {
        using namespace CursorOp;
        return m_ctx.dispatch(PaginateTimelineAction{
                +roomId(), eventId, std::nullopt});
    }

    lager::reader<bool> Room::hasUnknownDevices() const
    {
        return this->unknownDevices()
            .map(&UserIdToDeviceIdMap::empty)
            .map([](auto x) { return !x; });
    }

    lager::reader<UserIdToDeviceIdMap> Room::unknownDevices() const
    {
        auto client = sdkCursor().map(&SdkModel::c).make();
        return lager::with(client, members())
            .map([](const auto &client, const auto &userIds) {
                return intoImmer(UserIdToDeviceIdMap{},
                    zug::map([&](const auto &userId) {
                        return std::make_pair(userId, client.unknownDevices(userId));
                    })
                    | zug::filter([&](const auto &pair) {
                        return !pair.second.empty();
                    }),
                    userIds);
            });
    }
}
