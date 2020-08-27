
#pragma once

#include <tuple>
#include <variant>
#include <string>
#include <optional>

#include <lager/context.hpp>

#include "job/jobinterface.hpp"
#include "eventemitter/eventinterface.hpp"
#include "error.hpp"

namespace Kazv
{
    struct Client
    {
        std::string serverUrl;
        std::string userId;
        std::string token;
        std::string deviceId;
        bool loggedIn;
        Error error;

        std::string syncToken;

        struct LoginAction {
            std::string serverUrl;
            std::string username;
            std::string password;
            std::optional<std::string> deviceName;
        };

        struct LoadUserInfoAction {
            std::string serverUrl;
            std::string userId;
            std::string token;
            std::string deviceId;
            bool loggedIn;
        };

        struct LogoutAction {};

        struct SyncAction {};

        struct LoadSyncTokenAction {
            std::string syncToken;
        };

        using Action = std::variant<LoginAction,
                                    LogoutAction,
                                    LoadUserInfoAction,
                                    SyncAction,
                                    Error::Action,
                                    LoadSyncTokenAction
                                    >;
        using Effect = lager::effect<Action, lager::deps<JobInterface &, EventInterface &>>;
        using Result = std::pair<Client, Effect>;
        static Result update(Client m, Action a);
    };

    Client::Effect syncEffect(Client m, Client::SyncAction a);
}
