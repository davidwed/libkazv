
#pragma once

#include <tuple>
#include <variant>
#include <string>

#include <lager/context.hpp>

#include "job/jobinterface.hpp"
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

        using Action = std::variant<LoginAction,
                                    LogoutAction,
                                    LoadUserInfoAction,
                                    Error::Action
                                    >;
        using Effect = lager::effect<Action, lager::deps<JobInterface &>>;
        using Result = std::pair<Client, Effect>;
        static Result update(Client m, Action a);
    };
}
