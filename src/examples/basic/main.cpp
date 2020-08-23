
#include <string>
#include <iostream>
#include <lager/store.hpp>
#include <lager/event_loop/manual.hpp>

#include <client/client.hpp>
#include <job/cprjobhandler.hpp>

using namespace std::string_literals;

int main()
{
    Kazv::Descendent<Kazv::JobInterface> jobHandler(Kazv::CprJobHandler{});
    auto store = lager::make_store<Kazv::Client::Action>(
        Kazv::Client{},
        &Kazv::Client::update,
        lager::with_manual_event_loop{},
        lager::with_deps(std::ref(*jobHandler.data())));

    std::string homeserver;
    std::string username;
    std::string password;
    std::cout << "Homeserver: ";
    std::getline(std::cin, homeserver);
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);
    store.dispatch(Kazv::Client::LoginAction{homeserver, username, password, "libkazv basic example"s});

    std::cout << "Token: " << store.get().token << std::endl;

}
