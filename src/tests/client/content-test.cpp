/*
 * Copyright (C) 2021 Tusooa Zhu <tusooa@vista.aero>
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


#include <catch2/catch.hpp>

#include <boost/asio.hpp>

#include <asio-promise-handler.hpp>
#include <cursorutil.hpp>
#include <sdk-model.hpp>
#include <client/client.hpp>

#include "client-test-util.hpp"

// The example response is adapted from https://matrix.org/docs/spec/client_server/latest
static json uploadContentResponseJson = R"({
  "content_uri": "mxc://example.com/AQwafuaFswefuhsfAFAgsw"
})"_json;

TEST_CASE("Upload content should give the mxc uri", "[client][content]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("UploadContent", uploadContentResponseJson, json{{"uploadId", "whatever"}});

    store.dispatch(ProcessResponseAction{resp})
        .then([](auto stat) {
                  REQUIRE(stat.success());
                  auto mxcUri = stat.dataStr("mxcUri");
                  REQUIRE(mxcUri == std::string("mxc://example.com/AQwafuaFswefuhsfAFAgsw"));
              });

    io.run();
}