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

#include "libkazv-config.hpp"


#include <lager/util.hpp>
#include <vector>
#include <tuple>

#include "basejob.hpp"

namespace Kazv
{
    BaseJob::Get BaseJob::GET{};
    BaseJob::Post BaseJob::POST{};
    BaseJob::Put BaseJob::PUT{};
    BaseJob::Delete BaseJob::DELETE{};

    struct BaseJob::Private
    {
        Private(std::string serverUrl,
                std::string requestUrl,
                Method method,
                std::string token,
                ReturnType returnType,
                Body body,
                Query query,
                Header header,
                std::string jobId);
        std::string fullRequestUrl;
        Method method;
        ReturnType returnType;
        BytesBody body;
        Query query;
        Header header;
        JsonWrap data;
        std::string jobId;
        std::optional<std::string> queueId;
        JobQueuePolicy queuePolicy;
    };

    BaseJob::Private::Private(std::string serverUrl,
                              std::string requestUrl,
                              Method method,
                              std::string token,
                              ReturnType returnType,
                              Body body,
                              Query query,
                              Header header,
                              std::string jobId)
        : fullRequestUrl(serverUrl + requestUrl)
        , method(std::move(method))
        , returnType(returnType)
        , body()
        , query(std::move(query))
        , jobId(std::move(jobId))
    {
        auto header_ = header.get();
        if (token.size()) {
            header_["Authorization"] = "Bearer " + token;
        }

        if (isBodyJson(body)) {
            JsonBody j = std::get<JsonBody>(std::move(body));
            header_["Content-Type"] = "application/json";
            this->body = j.get().dump();
        } else if (std::holds_alternative<BytesBody>(body)) {
            BytesBody b = std::get<BytesBody>(std::move(body));
            this->body = b;
        }

        this->header = header_;
    }

    BaseJob::BaseJob(std::string serverUrl,
                     std::string requestUrl,
                     Method method,
                     std::string jobId,
                     std::string token,
                     ReturnType returnType,
                     Body body,
                     Query query,
                     Header header)
        : m_d(std::move(Private(serverUrl, requestUrl, method, token,
                                returnType, body, query, header, jobId)))
    {
    }

    bool BaseJob::shouldReturnJson() const
    {
        return m_d->returnType == ReturnType::Json;
    };

    std::string BaseJob::url() const
    {
        return m_d->fullRequestUrl;
    };

    auto BaseJob::requestBody() const -> BytesBody
    {
        return m_d->body;
    }

    auto BaseJob::requestHeader() const -> Header
    {
        return m_d->header;
    }

    auto BaseJob::returnType() const -> ReturnType
    {
        return m_d->returnType;
    }

    auto BaseJob::requestQuery() const -> Query
    {
        return m_d->query;
    }

    auto BaseJob::requestMethod() const -> Method
    {
        return m_d->method;
    }

    JsonWrap Response::jsonBody() const
    {
        return std::get<JsonWrap>(body);
    }

    json Response::dataJson(const std::string &key) const
    {
        return extraData.get()[key];
    }

    std::string Response::dataStr(const std::string &key) const
    {
        return dataJson(key);
    }

    std::string Response::jobId() const
    {
        return dataStr("-job-id");
    }


    bool BaseJob::contentTypeMatches(immer::array<std::string> expected, std::string actual)
    {
        for (const auto &i : expected) {
            if (i == "*/*"s) {
                return true;
            } else {
                std::size_t pos = i.find("/*"s);
                if (pos != std::string::npos) {
                    std::string majorType(i.data(), i.data() + pos + 1); // includes `/'
                    if (actual.find(majorType) == 0) {
                        return true;
                    }
                } else if (i == actual) {
                    return true;
                }
            }
        }
        return false;
    }

    Response BaseJob::genResponse(Response r) const
    {
        auto j = m_d->data.get();
        j["-job-id"] = m_d->jobId;
        r.extraData = j;
        return r;
    }

    void BaseJob::attachData(JsonWrap j)
    {
        m_d->data = j;
    }

    BaseJob BaseJob::withData(JsonWrap j) &&
    {
        auto ret = BaseJob(std::move(*this));
        ret.attachData(j);
        return ret;
    }

    BaseJob BaseJob::withData(JsonWrap j) const &
    {
        auto ret = BaseJob(*this);
        ret.attachData(j);
        return ret;
    }

    BaseJob BaseJob::withQueue(std::string id, JobQueuePolicy policy) &&
    {
        auto ret = BaseJob(std::move(*this));
        ret.m_d->queueId = id;
        ret.m_d->queuePolicy = policy;
        return ret;
    }

    BaseJob BaseJob::withQueue(std::string id, JobQueuePolicy policy) const &
    {
        auto ret = BaseJob(*this);
        ret.m_d->queueId = id;
        ret.m_d->queuePolicy = policy;
        return ret;
    }

    json BaseJob::dataJson(const std::string &key) const
    {
        return m_d->data.get()[key];
    }

    std::string BaseJob::dataStr(const std::string &key) const
    {
        return dataJson(key);
    }

    std::string BaseJob::jobId() const
    {
        return m_d->jobId;
    }

    std::optional<std::string> BaseJob::queueId() const
    {
        return m_d->queueId;
    }

    JobQueuePolicy BaseJob::queuePolicy() const
    {
        return m_d->queuePolicy;
    }

    std::string Response::errorCode() const
    {
        // https://matrix.org/docs/spec/client_server/latest#api-standards
        if (isBodyJson(body)) {
            auto jb = jsonBody();
            if (jb.get().contains("errcode")) {
                auto code = jb.get()["errcode"].get<std::string>();
                if (code != "M_UNKNOWN") {
                    return code;
                }
            }
        }
        return std::to_string(statusCode);
    }

    std::string Response::errorMessage() const
    {
        if (isBodyJson(body)) {
            auto jb = jsonBody();
            if (jb.get().contains("error")) {
                auto msg = jb.get()["error"].get<std::string>();
                return msg;
            }
        }
        return "";
    }

    bool operator==(BaseJob a, BaseJob b)
    {
        return a.m_d->fullRequestUrl == b.m_d->fullRequestUrl
            && a.m_d->method == b.m_d->method
            && a.m_d->returnType == b.m_d->returnType
            && a.m_d->body == b.m_d->body
            && a.m_d->query == b.m_d->query
            && a.m_d->header == b.m_d->header
            && a.m_d->data == b.m_d->data
            && a.m_d->jobId == b.m_d->jobId;
    }

    bool operator!=(BaseJob a, BaseJob b)
    {
        return !(a == b);
    }
}
