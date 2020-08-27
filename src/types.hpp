
#pragma once
#include <string>
#include <variant>
#include <nlohmann/json.hpp>
#include <immer/array.hpp>
#include <immer/map.hpp>
#include <boost/hana/type.hpp>
#include <lager/util.hpp>

#include "descendent.hpp"

namespace Kazv
{
    using json = nlohmann::json;

    using Bytes = std::string;

    enum Status : bool
    {
        FAIL,
        SUCC,
    };

    class JsonWrap
    {
        // Cannot use box here, because it causes the resulting json
        // to be wrapped into an array.
        // https://github.com/arximboldi/immer/issues/155
        immer::array<json> m_d;
    public:
        JsonWrap() = default;
        JsonWrap(json&& j) : m_d(1, std::move(j)) {}
        JsonWrap(const json& j) : m_d(1, j) {}

        const json &get() const { return m_d.at(0); }
        operator json() const { return m_d.at(0); }
    };

    namespace detail
    {
        auto hasEmptyMethod = boost::hana::is_valid(
            [](auto &&x) -> decltype((void)x.empty()) {});
        template<class U>
        struct AddToJsonIfNeededT
        {
            template<class T>
            static void call(json &j, std::string name, T &&arg) {
                if constexpr (detail::hasEmptyMethod(arg)) {
                    if (! arg.empty()) {
                        j[name] = std::forward<T>(arg);
                    }
                } else {
                    j[name] = std::forward<T>(arg);
                }
            }
        };

        template<class U>
        struct AddToJsonIfNeededT<std::optional<U>>
        {
            template<class T>
            static void call(json &j, std::string name, T &&arg) {
                if (arg.has_value()) {
                    j[name] = std::forward<T>(arg).value();
                }
            }
        };

    }

    template<class T>
    inline void addToJsonIfNeeded(json &j, std::string name, T &&arg)
    {
        detail::AddToJsonIfNeededT<std::decay_t<T>>::call(j, name, std::forward<T>(arg));
    };

    // Provide a non-destructive way to add the map
    // to json.
    template<class MapT,
             // disallow json object here
             std::enable_if_t<!std::is_same_v<std::decay_t<MapT>, json>
                              && !std::is_same_v<std::decay_t<MapT>, JsonWrap>, int> = 0>
    inline void addPropertyMapToJson(json &j, MapT &&arg)
    {
        for (auto kv : std::forward<MapT>(arg)) {
            auto [k, v] = kv;
            j[k] = v;
        }
    };

    inline void addPropertyMapToJson(json &j, const json &arg)
    {
        for (auto kv : arg.items()) {
            auto [k, v] = kv;
            j[k] = v;
        }
    };
    using EventList = immer::array<JsonWrap>;

    using namespace std::string_literals;

    struct Null {};
    using Variant = std::variant<std::string, JsonWrap, Null>;
}

namespace nlohmann {
    template <class T, class V>
    struct adl_serializer<immer::map<T, V>> {
        static void to_json(json& j, immer::map<T, V> map) {
            for (auto [k, v] : map) {
                j[k] = v;
            }
        }

        static void from_json(const json& j, immer::map<T, V> &m) {
            immer::map<T, V> ret;
            if (j.is_object()) {
                for (const auto &[k, v] : j.items()) {
                    ret = std::move(ret).set(k, v);
                }
            }
            m = ret;
        }
    };

    template <class T>
    struct adl_serializer<immer::array<T>> {
        static void to_json(json& j, immer::array<T> arr) {
            for (auto i : arr) {
                j.push_back(i);
            }
        }

        static void from_json(const json& j, immer::array<T> &a) {
            immer::array<T> ret;
            if (j.is_array()) {
                for (const auto &i : j) {
                    ret = std::move(ret).push_back(i);
                }
            }
            a = ret;
        }
    };

    template <>
    struct adl_serializer<Kazv::JsonWrap> {
        static void to_json(json& j, Kazv::JsonWrap w) {
            j = w.get();
        }

        static void from_json(const json& j, Kazv::JsonWrap &w) {
            w = Kazv::JsonWrap(j);
        }
    };

    template <>
    struct adl_serializer<Kazv::Variant> {
        static void to_json(json& j, const Kazv::Variant &var) {
            std::visit(lager::visitor{
                    [&j](std::string i) { j = i; },
                    [&j](Kazv::JsonWrap i) { j = i; },
                    [&j](Kazv::Null) { j = nullptr; }
                }, var);
        }

        static void from_json(const json& j, Kazv::Variant &var) {
            if (j.is_string()) {
                var = j.get<std::string>();
            } else if (j.is_null()) {
                var = Kazv::Null{};
            } else { // is object
                var = Kazv::Variant(Kazv::JsonWrap(j));
            }
        }
    };

}

namespace Kazv
{
    inline bool operator==(JsonWrap a, JsonWrap b)
    {
        return a.get() == b.get();
    }

}
