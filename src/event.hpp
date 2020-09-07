
#pragma once

#include <string>
#include <cstdint>

#include "jsonwrap.hpp"

namespace Kazv
{
    using Timestamp = std::int_fast64_t;

    class Event
    {
    public:
        static const JsonWrap notYetDecryptedEvent;

        enum DecryptionStatus {
            NotDecrypted,
            Decrypted
        };

        Event();

        Event(JsonWrap j);

        static Event fromSync(Event e, std::string roomId);

        /// returns the id of this event
        std::string id() const;

        std::string sender() const;

        Timestamp originServerTs() const;

        std::string type() const;

        std::string stateKey() const;

        JsonWrap content() const;

        /// returns the decrypted json
        JsonWrap raw() const;

        /// returns the original json we fetched, probably encrypted.
        JsonWrap originalJson() const;

        JsonWrap decryptedJson() const;

        bool encrypted() const;

        bool decrypted() const;

        /// internal. only to be called from inside the client.
        Event setDecryptedJson(JsonWrap decryptedJson, DecryptionStatus decrypted) const;

        template <class Archive>
        void save(Archive & ar, std::uint32_t const /*version*/ ) const {
            ar( m_json, m_decryptedJson, m_decrypted, m_encrypted );
        }

        template <class Archive>
        void load( Archive & ar, std::uint32_t const /*version*/ ) {
            ar( m_json, m_decryptedJson, m_decrypted, m_encrypted );
        }

    private:
        JsonWrap m_json;
        JsonWrap m_decryptedJson;
        DecryptionStatus m_decrypted{NotDecrypted};
        bool m_encrypted{false};
    };

    bool operator==(Event a, Event b);
    inline bool operator!=(Event a, Event b) { return !(a == b); };

}

CEREAL_CLASS_VERSION(Kazv::Event, 0);

namespace nlohmann
{
    template <>
    struct adl_serializer<Kazv::Event> {
        static void to_json(json& j, Kazv::Event w) {
            j = w.originalJson();
        }

        static void from_json(const json& j, Kazv::Event &w) {
            w = Kazv::Event(Kazv::JsonWrap(j));
        }
    };
}
