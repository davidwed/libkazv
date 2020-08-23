/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv {

/*! \brief Send an event to a given set of devices.
 *
 * This endpoint is used to send send-to-device events to a set of
 * client devices.
 */
class SendToDeviceJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Send an event to a given set of devices.
 *
    * \param eventType
    *   The type of event to send.
    * 
    * \param txnId
    *   The transaction ID for this event. Clients should generate an
    *   ID unique across requests with the same access token; it will be
    *   used by the server to ensure idempotency of requests.
    * 
    * \param messages
    *   The messages to send. A map from user ID, to a map from
    *   device ID to message body. The device ID may also be `*`,
    *   meaning all known devices for the user.
    */
    explicit SendToDeviceJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string eventType , std::string txnId , immer::map<std::string, immer::map<std::string, JsonWrap>> messages  = {});
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string eventType, std::string txnId, immer::map<std::string, immer::map<std::string, JsonWrap>> messages);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

} // namespace Kazv
