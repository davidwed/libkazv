/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/../../identity/definitions/request_msisdn_validation.hpp"

namespace Kazv {

struct MsisdnValidationData : RequestMsisdnValidation
{       

/// The hostname of the identity server to communicate with. May optionally
/// include a port. This parameter is ignored when the homeserver handles
/// 3PID verification.
/// 
/// This parameter is deprecated with a plan to be removed in a future specification
/// version for ``/account/password`` and ``/register`` requests.
    std::string idServer;

/// An access token previously registered with the identity server. Servers
/// can treat this as optional to distinguish between r0.5-compatible clients
/// and this specification version.
/// 
/// Required if an ``id_server`` is supplied.
    std::string idAccessToken;
};

}
namespace nlohmann
{
using namespace Kazv;
template<>
struct adl_serializer<MsisdnValidationData> {
  static void to_json(json& jo, const MsisdnValidationData &pod)
  {
    jo = static_cast<const RequestMsisdnValidation &>(pod);
  
    
    addToJsonIfNeeded(jo, "id_server"s, pod.idServer);
    
    addToJsonIfNeeded(jo, "id_access_token"s, pod.idAccessToken);
  }
  static void from_json(const json &jo, MsisdnValidationData& result)
  {
    static_cast<RequestMsisdnValidation &>(result) = jo;
    result.idServer = jo.at("id_server"s);
    result.idAccessToken = jo.at("id_access_token"s);
  
  }
};
    }

    namespace Kazv
    {
} // namespace Kazv
