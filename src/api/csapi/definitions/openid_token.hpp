/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct OpenidToken
{       

/// An access token the consumer may use to verify the identity of
/// the person who generated the token. This is given to the federation
/// API ``GET /openid/userinfo`` to verify the user's identity.
    std::string accessToken;

/// The string ``Bearer``.
    std::string tokenType;

/// The homeserver domain the consumer should use when attempting to
/// verify the user's identity.
    std::string matrixServerName;

/// The number of seconds before this token expires and a new one must
/// be generated.
    int expiresIn;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<OpenidToken> {
  static void to_json(json& jo, const OpenidToken &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["access_token"s] = pod.accessToken;
    
    jo["token_type"s] = pod.tokenType;
    
    jo["matrix_server_name"s] = pod.matrixServerName;
    
    jo["expires_in"s] = pod.expiresIn;
    
  }
  static void from_json(const json &jo, OpenidToken& result)
  {
  
    if (jo.contains("access_token"s)) {
      result.accessToken = jo.at("access_token"s);
    }
    if (jo.contains("token_type"s)) {
      result.tokenType = jo.at("token_type"s);
    }
    if (jo.contains("matrix_server_name"s)) {
      result.matrixServerName = jo.at("matrix_server_name"s);
    }
    if (jo.contains("expires_in"s)) {
      result.expiresIn = jo.at("expires_in"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
