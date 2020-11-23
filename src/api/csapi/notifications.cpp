/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "notifications.hpp"

namespace Kazv
{


BaseJob::Query GetNotificationsJob::buildQuery(
std::string from, std::optional<int> limit, std::string only)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "from"s, from);
  
    addToQueryIfNeeded(_q, "limit"s, limit);
  
    addToQueryIfNeeded(_q, "only"s, only);
return _q;
}

    BaseJob::Body GetNotificationsJob::buildBody(std::string from, std::optional<int> limit, std::string only)
      {
      // ignore unused param
      (void)(from);(void)(limit);(void)(only);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetNotificationsJob::GetNotificationsJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string from, std::optional<int> limit, std::string only)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/notifications",
          GET,
          std::string("GetNotifications"),
          _accessToken,
          ReturnType::Json,
            buildBody(from, limit, only)
              , buildQuery(from, limit, only)
                )
        {
        }

        GetNotificationsJob GetNotificationsJob::withData(JsonWrap j) &&
        {
          auto ret = GetNotificationsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetNotificationsJob GetNotificationsJob::withData(JsonWrap j) const &
        {
          auto ret = GetNotificationsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetNotificationsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetNotificationsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("notifications"s)
          ;
          }


    
    std::string GetNotificationsResponse::nextToken() const
    {
    if (jsonBody().get()
    .contains("next_token"s)) {
    return
    jsonBody().get()["next_token"s]
    /*.get<std::string>()*/;}
    else { return std::string(  );}
    }

    
    immer::array<GetNotificationsJob::Notification> GetNotificationsResponse::notifications() const
    {
    if (jsonBody().get()
    .contains("notifications"s)) {
    return
    jsonBody().get()["notifications"s]
    /*.get<immer::array<Notification>>()*/;}
    else { return immer::array<Notification>(  );}
    }

}
