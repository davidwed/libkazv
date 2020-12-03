/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "room_initial_sync.hpp"

namespace Kazv
{


BaseJob::Query RoomInitialSyncJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RoomInitialSyncJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

RoomInitialSyncJob::RoomInitialSyncJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/initialSync",
          GET,
          std::string("RoomInitialSync"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                )
        {
        }

        RoomInitialSyncJob RoomInitialSyncJob::withData(JsonWrap j) &&
        {
          auto ret = RoomInitialSyncJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RoomInitialSyncJob RoomInitialSyncJob::withData(JsonWrap j) const &
        {
          auto ret = RoomInitialSyncJob(*this);
          ret.attachData(j);
          return ret;
        }

        RoomInitialSyncJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RoomInitialSyncResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("room_id"s)
          ;
          }


    
    std::string RoomInitialSyncResponse::roomId() const
    {
    if (jsonBody().get()
    .contains("room_id"s)) {
    return
    jsonBody().get()["room_id"s]
    /*.get<std::string>()*/;}
    else { return std::string(  );}
    }

    
    std::string RoomInitialSyncResponse::membership() const
    {
    if (jsonBody().get()
    .contains("membership"s)) {
    return
    jsonBody().get()["membership"s]
    /*.get<std::string>()*/;}
    else { return std::string(  );}
    }

    
    std::optional<RoomInitialSyncJob::PaginationChunk> RoomInitialSyncResponse::messages() const
    {
    if (jsonBody().get()
    .contains("messages"s)) {
    return
    jsonBody().get()["messages"s]
    /*.get<PaginationChunk>()*/;}
    else { return std::optional<PaginationChunk>(  );}
    }

    
    EventList RoomInitialSyncResponse::state() const
    {
    if (jsonBody().get()
    .contains("state"s)) {
    return
    jsonBody().get()["state"s]
    /*.get<EventList>()*/;}
    else { return EventList(  );}
    }

    
    std::string RoomInitialSyncResponse::visibility() const
    {
    if (jsonBody().get()
    .contains("visibility"s)) {
    return
    jsonBody().get()["visibility"s]
    /*.get<std::string>()*/;}
    else { return std::string(  );}
    }

    
    EventList RoomInitialSyncResponse::accountData() const
    {
    if (jsonBody().get()
    .contains("account_data"s)) {
    return
    jsonBody().get()["account_data"s]
    /*.get<EventList>()*/;}
    else { return EventList(  );}
    }

}