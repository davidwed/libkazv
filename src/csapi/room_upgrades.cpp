/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "room_upgrades.hpp"

namespace Kazv
{


BaseJob::Query UpgradeRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body UpgradeRoomJob::buildBody(std::string roomId, std::string newVersion)
      {
      // ignore unused param
      (void)(roomId);(void)(newVersion);
      
        json _data
        ;
        
            _data["new_version"s] = newVersion;
          
        return BaseJob::JsonBody(_data);
        

      };

      

UpgradeRoomJob::UpgradeRoomJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId, std::string newVersion)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/upgrade",
          POST,
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, newVersion)
              , buildQuery()
                )
        {
        }

          bool UpgradeRoomJob::success(Response r)
          {
            return BaseJob::success(r)
            
              && isBodyJson(r.body)
            && jsonBody(r).get().contains("replacement_room"s)
          ;
          }


    
    std::string UpgradeRoomJob::replacementRoom(Response r)
    {
    if (jsonBody(r).get()
    .contains("replacement_room"s)) {
    return
    jsonBody(r).get()["replacement_room"s]
    /*.get<std::string>()*/;}
    else { return std::string(  );}
    }

}