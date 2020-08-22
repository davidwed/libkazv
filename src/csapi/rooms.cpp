/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include "rooms.hpp"

namespace Kazv
{
  

    BaseJob::Body GetOneRoomEventJob::buildBody(std::string roomId, std::string eventId)
      {
      // ignore unused param
      (void)(roomId);(void)(eventId);
      
      
              return BaseJob::EmptyBody{};

      };

GetOneRoomEventJob::GetOneRoomEventJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId, std::string eventId)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/event/" + eventId,
          GET,
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventId)
      )
        {
        
        
        }


  

    BaseJob::Body GetRoomStateWithKeyJob::buildBody(std::string roomId, std::string eventType, std::string stateKey)
      {
      // ignore unused param
      (void)(roomId);(void)(eventType);(void)(stateKey);
      
      
              return BaseJob::EmptyBody{};

      };

GetRoomStateWithKeyJob::GetRoomStateWithKeyJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId, std::string eventType, std::string stateKey)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/state/" + eventType + "/" + stateKey,
          GET,
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventType, stateKey)
      )
        {
        
        
        }


  

    BaseJob::Body GetRoomStateJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

GetRoomStateJob::GetRoomStateJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/state",
          GET,
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
      )
        {
        
        
        }



BaseJob::Query GetMembersByRoomJob::buildQuery(
std::string at, std::string membership, std::string notMembership)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "at"s, at);
  
    addToQueryIfNeeded(_q, "membership"s, membership);
  
    addToQueryIfNeeded(_q, "not_membership"s, notMembership);
return _q;
}

    BaseJob::Body GetMembersByRoomJob::buildBody(std::string roomId, std::string at, std::string membership, std::string notMembership)
      {
      // ignore unused param
      (void)(roomId);(void)(at);(void)(membership);(void)(notMembership);
      
      
              return BaseJob::EmptyBody{};

      };

GetMembersByRoomJob::GetMembersByRoomJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId, std::string at, std::string membership, std::string notMembership)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/members",
          GET,
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, at, membership, notMembership)
      , buildQuery(at, membership, notMembership))
        {
        
        
        }


    
    immer::array<TheCurrentMembershipStateOfAUserInTheRoom> GetMembersByRoomJob::chunk(Response r)
    {
    if (jsonBody(r).get()
    .contains("chunk"s)) {
    return
    jsonBody(r).get()["chunk"s]
    /*.get<immer::array<TheCurrentMembershipStateOfAUserInTheRoom>>()*/;}
    else { return immer::array<TheCurrentMembershipStateOfAUserInTheRoom>(  );}
    }

  

    BaseJob::Body GetJoinedMembersByRoomJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

GetJoinedMembersByRoomJob::GetJoinedMembersByRoomJob(
        std::string serverUrl
        , std::string _accessToken
        ,
        std::string roomId)
      : BaseJob(std::move(serverUrl),
          std::string("/_matrix/client/r0") + "/rooms/" + roomId + "/joined_members",
          GET,
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
      )
        {
        
        
        }


    
    immer::map<std::string, GetJoinedMembersByRoomJob::RoomMember> GetJoinedMembersByRoomJob::joined(Response r)
    {
    if (jsonBody(r).get()
    .contains("joined"s)) {
    return
    jsonBody(r).get()["joined"s]
    /*.get<immer::map<std::string, RoomMember>>()*/;}
    else { return immer::map<std::string, RoomMember>(  );}
    }

}
