/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv {

/*! \brief Updates a room's visibility in the application service's room directory.
 *
 * Updates the visibility of a given room on the application service's room
 * directory.
 * 
 * This API is similar to the room directory visibility API used by clients
 * to update the homeserver's more general room directory.
 * 
 * This API requires the use of an application service access token (``as_token``)
 * instead of a typical client's access_token. This API cannot be invoked by
 * users who are not identified as application services.
 */
class UpdateAppserviceRoomDirectoryVsibilityJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Updates a room's visibility in the application service's room directory.
 *
    * \param networkId
    *   The protocol (network) ID to update the room list for. This would
    *   have been provided by the application service as being listed as
    *   a supported protocol.
    * 
    * \param roomId
    *   The room ID to add to the directory.
    * 
    * \param visibility
    *   Whether the room should be visible (public) in the directory
    *   or not (private).
    */
    explicit UpdateAppserviceRoomDirectoryVsibilityJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string networkId , std::string roomId , std::string visibility );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string networkId, std::string roomId, std::string visibility);

        

        

      UpdateAppserviceRoomDirectoryVsibilityJob withData(JsonWrap j) &&;
      UpdateAppserviceRoomDirectoryVsibilityJob withData(JsonWrap j) const &;
      };
      using UpdateAppserviceRoomDirectoryVsibilityResponse = UpdateAppserviceRoomDirectoryVsibilityJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

} // namespace Kazv
