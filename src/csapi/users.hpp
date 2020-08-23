/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv {

/*! \brief Searches the user directory.
 *
 * Performs a search for users. The homeserver may
 * determine which subset of users are searched, however the homeserver
 * MUST at a minimum consider the users the requesting user shares a
 * room with and those who reside in public rooms (known to the homeserver).
 * The search MUST consider local users to the homeserver, and SHOULD
 * query remote users as part of the search.
 * 
 * The search is performed case-insensitively on user IDs and display
 * names preferably using a collation determined based upon the 
 * ``Accept-Language`` header provided in the request, if present.
 */
class SearchUserDirectoryJob : public BaseJob {
public:
  // Inner data structures

/// Performs a search for users. The homeserver may
/// determine which subset of users are searched, however the homeserver
/// MUST at a minimum consider the users the requesting user shares a
/// room with and those who reside in public rooms (known to the homeserver).
/// The search MUST consider local users to the homeserver, and SHOULD
/// query remote users as part of the search.
/// 
/// The search is performed case-insensitively on user IDs and display
/// names preferably using a collation determined based upon the 
/// ``Accept-Language`` header provided in the request, if present.
    struct User
        {
/// The user's matrix user ID.
          std::string userId;
/// The display name of the user, if one exists.
          std::string displayName;
/// The avatar url, as an MXC, if one exists.
          std::string avatarUrl;
        
        };


// Construction/destruction

  /*! \brief Searches the user directory.
 *
    * \param searchTerm
    *   The term to search for
    * 
    * \param limit
    *   The maximum number of results to return. Defaults to 10.
    */
    explicit SearchUserDirectoryJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string searchTerm , std::optional<int> limit  = std::nullopt);
    

    // Result properties
        
        

    
/// Ordered by rank and then whether or not profile info is available.
static immer::array<User> results(Response r);

    
/// Indicates if the result list has been truncated by the limit.
static bool limited(Response r);

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string searchTerm, std::optional<int> limit);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
      template<>
      struct adl_serializer<SearchUserDirectoryJob::User> {

  static void from_json(const json &jo, SearchUserDirectoryJob::User& result)
  {
  
    result.userId = jo.at("user_id"s);
    result.displayName = jo.at("display_name"s);
    result.avatarUrl = jo.at("avatar_url"s);
  
  }
};
    }

    namespace Kazv
    {

} // namespace Kazv