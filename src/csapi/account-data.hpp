/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv {

/*! \brief Set some account_data for the user.
 *
 * Set some account_data for the client. This config is only visible to the user
 * that set the account_data. The config will be synced to clients in the
 * top-level ``account_data``.
 */
class SetAccountDataJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Set some account_data for the user.
 *
    * \param userId
    *   The ID of the user to set account_data for. The access token must be
    *   authorized to make requests for this user ID.
    * 
    * \param type
    *   The event type of the account_data to set. Custom types should be
    *   namespaced to avoid clashes.
    * 
    * \param content
    *   The content of the account_data
    */
    explicit SetAccountDataJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string type , JsonWrap content  = {});
    

    

    static BaseJob::Body buildBody(std::string userId, std::string type, JsonWrap content);
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Get some account_data for the user.
 *
 * Get some account_data for the client. This config is only visible to the user
 * that set the account_data.
 */
class GetAccountDataJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Get some account_data for the user.
 *
    * \param userId
    *   The ID of the user to get account_data for. The access token must be
    *   authorized to make requests for this user ID.
    * 
    * \param type
    *   The event type of the account_data to get. Custom types should be
    *   namespaced to avoid clashes.
    */
    explicit GetAccountDataJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string type );


    

    static BaseJob::Body buildBody(std::string userId, std::string type);
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Set some account_data for the user.
 *
 * Set some account_data for the client on a given room. This config is only
 * visible to the user that set the account_data. The config will be synced to
 * clients in the per-room ``account_data``.
 */
class SetAccountDataPerRoomJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Set some account_data for the user.
 *
    * \param userId
    *   The ID of the user to set account_data for. The access token must be
    *   authorized to make requests for this user ID.
    * 
    * \param roomId
    *   The ID of the room to set account_data on.
    * 
    * \param type
    *   The event type of the account_data to set. Custom types should be
    *   namespaced to avoid clashes.
    * 
    * \param content
    *   The content of the account_data
    */
    explicit SetAccountDataPerRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string roomId , std::string type , JsonWrap content  = {});
    

    

    static BaseJob::Body buildBody(std::string userId, std::string roomId, std::string type, JsonWrap content);
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Get some account_data for the user.
 *
 * Get some account_data for the client on a given room. This config is only
 * visible to the user that set the account_data.
 */
class GetAccountDataPerRoomJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Get some account_data for the user.
 *
    * \param userId
    *   The ID of the user to set account_data for. The access token must be
    *   authorized to make requests for this user ID.
    * 
    * \param roomId
    *   The ID of the room to get account_data for.
    * 
    * \param type
    *   The event type of the account_data to get. Custom types should be
    *   namespaced to avoid clashes.
    */
    explicit GetAccountDataPerRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string roomId , std::string type );


    

    static BaseJob::Body buildBody(std::string userId, std::string roomId, std::string type);
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

} // namespace Kazv
