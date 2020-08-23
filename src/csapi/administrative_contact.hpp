/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/request_msisdn_validation.hpp"
#include "csapi/definitions/request_token_response.hpp"
#include "csapi/definitions/request_email_validation.hpp"
#include "csapi/definitions/auth_data.hpp"

namespace Kazv {

/*! \brief Gets a list of a user's third party identifiers.
 *
 * Gets a list of the third party identifiers that the homeserver has
 * associated with the user's account.
 * 
 * This is *not* the same as the list of third party identifiers bound to
 * the user's Matrix ID in identity servers.
 * 
 * Identifiers in this list may be used by the homeserver as, for example,
 * identifiers that it will accept to reset the user's account password.
 */
class GetAccount3PIDsJob : public BaseJob {
public:
  // Inner data structures

/// Gets a list of the third party identifiers that the homeserver has
/// associated with the user's account.
/// 
/// This is *not* the same as the list of third party identifiers bound to
/// the user's Matrix ID in identity servers.
/// 
/// Identifiers in this list may be used by the homeserver as, for example,
/// identifiers that it will accept to reset the user's account password.
    struct ThirdPartyIdentifier
        {
/// The medium of the third party identifier.
          std::string medium;
/// The third party identifier address.
          std::string address;
/// The timestamp, in milliseconds, when the identifier was
/// validated by the identity server.
          std::int_fast64_t validatedAt;
/// The timestamp, in milliseconds, when the homeserver associated the third party identifier with the user.
          std::int_fast64_t addedAt;
        
        };


// Construction/destruction

    /// Gets a list of a user's third party identifiers.
    explicit GetAccount3PIDsJob(std::string serverUrl
    , std::string _accessToken
      
        );


    // Result properties
        
        

    
/// Gets a list of the third party identifiers that the homeserver has
/// associated with the user's account.
/// 
/// This is *not* the same as the list of third party identifiers bound to
/// the user's Matrix ID in identity servers.
/// 
/// Identifiers in this list may be used by the homeserver as, for example,
/// identifiers that it will accept to reset the user's account password.
static immer::array<ThirdPartyIdentifier> threepids(Response r);

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
      template<>
      struct adl_serializer<GetAccount3PIDsJob::ThirdPartyIdentifier> {

  static void from_json(const json &jo, GetAccount3PIDsJob::ThirdPartyIdentifier& result)
  {
  
    result.medium = jo.at("medium"s);
    result.address = jo.at("address"s);
    result.validatedAt = jo.at("validated_at"s);
    result.addedAt = jo.at("added_at"s);
  
  }
};
    }

    namespace Kazv
    {

/*! \brief Adds contact information to the user's account.
 *
 * Adds contact information to the user's account.
 * 
 * This endpoint is deprecated in favour of the more specific ``/3pid/add``
 * and ``/3pid/bind`` endpoints.
 * 
 * .. Note::
 *    Previously this endpoint supported a ``bind`` parameter. This parameter
 *    has been removed, making this endpoint behave as though it was ``false``.
 *    This results in this endpoint being an equivalent to ``/3pid/bind`` rather
 *    than dual-purpose.
 */
class Post3PIDsJob : public BaseJob {
public:
  // Inner data structures

/// The third party credentials to associate with the account.
    struct ThreePidCredentials
        {
/// The client secret used in the session with the identity server.
          std::string clientSecret;
/// The identity server to use.
          std::string idServer;
/// An access token previously registered with the identity server. Servers
/// can treat this as optional to distinguish between r0.5-compatible clients
/// and this specification version.
          std::string idAccessToken;
/// The session identifier given by the identity server.
          std::string sid;
        
        };


// Construction/destruction

  /*! \brief Adds contact information to the user's account.
 *
    * \param threePidCreds
    *   The third party credentials to associate with the account.
    */
    explicit Post3PIDsJob(std::string serverUrl
    , std::string _accessToken
      ,
        ThreePidCredentials threePidCreds );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(ThreePidCredentials threePidCreds);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
      template<>
      struct adl_serializer<Post3PIDsJob::ThreePidCredentials> {
  static void to_json(json& jo, const Post3PIDsJob::ThreePidCredentials &pod)
  {
  
  
    jo["client_secret"s] = pod.clientSecret;
    
    jo["id_server"s] = pod.idServer;
    
    jo["id_access_token"s] = pod.idAccessToken;
    
    jo["sid"s] = pod.sid;
    
  }

};
    }

    namespace Kazv
    {

/*! \brief Adds contact information to the user's account.
 *
 * This API endpoint uses the `User-Interactive Authentication API`_.
 * 
 * Adds contact information to the user's account. Homeservers should use 3PIDs added
 * through this endpoint for password resets instead of relying on the identity server.
 * 
 * Homeservers should prevent the caller from adding a 3PID to their account if it has
 * already been added to another user's account on the homeserver.
 */
class Add3PIDJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Adds contact information to the user's account.
 *
    * \param clientSecret
    *   The client secret used in the session with the homeserver.
    * 
    * \param sid
    *   The session identifier given by the homeserver.
    * 
    * \param auth
    *   Additional authentication information for the
    *   user-interactive authentication API.
    */
    explicit Add3PIDJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string clientSecret , std::string sid , std::optional<AuthenticationData> auth  = std::nullopt);
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string clientSecret, std::string sid, std::optional<AuthenticationData> auth);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Binds a 3PID to the user's account through an Identity Service.
 *
 * Binds a 3PID to the user's account through the specified identity server.
 * 
 * Homeservers should not prevent this request from succeeding if another user
 * has bound the 3PID. Homeservers should simply proxy any errors received by
 * the identity server to the caller.
 * 
 * Homeservers should track successful binds so they can be unbound later.
 */
class Bind3PIDJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Binds a 3PID to the user's account through an Identity Service.
 *
    * \param clientSecret
    *   The client secret used in the session with the identity server.
    * 
    * \param idServer
    *   The identity server to use.
    * 
    * \param idAccessToken
    *   An access token previously registered with the identity server.
    * 
    * \param sid
    *   The session identifier given by the identity server.
    */
    explicit Bind3PIDJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string clientSecret , std::string idServer , std::string idAccessToken , std::string sid );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string clientSecret, std::string idServer, std::string idAccessToken, std::string sid);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Deletes a third party identifier from the user's account
 *
 * Removes a third party identifier from the user's account. This might not
 * cause an unbind of the identifier from the identity server.
 * 
 * Unlike other endpoints, this endpoint does not take an ``id_access_token``
 * parameter because the homeserver is expected to sign the request to the
 * identity server instead.
 */
class Delete3pidFromAccountJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Deletes a third party identifier from the user's account
 *
    * \param medium
    *   The medium of the third party identifier being removed.
    * 
    * \param address
    *   The third party address being removed.
    * 
    * \param idServer
    *   The identity server to unbind from. If not provided, the homeserver
    *   MUST use the ``id_server`` the identifier was added through. If the
    *   homeserver does not know the original ``id_server``, it MUST return
    *   a ``id_server_unbind_result`` of ``no-support``.
    */
    explicit Delete3pidFromAccountJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string medium , std::string address , std::string idServer  = {});
    

    // Result properties
        
        

    
/// An indicator as to whether or not the homeserver was able to unbind
/// the 3PID from the identity server. ``success`` indicates that the
/// indentity server has unbound the identifier whereas ``no-support``
/// indicates that the identity server refuses to support the request
/// or the homeserver was not able to determine an identity server to
/// unbind from.
static std::string idServerUnbindResult(Response r);

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string medium, std::string address, std::string idServer);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Removes a user's third party identifier from an identity server.
 *
 * Removes a user's third party identifier from the provided identity server
 * without removing it from the homeserver.
 * 
 * Unlike other endpoints, this endpoint does not take an ``id_access_token``
 * parameter because the homeserver is expected to sign the request to the
 * identity server instead.
 */
class Unbind3pidFromAccountJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Removes a user's third party identifier from an identity server.
 *
    * \param medium
    *   The medium of the third party identifier being removed.
    * 
    * \param address
    *   The third party address being removed.
    * 
    * \param idServer
    *   The identity server to unbind from. If not provided, the homeserver
    *   MUST use the ``id_server`` the identifier was added through. If the
    *   homeserver does not know the original ``id_server``, it MUST return
    *   a ``id_server_unbind_result`` of ``no-support``.
    */
    explicit Unbind3pidFromAccountJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string medium , std::string address , std::string idServer  = {});
    

    // Result properties
        
        

    
/// An indicator as to whether or not the identity server was able to unbind
/// the 3PID. ``success`` indicates that the identity server has unbound the
/// identifier whereas ``no-support`` indicates that the identity server
/// refuses to support the request or the homeserver was not able to determine
/// an identity server to unbind from.
static std::string idServerUnbindResult(Response r);

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string medium, std::string address, std::string idServer);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Begins the validation process for an email address for association with the user's account.
 *
 * The homeserver must check that the given email address is **not**
 * already associated with an account on this homeserver. This API should
 * be used to request validation tokens when adding an email address to an
 * account. This API's parameters and response are identical to that of
 * the |/register/email/requestToken|_ endpoint. The homeserver should validate
 * the email itself, either by sending a validation email itself or by using
 * a service it has control over.
 */
class RequestTokenTo3PIDEmailJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Begins the validation process for an email address for association with the user's account.
 *
    * \param body
    *   The homeserver must check that the given email address is **not**
    *   already associated with an account on this homeserver. This API should
    *   be used to request validation tokens when adding an email address to an
    *   account. This API's parameters and response are identical to that of
    *   the |/register/email/requestToken|_ endpoint. The homeserver should validate
    *   the email itself, either by sending a validation email itself or by using
    *   a service it has control over.
    */
    explicit RequestTokenTo3PIDEmailJob(std::string serverUrl
    
      ,
        EmailValidationData body );
    

    // Result properties
        

/// An email was sent to the given address. Note that this may be an
/// email containing the validation token or it may be informing the
/// user of an error.
    static RequestTokenResponse data(Response r)
    {
    return
    
      std::move(jsonBody(r).get()).get<RequestTokenResponse>()
    ;
    }
        

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(EmailValidationData body);

        static bool success(Response r);
        
      };

      } 
      namespace nlohmann
      {
      using namespace Kazv;
    
    }

    namespace Kazv
    {

/*! \brief Begins the validation process for a phone number for association with the user's account.
 *
 * The homeserver must check that the given phone number is **not**
 * already associated with an account on this homeserver. This API should
 * be used to request validation tokens when adding a phone number to an
 * account. This API's parameters and response are identical to that of
 * the |/register/msisdn/requestToken|_ endpoint. The homeserver should validate
 * the phone number itself, either by sending a validation message itself or by using
 * a service it has control over.
 */
class RequestTokenTo3PIDMSISDNJob : public BaseJob {
public:


// Construction/destruction

  /*! \brief Begins the validation process for a phone number for association with the user's account.
 *
    * \param body
    *   The homeserver must check that the given phone number is **not**
    *   already associated with an account on this homeserver. This API should
    *   be used to request validation tokens when adding a phone number to an
    *   account. This API's parameters and response are identical to that of
    *   the |/register/msisdn/requestToken|_ endpoint. The homeserver should validate
    *   the phone number itself, either by sending a validation message itself or by using
    *   a service it has control over.
    */
    explicit RequestTokenTo3PIDMSISDNJob(std::string serverUrl
    
      ,
        MsisdnValidationData body );
    

    // Result properties
        

/// An SMS message was sent to the given phone number.
    static RequestTokenResponse data(Response r)
    {
    return
    
      std::move(jsonBody(r).get()).get<RequestTokenResponse>()
    ;
    }
        

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(MsisdnValidationData body);

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
