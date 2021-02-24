/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/request_msisdn_validation.hpp"
#include "csapi/definitions/request_token_response.hpp"
#include "csapi/definitions/auth_data.hpp"
#include "csapi/definitions/request_email_validation.hpp"

namespace Kazv::Api {

/*! \brief Register for an account on this homeserver.
 *
 * This API endpoint uses the `User-Interactive Authentication API`_, except in
 * the cases where a guest account is being registered.
 * 
 * Register for an account on this homeserver.
 * 
 * There are two kinds of user account:
 * 
 * - `user` accounts. These accounts may use the full API described in this specification.
 * 
 * - `guest` accounts. These accounts may have limited permissions and may not be supported by all servers.
 * 
 * If registration is successful, this endpoint will issue an access token
 * the client can use to authorize itself in subsequent requests.
 * 
 * If the client does not supply a ``device_id``, the server must
 * auto-generate one.
 * 
 * The server SHOULD register an account with a User ID based on the
 * ``username`` provided, if any. Note that the grammar of Matrix User ID
 * localparts is restricted, so the server MUST either map the provided
 * ``username`` onto a ``user_id`` in a logical manner, or reject
 * ``username``\s which do not comply to the grammar, with
 * ``M_INVALID_USERNAME``.
 * 
 * Matrix clients MUST NOT assume that localpart of the registered
 * ``user_id`` matches the provided ``username``.
 * 
 * The returned access token must be associated with the ``device_id``
 * supplied by the client or generated by the server. The server may
 * invalidate any access token previously associated with that device. See
 * `Relationship between access tokens and devices`_.
 * 
 * When registering a guest account, all parameters in the request body
 * with the exception of ``initial_device_display_name`` MUST BE ignored
 * by the server. The server MUST pick a ``device_id`` for the account
 * regardless of input.
 * 
 * Any user ID returned by this API must conform to the grammar given in the
 * `Matrix specification <../appendices.html#user-identifiers>`_.
 */
class RegisterJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The fully-qualified Matrix user ID (MXID) that has been registered.
/// 
/// Any user ID returned by this API must conform to the grammar given in the
/// `Matrix specification <../appendices.html#user-identifiers>`_.
std::string userId() const;

    
/// An access token for the account.
/// This access token can then be used to authorize other requests.
/// Required if the ``inhibit_login`` option is false.
std::optional<std::string> accessToken() const;

    
/// The server_name of the homeserver on which the account has
/// been registered.
/// 
/// **Deprecated**. Clients should extract the server_name from
/// ``user_id`` (by splitting at the first colon) if they require
/// it. Note also that ``homeserver`` is not spelt this way.
std::optional<std::string> homeServer() const;

    
/// ID of the registered device. Will be the same as the
/// corresponding parameter in the request, if one was specified.
/// Required if the ``inhibit_login`` option is false.
std::optional<std::string> deviceId() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Register for an account on this homeserver.
 *
    * \param kind
    *   The kind of account to register. Defaults to ``user``.
    * 
    * \param auth
    *   Additional authentication information for the
    *   user-interactive authentication API. Note that this
    *   information is *not* used to define how the registered user
    *   should be authenticated, but is instead used to
    *   authenticate the ``register`` call itself.
    * 
    * \param username
    *   The basis for the localpart of the desired Matrix ID. If omitted,
    *   the homeserver MUST generate a Matrix ID local part.
    * 
    * \param password
    *   The desired password for the account.
    * 
    * \param deviceId
    *   ID of the client device. If this does not correspond to a
    *   known client device, a new device will be created. The server
    *   will auto-generate a device_id if this is not specified.
    * 
    * \param initialDeviceDisplayName
    *   A display name to assign to the newly-created device. Ignored
    *   if ``device_id`` corresponds to a known device.
    * 
    * \param inhibitLogin
    *   If true, an ``access_token`` and ``device_id`` should not be
    *   returned from this call, therefore preventing an automatic
    *   login. Defaults to false.
    */
    explicit RegisterJob(std::string serverUrl
    
      ,
        std::string kind  = std::string("user"), std::optional<AuthenticationData> auth  = std::nullopt, std::optional<std::string> username  = std::nullopt, std::optional<std::string> password  = std::nullopt, std::optional<std::string> deviceId  = std::nullopt, std::optional<std::string> initialDeviceDisplayName  = std::nullopt, std::optional<bool> inhibitLogin  = std::nullopt);
    

    static BaseJob::Query buildQuery(
    std::string kind);

      static BaseJob::Body buildBody(std::string kind, std::optional<AuthenticationData> auth, std::optional<std::string> username, std::optional<std::string> password, std::optional<std::string> deviceId, std::optional<std::string> initialDeviceDisplayName, std::optional<bool> inhibitLogin);

        

        

      RegisterJob withData(JsonWrap j) &&;
      RegisterJob withData(JsonWrap j) const &;
      };
      using RegisterResponse = RegisterJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Begins the validation process for an email to be used during registration.
 *
 * The homeserver must check that the given email address is **not**
 * already associated with an account on this homeserver. The homeserver
 * should validate the email itself, either by sending a validation email
 * itself or by using a service it has control over.
 */
class RequestTokenToRegisterEmailJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// An email has been sent to the specified address. Note that this
/// may be an email containing the validation token or it may be
/// informing the user of an error.
    
    RequestTokenResponse data() const
    {
    return
      std::move(jsonBody().get()).get<RequestTokenResponse>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Begins the validation process for an email to be used during registration.
 *
    * \param body
    *   The homeserver must check that the given email address is **not**
    *   already associated with an account on this homeserver. The homeserver
    *   should validate the email itself, either by sending a validation email
    *   itself or by using a service it has control over.
    */
    explicit RequestTokenToRegisterEmailJob(std::string serverUrl
    
      ,
        EmailValidationData body );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(EmailValidationData body);

        

        

      RequestTokenToRegisterEmailJob withData(JsonWrap j) &&;
      RequestTokenToRegisterEmailJob withData(JsonWrap j) const &;
      };
      using RequestTokenToRegisterEmailResponse = RequestTokenToRegisterEmailJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Requests a validation token be sent to the given phone number for the purpose of registering an account
 *
 * The homeserver must check that the given phone number is **not**
 * already associated with an account on this homeserver. The homeserver
 * should validate the phone number itself, either by sending a validation
 * message itself or by using a service it has control over.
 */
class RequestTokenToRegisterMSISDNJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// An SMS message has been sent to the specified phone number. Note
/// that this may be an SMS message containing the validation token or
/// it may be informing the user of an error.
    
    RequestTokenResponse data() const
    {
    return
      std::move(jsonBody().get()).get<RequestTokenResponse>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Requests a validation token be sent to the given phone number for the purpose of registering an account
 *
    * \param body
    *   The homeserver must check that the given phone number is **not**
    *   already associated with an account on this homeserver. The homeserver
    *   should validate the phone number itself, either by sending a validation
    *   message itself or by using a service it has control over.
    */
    explicit RequestTokenToRegisterMSISDNJob(std::string serverUrl
    
      ,
        MsisdnValidationData body );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(MsisdnValidationData body);

        

        

      RequestTokenToRegisterMSISDNJob withData(JsonWrap j) &&;
      RequestTokenToRegisterMSISDNJob withData(JsonWrap j) const &;
      };
      using RequestTokenToRegisterMSISDNResponse = RequestTokenToRegisterMSISDNJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Changes a user's password.
 *
 * Changes the password for an account on this homeserver.
 * 
 * This API endpoint uses the `User-Interactive Authentication API`_ to
 * ensure the user changing the password is actually the owner of the
 * account.
 * 
 * An access token should be submitted to this endpoint if the client has
 * an active session.
 * 
 * The homeserver may change the flows available depending on whether a
 * valid access token is provided. The homeserver SHOULD NOT revoke the
 * access token provided in the request. Whether other access tokens for
 * the user are revoked depends on the request parameters.
 */
class ChangePasswordJob : public BaseJob {
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

  /*! \brief Changes a user's password.
 *
    * \param newPassword
    *   The new password for the account.
    * 
    * \param logoutDevices
    *   Whether the user's other access tokens, and their associated devices, should be
    *   revoked if the request succeeds. Defaults to true.
    *   
    *   When ``false``, the server can still take advantage of `the soft logout method <#soft-logout>`_
    *   for the user's remaining devices.
    * 
    * \param auth
    *   Additional authentication information for the user-interactive authentication API.
    */
    explicit ChangePasswordJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string newPassword , std::optional<bool> logoutDevices  = std::nullopt, std::optional<AuthenticationData> auth  = std::nullopt);
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string newPassword, std::optional<bool> logoutDevices, std::optional<AuthenticationData> auth);

        

        

      ChangePasswordJob withData(JsonWrap j) &&;
      ChangePasswordJob withData(JsonWrap j) const &;
      };
      using ChangePasswordResponse = ChangePasswordJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Requests a validation token be sent to the given email address for the purpose of resetting a user's password
 *
 * The homeserver must check that the given email address **is
 * associated** with an account on this homeserver. This API should be
 * used to request validation tokens when authenticating for the
 * ``/account/password`` endpoint.
 * 
 * This API's parameters and response are identical to that of the
 * |/register/email/requestToken|_ endpoint, except that
 * ``M_THREEPID_NOT_FOUND`` may be returned if no account matching the
 * given email address could be found. The server may instead send an
 * email to the given address prompting the user to create an account.
 * ``M_THREEPID_IN_USE`` may not be returned.
 * 
 * The homeserver should validate the email itself, either by sending a
 * validation email itself or by using a service it has control over.
 * 
 * 
 * .. |/register/email/requestToken| replace:: ``/register/email/requestToken``
 * 
 * .. _/register/email/requestToken: #post-matrix-client-r0-register-email-requesttoken
 */
class RequestTokenToResetPasswordEmailJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// An email was sent to the given address.
    
    RequestTokenResponse data() const
    {
    return
      std::move(jsonBody().get()).get<RequestTokenResponse>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Requests a validation token be sent to the given email address for the purpose of resetting a user's password
 *
    * \param body
    *   The homeserver must check that the given email address **is
    *   associated** with an account on this homeserver. This API should be
    *   used to request validation tokens when authenticating for the
    *   ``/account/password`` endpoint.
    *   
    *   This API's parameters and response are identical to that of the
    *   |/register/email/requestToken|_ endpoint, except that
    *   ``M_THREEPID_NOT_FOUND`` may be returned if no account matching the
    *   given email address could be found. The server may instead send an
    *   email to the given address prompting the user to create an account.
    *   ``M_THREEPID_IN_USE`` may not be returned.
    *   
    *   The homeserver should validate the email itself, either by sending a
    *   validation email itself or by using a service it has control over.
    *   
    *   
    *   .. |/register/email/requestToken| replace:: ``/register/email/requestToken``
    *   
    *   .. _/register/email/requestToken: #post-matrix-client-r0-register-email-requesttoken
    */
    explicit RequestTokenToResetPasswordEmailJob(std::string serverUrl
    
      ,
        EmailValidationData body );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(EmailValidationData body);

        

        

      RequestTokenToResetPasswordEmailJob withData(JsonWrap j) &&;
      RequestTokenToResetPasswordEmailJob withData(JsonWrap j) const &;
      };
      using RequestTokenToResetPasswordEmailResponse = RequestTokenToResetPasswordEmailJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Requests a validation token be sent to the given phone number for the purpose of resetting a user's password.
 *
 * The homeserver must check that the given phone number **is
 * associated** with an account on this homeserver. This API should be
 * used to request validation tokens when authenticating for the
 * ``/account/password`` endpoint.
 * 
 * This API's parameters and response are identical to that of the
 * |/register/msisdn/requestToken|_ endpoint, except that
 * ``M_THREEPID_NOT_FOUND`` may be returned if no account matching the
 * given phone number could be found. The server may instead send the SMS
 * to the given phone number prompting the user to create an account.
 * ``M_THREEPID_IN_USE`` may not be returned.
 * 
 * The homeserver should validate the phone number itself, either by sending a
 * validation message itself or by using a service it has control over.
 * 
 * .. |/register/msisdn/requestToken| replace:: ``/register/msisdn/requestToken``
 * 
 * .. _/register/msisdn/requestToken: #post-matrix-client-r0-register-email-requesttoken
 */
class RequestTokenToResetPasswordMSISDNJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// An SMS message was sent to the given phone number.
    
    RequestTokenResponse data() const
    {
    return
      std::move(jsonBody().get()).get<RequestTokenResponse>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Requests a validation token be sent to the given phone number for the purpose of resetting a user's password.
 *
    * \param body
    *   The homeserver must check that the given phone number **is
    *   associated** with an account on this homeserver. This API should be
    *   used to request validation tokens when authenticating for the
    *   ``/account/password`` endpoint.
    *   
    *   This API's parameters and response are identical to that of the
    *   |/register/msisdn/requestToken|_ endpoint, except that
    *   ``M_THREEPID_NOT_FOUND`` may be returned if no account matching the
    *   given phone number could be found. The server may instead send the SMS
    *   to the given phone number prompting the user to create an account.
    *   ``M_THREEPID_IN_USE`` may not be returned.
    *   
    *   The homeserver should validate the phone number itself, either by sending a
    *   validation message itself or by using a service it has control over.
    *   
    *   .. |/register/msisdn/requestToken| replace:: ``/register/msisdn/requestToken``
    *   
    *   .. _/register/msisdn/requestToken: #post-matrix-client-r0-register-email-requesttoken
    */
    explicit RequestTokenToResetPasswordMSISDNJob(std::string serverUrl
    
      ,
        MsisdnValidationData body );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(MsisdnValidationData body);

        

        

      RequestTokenToResetPasswordMSISDNJob withData(JsonWrap j) &&;
      RequestTokenToResetPasswordMSISDNJob withData(JsonWrap j) const &;
      };
      using RequestTokenToResetPasswordMSISDNResponse = RequestTokenToResetPasswordMSISDNJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Deactivate a user's account.
 *
 * Deactivate the user's account, removing all ability for the user to
 * login again.
 * 
 * This API endpoint uses the `User-Interactive Authentication API`_.
 * 
 * An access token should be submitted to this endpoint if the client has
 * an active session.
 * 
 * The homeserver may change the flows available depending on whether a
 * valid access token is provided.
 * 
 * Unlike other endpoints, this endpoint does not take an ``id_access_token``
 * parameter because the homeserver is expected to sign the request to the
 * identity server instead.
 */
class DeactivateAccountJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// An indicator as to whether or not the homeserver was able to unbind
/// the user's 3PIDs from the identity server(s). ``success`` indicates
/// that all identifiers have been unbound from the identity server while
/// ``no-support`` indicates that one or more identifiers failed to unbind
/// due to the identity server refusing the request or the homeserver
/// being unable to determine an identity server to unbind from. This
/// must be ``success`` if the homeserver has no identifiers to unbind
/// for the user.
std::string idServerUnbindResult() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Deactivate a user's account.
 *
    * \param auth
    *   Additional authentication information for the user-interactive authentication API.
    * 
    * \param idServer
    *   The identity server to unbind all of the user's 3PIDs from.
    *   If not provided, the homeserver MUST use the ``id_server``
    *   that was originally use to bind each identifier. If the
    *   homeserver does not know which ``id_server`` that was,
    *   it must return an ``id_server_unbind_result`` of
    *   ``no-support``.
    */
    explicit DeactivateAccountJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<AuthenticationData> auth  = std::nullopt, std::optional<std::string> idServer  = std::nullopt);
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::optional<AuthenticationData> auth, std::optional<std::string> idServer);

        

        

      DeactivateAccountJob withData(JsonWrap j) &&;
      DeactivateAccountJob withData(JsonWrap j) const &;
      };
      using DeactivateAccountResponse = DeactivateAccountJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Checks to see if a username is available on the server.
 *
 * Checks to see if a username is available, and valid, for the server.
 * 
 * The server should check to ensure that, at the time of the request, the
 * username requested is available for use. This includes verifying that an
 * application service has not claimed the username and that the username
 * fits the server's desired requirements (for example, a server could dictate
 * that it does not permit usernames with underscores).
 * 
 * Matrix clients may wish to use this API prior to attempting registration,
 * however the clients must also be aware that using this API does not normally
 * reserve the username. This can mean that the username becomes unavailable
 * between checking its availability and attempting to register it.
 */
class CheckUsernameAvailabilityJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A flag to indicate that the username is available. This should always
/// be ``true`` when the server replies with 200 OK.
std::optional<bool> available() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Checks to see if a username is available on the server.
 *
    * \param username
    *   The username to check the availability of.
    */
    explicit CheckUsernameAvailabilityJob(std::string serverUrl
    
      ,
        std::string username );


    static BaseJob::Query buildQuery(
    std::string username);

      static BaseJob::Body buildBody(std::string username);

        

        

      CheckUsernameAvailabilityJob withData(JsonWrap j) &&;
      CheckUsernameAvailabilityJob withData(JsonWrap j) const &;
      };
      using CheckUsernameAvailabilityResponse = CheckUsernameAvailabilityJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
