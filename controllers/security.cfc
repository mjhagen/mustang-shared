component accessors=true {
  property framework;
  property config;

  property contactService;
  property contentService;
  property dataService;
  property emailService;
  property optionService;
  property securityService;
  property logService;
  property utilityService;

  public void function before( required struct rc ) {
  }

  public void function login( required struct rc ) {
    framework.setLayout( 'security' );

    sessionInvalidate();

    param rc.username="";
    param rc.password="";
  }

  public void function doLogin( required struct rc ) {
    param rc.username="";
    param rc.password="";
    param rc.authhash="";

    var updateUserWith = { 'lastLoginDate' = now() };
    // Check credentials:
    if ( structKeyExists( rc, 'authhash' ) && len( trim( rc.authhash ) ) ) {
      logService.writeLogLevel( 'trying authhash', request.appName );

      var decryptedHash = decrypt(
            utilityService.base64URLDecode( rc.authhash ),
            config.encryptKey
          );
      if ( isJSON( decryptedHash ) ) {
        var hashStruct = deserializeJSON( decryptedHash );
        if ( isStruct( hashStruct ) && structKeyExists( hashStruct, 'path' ) ) {
          var cgi_path = cgi.path_info;
          if ( right( cgi.path_info, 1 ) eq '/' ) {
            cgi_path = left( cgi_path, len( cgi_path ) - 1 );
          }

          if ( !findNoCase( cgi_path, hashStruct.path ) ) {
            rc.alert = { 'class' = 'danger', 'text' = 'user-not-found' };
            logService.writeLogLevel( text = 'authhash path failure', type = 'warning', file = request.appName );
            doLogout( rc );
          }
          var contactID = hashStruct.userId;
        }
      } else {
        var contactID = decrypt( utilityService.base64URLDecode( rc.authhash ), config.encryptKey );
      }
      var user = contactService.get( contactID );

      if ( isNull( user ) ) {
        rc.alert = { 'class' = 'danger', 'text' = 'user-not-found' };
        logService.writeLogLevel( text = 'authhash failed', type = 'warning', file = request.appName );
        doLogout( rc );
      }

      param rc.dontRedirect = true;

      logService.writeLogLevel( text = 'authhash success', type = 'information', file = request.appName );
    } else {
      // CHECK USERNAME:
      var user = contactService.getByUsername( rc.username );

      if ( isNull( user ) ) {
        rc.alert = { 'class' = 'danger', 'text' = 'user-not-found' };
        logService.writeLogLevel(
          text = 'login failed: wrong username (#rc.username#)',
          type = 'warning',
          file = request.appName
        );
        doLogout( rc );
      }

      // CHECK PASSWORD:
      var decryptSpeed = getTickCount();
      var passwordIsCorrect = securityService.comparePassword( password = rc.password, storedPW = user.getPassword() );
      decryptSpeed = getTickCount() - decryptSpeed;

      if ( !passwordIsCorrect ) {
        rc.alert = { 'class' = 'danger', 'text' = 'password-incorrect' };
        logService.writeLogLevel(
          text = 'user #user.getUsername()# login failed: wrong password ',
          type = 'warning',
          file = request.appName
        );
        doLogout( rc );
      }

      if ( decryptSpeed < 250 || decryptSpeed > 1000 ) {
        // re-encrypt if decryption is too slow, or too fast:
        updateUserWith.password = securityService.hashPassword( rc.password );
      }
    }

    // Set auth struct:
    securityService.refreshSession( user );

    updateUserWith[ 'contactID' ] = user.getID();

    if ( config.log ) {
      var securityLogaction = optionService.getOptionByName( 'logaction', 'security' );
      updateUserWith[ 'add_logEntry' ] = {
        'relatedEntity' = user.getId(),
        'by' = user.getId(),
        'dd' = now(),
        'ip' = cgi.remote_addr,
        'logaction' = securityLogaction.getId(),
        'note' = 'Logged in'
      };
    }

    var originalLogSetting = config.log;

    request.context.config.log = false;

    transaction {
      user.save( updateUserWith );
    }

    request.context.config.log = originalLogSetting;

    logService.writeLogLevel( text = 'user #user.getUsername()# logged in.', type = 'information', file = request.appName );

    rc.auth = securityService.getAuth();

    param rc.dontRedirect = false;

    if ( !rc.dontRedirect ) {
      var loginscript = '';

      if ( !isNull( rc.auth.role.loginscript ) ) {
        loginscript = rc.auth.role.loginscript;
      }

      if ( structKeyExists( rc, 'returnpage' ) ) {
        loginscript = rc.returnpage;
      } else if ( isNull( loginscript ) || !len( trim( loginscript ) ) ) {
        loginscript = ':';
      }

      framework.redirect( loginscript );
    }
  }

  public void function doLogout( required struct rc ) {
    // reset session
    securityService.endSession();

    var logMessage = 'user logged out.';

    if ( config.log && isDefined( 'rc.auth.userid' ) && dataService.isGUID( rc.auth.userid ) ) {
      var user = contactService.get( rc.auth.userid );

      if ( !isNull( user ) ) {
        logMessage = user.getUsername() & ' logged out.';

        var updateUserLog = {
          'contactID' = user.getID(),
          'add_logEntry' = {
            'relatedEntity' = user.getId(),
            'by' = user.getId(),
            'dd' = now(),
            'ip' = cgi.remote_addr,
            'logaction' = optionService.getOptionByName( 'logaction', 'security' ),
            'note' = logMessage
          }
        };

        var originalLogSetting = config.log;
        request.context.config.log = false;

        user.save( updateUserLog );

        request.context.config.log = originalLogSetting;
      }
    }

    logService.writeLogLevel( logMessage );

    if ( framework.getSubsystem() == 'api' || listFirst( cgi.PATH_INFO, '/' ) == 'api' ) {
      cfcontent( reset = true );
      var statusCode = rc.alert.class == 'danger' ? 401 : 200;
      framework.renderData()
        .type( 'json' )
        .data( rc.alert )
        .statusCode( statusCode );
      framework.abortController();
    }

    if ( isDefined( 'rc.auth.isLoggedIn' ) && isBoolean( rc.auth.isLoggedIn ) && rc.auth.isLoggedIn && !structKeyExists( rc, 'alert' ) ) {
      rc.alert = { 'class' = 'success', 'text' = 'logout-success' };
    }

    framework.redirect( ':security.login', 'alert' );
    framework.abortController();
  }

  public void function authorize( required struct rc ) {
    if( structKeyExists( rc, 'authhash' ) ) doLogin( rc );

    // Use auth struct that's stored in session
    rc.auth = securityService.getAuth();

    if ( config.disableSecurity ) {
      securityService.refreshFakeSession();
      rc.auth = securityService.getAuth();
      return;
    }

    // Always allow access to security && api:css
    var args = {
      'subsystem' = framework.getSubsystem(),
      'section' = framework.getSection(),
      'fqa' = framework.getFullyQualifiedAction(),
      'defaultSubsystem' = framework.getDefaultSubsystem()
    };

    if ( securityService.canIgnoreSecurity( argumentCollection = args ) ) {
      return;
    }

    // check validity of auth struct
    if ( !structKeyExists( rc, 'auth' ) ) {
      rc.alert = { 'class' = 'danger', 'text' = 'no-auth-in-session' };
      rc.auth.isLoggedIn = false;
    } else if ( structKeyExists( rc, 'authhash' ) || !structKeyExists( rc.auth, 'isLoggedIn' ) || !isBoolean( rc.auth.isLoggedIn ) ) {
      rc.auth.isLoggedIn = false;
    }

    // we're not logged in, try a few options:
    if ( !rc.auth.isLoggedIn ) {
      if ( ( framework.getSubsystem() == 'api' || listFirst( cgi.PATH_INFO, '/' ) == 'api' ) && !structKeyExists(
        rc,
        'authhash'
      ) ) {
        // API basic auth login:
        var HTTPRequestData = getHTTPRequestData();

        if ( isDefined( 'HTTPRequestData.headers.authorization' ) ) {
          logService.writeLogLevel( text = 'trying API basic auth', type = 'information', file = request.appName );
          var basicAuth = toString( toBinary( listLast( HTTPRequestData.headers.authorization, ' ' ) ) );

          rc.username = listFirst( basicAuth, ':' );
          rc.password = listRest( basicAuth, ':' );
          rc.dontRedirect = true;
        } else {
          var isLucee = listFindNoCase( 'lucee,railo', server.ColdFusion.ProductName );
          var pageContext = getPageContext();
          var response = isLucee ? pageContext.getResponse() : pageContext.getFusionContext().getResponse();
          response.setHeader( 'WWW-Authenticate', 'Basic realm="#request.appName#-API"' );

          framework.renderData( 'rawjson', '{"status":"error","detail":"Unauthorized"}', 401 );
          framework.abortController();
        }
      }

      // Try authhash, or regular username/password if available (via basic auth for instance)
      if ( structKeyExists( rc, 'authhash' ) || ( structKeyExists( rc, 'username' ) && structKeyExists( rc, 'password' ) ) ) {
        doLogin( rc );
      } else {
        // nope, still not logged in: reset session via logout method.
        logService.writeLogLevel( text = 'User not logged in, reset session', type = 'information', file = request.appName );
        rc.alert = { 'class' = 'danger', 'text' = 'user-not-logged-in' };
        doLogout( rc );
      }
    }

    if ( framework.isFrameworkReloadRequest() && rc.auth.isLoggedIn ) {
      var user = contactService.get( rc.auth.userid );
      securityService.refreshSession( user );
    }
  }

  public void function doRetrieve( required struct rc ) {
    param rc.returnToSection='security';
    param rc.passwordResetFQA=':#rc.returnToSection#.password';
    param rc.emailTemplate='';

    if ( structKeyExists( rc, 'email' ) && len( trim( rc.email ) ) ) {
      var contact = contactService.getByEmail( rc.email );

      if ( !isNull( contact ) ) {
        var authhash = toBase64( encrypt( contact.getID(), config.encryptKey ) );
        var activationEmails = contentService.getByFQA( 'mail.activation' );

        if ( isObject( activationEmails ) ) {
          var emailText = activationEmails;
        } else if ( ( isArray( activationEmails ) && !arrayIsEmpty( activationEmails ) ) ) {
          var emailText = activationEmails[ 1 ];
        }

        if ( isNull( emailText ) || isNull( emailText.getFullyqualifiedaction() ) ) {
          var logMessage = 'missing activation email text, add text with fqa: ''mail.activation''';
          logService.writeLogLevel( text = logMessage, type = 'warning', file = request.appName );
          throw( logMessage );
        }

        var emailBody = utilityService.parseStringVariables(
          emailText.getBody(),
          {
            'link' = framework.buildURL( action = rc.passwordResetFQA, queryString = { 'authhash' = authhash } ),
            'firstname' = contact.getFirstname(),
            'fullname' = contact.getFullname()
          }
        );

        if ( len( trim( rc.emailTemplate ) ) ) {
          var emailBody = utilityService.parseStringVariables(
            framework.layout( 'mail', framework.view( rc.emailTemplate ) ),
            { 'firstname' = contact.getFirstname(), 'body' = emailBody }
          );
        }

        emailService.send( from = config.ownerEmail, to = contact, subject = emailText.getTitle(), body = emailBody );

        rc.alert = { 'class' = 'success', 'text' = 'email-sent' };
        logService.writeLogLevel( text = 'retrieve password email sent', type = 'information', file = request.appName );
        framework.redirect( ':#rc.returnToSection#.login', 'alert' );
      } else {
        rc.alert = { 'class' = 'danger', 'text' = 'email-not-found' };
        logService.writeLogLevel( text = 'retrieve password email not found', type = 'warning', file = request.appName );
        framework.redirect( ':#rc.returnToSection#.retrieve', 'alert' );
      }
    }
  }
}