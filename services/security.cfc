component accessors=true {
  property config;
  property dataService;
  property logService;
  property utilityService;

  public struct function getAuth( ) {
    var result = getEmptyAuth( );

    if ( !isNull( session.auth ) ) {
      var result = session.auth;
    }

    return result;
  }

  public boolean function authIsValid( required struct checkAuth ) {
    var requiredKeys = [ 'isLoggedIn', 'user', 'userid', 'role' ];

    for ( var key in requiredKeys ) {
      if ( !structKeyExists( checkAuth, key ) ) {
        return false;
      }
    }

    if ( !len( trim( checkAuth.userid ) ) ||
         !isStruct( checkAuth.user ) ||
         !isStruct( checkAuth.role ) ||
         !isBoolean( checkAuth.isLoggedIn ) ) {
      return false;
    }

    return true;
  }

  public void function createSession( ) {
    logService.writeLogLevel( "createSession() called", "securityService", "debug" );

    var tmpSession = {
      "can" = { },
      "auth" = getEmptyAuth( )
    };

    structClear( session );

    structAppend( session, tmpSession );
  }

  public void function endSession() {
    structDelete( session, 'auth' );
    structDelete( session, 'can' );
    sessionRotate();
  }

  public void function refreshFakeSession( ) {
    createSession( );

    var tempAuth = {
      "isLoggedIn" = true,
      "role" = getFakeRole( ),
      "user" = dataService.processEntity( getFakeUser( ) ),
      "userid" = createUUID( )
    };

    structAppend( session.auth, tempAuth, true );
  }

  public void function refreshSession( component user ) {
    if ( isNull( user ) ) {
      var currentAuth = getAuth();

      if ( utilityService.isGuid( currentAuth.userId ) ) {
        user = entityLoadByPK( 'contact', currentAuth.userId );
      }
    } else {
      entityReload( user );
    }

    createSession();

    var tempAuth = {
      'isLoggedIn' = true,
      'user' = dataService.processEntity( user, 0, 1, false ),
      'userid' = user.getID(),
      'role' = {}
    };

    if ( structKeyExists( user, 'getSecurityRole' ) ) {
      var securityRole = user.getSecurityRole();

      if ( isNull( securityRole ) ) {
        throw( 'No security role for this user, or no security role name set.', 'securityService.refreshSession' );
      }

      tempAuth[ 'role' ] = dataService.processEntity( securityRole, 0, 1, false );

      if ( isAdmin( tempAuth.role.name ) ) {
        tempAuth.role[ 'can' ] = yesWeCan;
      } else {
        cachePermissions( tempAuth.role.permissions );
        tempAuth.role[ 'can' ] = this.can;
      }

      // forwards compatibility (move can to main struct, since from now on we support more than one role):
      tempAuth[ 'can' ] = tempAuth.role.can;
      tempAuth[ 'menulist' ] = tempAuth.role.menulist;
    } else if ( structKeyExists( user, 'getSecurityRoles' ) ) {
      tempAuth[ 'canAccessAdmin' ] = false;
      tempAuth[ 'can' ] = this.can;
      tempAuth[ 'menulist' ] = [];

      entityLoad( 'securityrole' ).each( function( securityrole ) {
        tempAuth[ 'is#securityrole.getName()#' ] = false;
      } );

      tempAuth[ 'roles' ] = user.getSecurityRoles().map( function( assignment ) {
        var securityrole = assignment.getSecurityRole();
        var assignmentStruct = dataService.processEntity( securityrole, 0, 2, false );

        param assignmentStruct.canAccessAdmin = false;

        tempAuth[ 'is#securityrole.getName()#' ] = true;

        if ( assignmentStruct.canAccessAdmin ) {
          tempAuth[ 'canAccessAdmin' ] = true;
        }

        // merge and de-duplicate menuitems
        tempAuth.menulist = tempAuth.menulist.merge( assignmentStruct.menulist.listToArray() ).filter(
          function( value, index, self ) {
            return self.find( value ) == index;
          }
        );

        assignmentStruct[ 'permissions' ] = assignmentStruct.permissions.map( function( permission ) {
          return permission.permission;
        } );

        assignmentStruct.delete( 'contact' );
        assignmentStruct.delete( 'securityroles' );

        return assignmentStruct;
      } );

      tempAuth.menulist = tempAuth.menulist.toList();

      cacheMultiRolePermissions( tempAuth.roles );
    }

    structAppend( session.auth, tempAuth, true );
    sessionRotate();
  }

  public string function hashPassword( required string password ) {
    var minSpeed = 100;
    var cost = 4;
    var bcrypt = getBCrypt();
    do {
      var salt = bcrypt.gensalt( cost );
      var hashedPW = bcrypt.hashpw( password, salt );
      var start = getTickCount( );
      bcrypt.checkpw( password, hashedPW );
      var hashSpeed = getTickCount( ) - start;
      logService.writeLogLevel( "Password hash speed #hashSpeed#ms at #cost#.", "securityService", "debug" );
      cost++;
    } while ( hashSpeed < minSpeed && cost <= 30 );
    return hashedPW;
  }

  public boolean function comparePassword( required string password, required string storedPW ) {
    try {
      // FIRST TRY BCRYPT:
      var bcrypt = getBCrypt();
      return bcrypt.checkpw( password, storedPW );
    } catch ( any e ) {
      try {
        // THEN TRY THE OLD SHA-512 WAY:
        var storedsalt = right( storedPW, 16 );
        return 0 == compare( storedPW, hash( password & storedsalt, 'SHA-512' ) & storedsalt );
      } catch ( any e ) {
        return false;
      }
    }
  }

  public boolean function isAdmin( string roleName ) {
    if ( isNull( roleName ) ) {
      var currentAuth = getAuth( );
      roleName = currentAuth.role.name;
    }

    return roleName == "Administrator" || roleName == "Admin";
  }

  public boolean function yesWeCan( ) {
    return true;
  }

  public boolean function can( string action = '', string section = '' ) {
    if ( !session.keyExists( 'auth' ) ) {
      // not logged in
      return false;
    }

    param session.can = {};
    param session.auth.canAccessAdmin = false;
    param session.auth.role.canAccessAdmin = false;

    if ( !isBoolean( session.auth.canAccessAdmin ) ) session.auth.canAccessAdmin = false;
    if ( !isBoolean( session.auth.role.canAccessAdmin ) ) session.auth.role.canAccessAdmin = false;

    return structKeyExists( session.can, '#action#-#section#' ) || session.auth.canAccessAdmin || session.auth.role.canAccessAdmin;
  }

  public boolean function canIgnoreSecurity( string subsystem="",
                                             string section="",
                                             string fqa="",
                                             string defaultSubsystem="" ) {
    logService.writeLogLevel( text = fqa, level = 'information' );

    if ( isArray( variables.config.dontSecureFQA ) && variables.config.dontSecureFQA.findNoCase( fqa ) ) return true;
    if ( isSimpleValue( variables.config.dontSecureFQA ) && variables.config.dontSecureFQA.listfindNoCase( fqa ) ) return true;

    if ( subsystem == "adminapi" && section == "css" ) {
      return true;
    }

    if ( subsystem == "api" && section == "auth" ) {
      return true;
    }

    var inDefaultSubsystem = subsystem == defaultSubsystem;

    if ( inDefaultSubsystem && section == "security" ) {
      return true;
    }

    if ( inDefaultSubsystem && !variables.config.secureDefaultSubsystem ) {
      return true;
    }

    if ( !inDefaultSubsystem && !listFindNoCase( variables.config.securedSubsystems, subsystem ) ) {
      return true;
    }

    return false;
  }

  // private

  private void function cacheMultiRolePermissions( required array securityRoleAssignments ) {
    var actions = [
      'view',
      'change',
      'delete',
      'execute',
      'create'
    ];
    var cachedPermissions = {};

    securityRoleAssignments.each( function( assignment ) {
      param assignment.permissions = [];
      assignment.permissions.each( function( permission ) {
        actions.each( function( action ) {
          if ( permission.keyExists( action ) && isBoolean( permission[ action ] ) && permission[ action ] ) {
            cachedPermissions[ '#action#-#permission.section#' ] = true;
          }
        } );
      } );
    } );

    session.can = cachedPermissions;
  }

  private void function cachePermissions( required array allPermissions ) {
    var cachedPermissions = { };

    for ( var permission in allPermissions ) {
      if ( !structKeyExists( permission, "section" ) || !len( trim( permission.section ) ) ) {
        continue;
      }

      for ( var action in [ "view", "change", "delete", "execute", "create" ] ) {
        if ( structKeyExists( permission, action ) &&
                   isBoolean( permission[ action ] ) &&
                              permission[ action ] ) {
          cachedPermissions[ "#action#-#permission.section#" ] = '';
        }
      }
    }

    session.can = cachedPermissions;
  }

  private struct function getFakeUser( ) {
    return {
      "name" = "Administrator",
      "firstname" = "John",
      "lastname" = "Doe"
    };
  }

  private struct function getFakeRole( ) {
    return {
      "name" = "Administrator",
      "menuList" = "",
      "can" = yesWeCan
    };
  }

  private any function getBCrypt() {
    return createObject( 'java', 'org.mindrot.jbcrypt.BCrypt' );
  }

  private struct function getEmptyAuth( ) {
    return {
      "isLoggedIn" = false,
      "user" = { },
      "role" = { "name" = "none" },
      "userid" = ''
    };
  }
}
