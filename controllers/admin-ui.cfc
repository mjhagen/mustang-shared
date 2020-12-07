component accessors=true {
  property config;
  property framework;
  property contentService;
  property localeService;
  property translationService;
  property securityService;

  public void function load( rc ) {
    var noContentItems = ['doLogout','doLogin'];

    if ( noContentItems.findNoCase( framework.getItem() ) ) return;

    if ( !structKeyExists( rc, 'content' ) || isNull( rc.content ) ) {
      var locale = variables.localeService.get( variables.translationService.getLocaleID( ) );

      if ( isNull( locale ) ) {
        throw( "Application data not initialized", "admin-uiController.load.initError" );
      }

      rc.content = variables.contentService.getByFQA( variables.framework.getfullyqualifiedaction( ), locale );
    }

    rc.displaytitle = variables.translationService.translate( variables.framework.getfullyqualifiedaction( ) );

    if ( !structKeyExists( rc, "topnav" ) ) {
      rc.topnav = "";
    }

    rc.subnavHideHome = false;

    if ( variables.framework.getSubsystem() == variables.framework.getDefaultSubsystem() || listFindNoCase( config.contentSubsystems, variables.framework.getSubsystem() ) ) {
      var reload = true;

      lock scope="session" timeout="5" type="readonly" {
        if ( structKeyExists( session, "subnav" ) ) {
          rc.subnav = session.subnav;
          reload = false;
        }
      }

      if ( !config.appIsLive || request.reset ) {
        reload = true;
      }

      if ( reload ) {
        rc.subnav = "";

        if ( rc.auth.isLoggedIn && !isNull( rc.auth.menulist ) ) {
          var roleSubnav = rc.auth.menulist;
        }

        if ( isNull( roleSubnav ) ) {
          var roleSubnav = "";
        }

        if ( len( trim( roleSubnav ) ) ) {
          for ( var navItem in listToArray( roleSubnav ) ) {
            if ( navItem == "-" || variables.securityService.can( "view", navItem ) ) {
              rc.subnav = listAppend( rc.subnav, navItem );
            }
          }
        } else {
          var hiddenMenuitems = "base";
          var subnav = [ ];
          var tempSortOrder = 9001;

          for ( var entityPath in directoryList( request.root & '/model', false, 'name', '*.cfc' ) ) {
            var entityName = reverse( listRest( reverse( getFileFromPath( entityPath ) ), "." ) );
            var sortOrder = tempSortOrder++;
            var entity = getMetaData( createObject( "#config.root#.model." & entityName ) );

            if ( structKeyExists( entity, "hide" ) ||
                listFindNoCase( hiddenMenuitems, entityName ) ||
                ( rc.auth.isLoggedIn && !variables.securityService.can( "view", entityName ) ) ) {
              continue;
            }

            if ( structKeyExists( entity, "sortOrder" ) ) {
              sortOrder = entity[ "sortOrder" ];
            }

            subnav[ sortOrder ] = entityName;
          }

          for ( var menuItem in subnav ) {
            if ( !isNull( menuItem ) && len( trim( menuItem ) ) ) {
              rc.subnav = listAppend( rc.subnav, menuItem );
            }
          }
        }
      }

      lock scope="session" timeout="5" type="exclusive" {
        session.subnav = rc.subnav;
      }
    }
  }
}
