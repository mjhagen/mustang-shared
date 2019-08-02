component extends=framework.one {
  if ( !structKeyExists( variables, 'framework' ) ) {
    variables.framework = {};
  }
  variables.mstng = new mustang.base( variables.framework );
  variables.cfg = variables.mstng.readConfig();
  variables.root = variables.mstng.getRoot();

  param request.domainName=cgi.server_name;
  param request.appName="Nameless-Mustang-App-#createUUID()#";
  param request.version="?";
  param request.context.startTime=getTickCount();
  param request.context.config=variables.cfg;
  param request.webroot=variables.cfg.webroot;
  param request.appSimpleName=listFirst( request.appName, " ,-_" );
  param request.context.debug=variables.cfg.showDebug && listFind( variables.cfg.debugIP, cgi.remote_addr );

  variables.mstng.cleanXHTMLQueryString();
  variables.live = variables.cfg.appIsLive;
  variables.routes = [];
  variables.mstng.mergeStructs(
    {
      'routesCaseSensitive' = false,
      'generateSES' = true,
      'SESOmitIndex' = true,
      'base' = '/#variables.cfg.root#',
      'baseURL' = variables.cfg.webroot,
      'error' = 'app.error',
      'unhandledPaths' = '/inc,/tests,/browser,/cfimage,/diagram',
      'diLocations' = [
        '/mustang/services',
        '/#variables.cfg.root#/services',
        '/#variables.cfg.root#/model/services',
        '/#variables.cfg.root#/subsystems/api/services'
      ],
      'diConfig' = { 'constants' = { 'root' = variables.root, 'config' = variables.cfg }, 'loadListener' = variables.mstng.loadListener },
      'environments' = {
        'live' = {
          'cacheFileExists' = true,
          'password' = variables.cfg.reloadpw,
          'trace' = variables.cfg.showDebug
        },
        'dev' = { 'trace' = variables.cfg.showDebug }
      },
      'subsystems' = { 'api' = { 'error' = 'api:main.error' } }
    },
    variables.framework
  );

  this.mappings[ '/#variables.cfg.root#' ] = request.root = variables.root;
  this.sessionManagement = true;
  this.sessionTimeout = createTimespan( 0, 2, 0, 0 );

  if ( len( variables.cfg.datasource ) ) {
    this.datasource = variables.cfg.datasource;

    if ( variables.cfg.useOrm ) {
      this.ormEnabled = true;
      this.ormSettings = {
        'cfcLocation' = variables.root & 'model',
        'dbCreate' = variables.mstng.getDbCreate( variables.cfg ),
        'sqlScript' = variables.cfg.nukescript,
        'secondaryCacheEnabled' = variables.live ? true : false,
        'cacheProvider' = 'ehcache',
        'cacheConfig' = 'ehcache-config_ORM_#request.appSimpleName#.xml'
      };
    }
  }

  if ( structKeyExists( variables.cfg.paths, 'basecfc' ) ) {
    this.mappings[ '/basecfc' ] = variables.cfg.paths.basecfc;
  }

  if ( structKeyExists( variables.cfg.paths, 'mustang' ) ) {
    this.mappings[ '/mustang' ] = variables.cfg.paths.mustang;
  }

  if ( !structKeyExists( variables.cfg.paths, variables.cfg.root ) ) {
    variables.cfg.paths[ variables.cfg.root ] = variables.root;
  }

  if ( len( variables.cfg.paths.fileUploads ) ) {
    request.fileUploads = variables.cfg.paths.fileUploads;
  }


  // fw1 flow control

  public void function setupApplication() {
    frameworkTrace( '<b>mustang</b>: setupApplication() called.' );

    var bf = getBeanFactory();

    var logService = bf.getBean( 'logService' );

    if ( structKeyExists( url, 'nuke' ) ) {
      // empty caches:
      structDelete( application, 'cache' );
      structDelete( application, 'threads' );
      cacheRemove( arrayToList( cacheGetAllIds() ) );
      logService.writeLogLevel( 'NUKE: Caches purged', request.appName );

      // rebuild ORM:
      if ( variables.cfg.useOrm ) {
        ormEvictQueries();

        var modelPath = this.ormSettings.CFCLocation;

        if ( left( modelPath, 1 ) == '/' ) {
          modelPath = expandPath( modelPath );
        }

        var hbmxmlFiles = directoryList( modelPath, true, 'path', '*.hbmxml' );
        for ( var filepath in hbmxmlFiles ) {
          fileDelete( filepath );
        }
        logService.writeLogLevel( 'NUKE: HBMXML files deleted', request.appName );

        ormReload();

        var hbmxmlFiles = directoryList( modelPath, true, 'path', '*.hbmxml' );

        if ( !arrayIsEmpty( hbmxmlFiles ) ) {
          if ( !directoryExists( variables.root & 'documentation' ) ) {
            directoryCreate( variables.root & 'documentation' );
          }

          if ( !directoryExists( variables.root & 'documentation/hbmxml' ) ) {
            directoryCreate( variables.root & 'documentation/hbmxml' );
          }

          for ( var filepath in hbmxmlFiles ) {
            var fileName = getFileFromPath( filepath );
            var destination = variables.root & 'documentation/hbmxml/' & fileName;
            fileMove( filepath, destination );
          }
        }

        logService.writeLogLevel( 'NUKE: ORM reloaded', request.appName );
      }
    }

    logService.writeLogLevel( 'Application initialized', request.appName, 'information' );
  }

  public void function setupSession() {
    frameworkTrace( '<b>mustang</b>: setupSession() called.' );
    structDelete( session, 'progress' );
    session.connectionStorage = {};
  }

  public void function setupSubsystem( string subsystem = '' ) {
    frameworkTrace( '<b>mustang</b>: setupSubsystem() called.' );

    if ( structKeyExists( variables.framework.subsystems, subsystem ) ) {
      var subsystemConfig = getSubsystemConfig( subsystem );
      variables.mstng.mergeStructs( subsystemConfig, variables.framework );
      structDelete( variables.framework.subsystems, subsystem );
    }
  }

  public void function setupRequest() {
    frameworkTrace( '<b>mustang</b>: setupRequest() called.' );

    if ( structKeyExists( url, 'clear' ) ) {
      variables.mstng.clearCache();
      frameworkTrace( '<b>mustang</b>: cache reset' );
    }

    request.reset = isFrameworkReloadRequest();

    if ( request.reset ) {
      setupSession();
    }

    var bf = getBeanFactory();
    var i18n = bf.getBean( 'translationService' );
    var util = bf.getBean( 'utilityService' );

    request.context.util = variables.util = util;
    request.context.i18n = variables.i18n = i18n;

    util.setCFSetting( 'showdebugoutput', request.context.debug );
    util.limiter();

    // security:
    controller( ':security.authorize' );

    // internationalization:
    controller( ':i18n.load' );

    // content:
    if ( getSubsystem() == getDefaultSubsystem() || listFindNoCase( variables.cfg.contentSubsystems, getSubsystem() ) ) {
      controller( ':admin-ui.load' );
    }

    // try to queue up crud (admin) actions:
    if ( getSubsystem() == getDefaultSubsystem() && !util.fileExistsUsingCache( variables.root & '/controllers/#getSection()#.cfc' ) ) {
      controller( ':crud.#getItem()#' );
    }

    // try to queue up api actions:
    if ( getSubsystem() == 'api' && !util.fileExistsUsingCache( variables.root & '/subsystems/api/controllers/#getSection()#.cfc' ) ) {
      controller( 'api:main.#getItem()#' );
    }
  }


  // fw1 helper functions

  public array function getRoutes() {
    var resources = cacheGet( 'resources_#this.name#' );

    if ( isNull( resources ) || !variables.cfg.appIsLive ) {
      var listOfResources = '';
      var modelFiles = directoryList( this.mappings[ '/#request.context.config.root#' ] & '/model', true, 'name', '*.cfc', 'name asc' );

      for ( var fileName in modelFiles ) {
        listOfResources = listAppend( listOfResources, reverse( listRest( reverse( fileName ), '.' ) ) );
      }

      var resources = variables.routes;

      resources.addAll( [
        { '^/api/auth/:item' = '/api:auth/:item/' },
        { '^/api/$' = '/api:main/notfound' },
        { '$RESOURCES' = { resources = listOfResources, subsystem = 'api' } }
      ] );

      cachePut( 'resources_#this.name#', resources );
    }

    return resources;
  }

  public string function getEnvironment() {
    return variables.live ? 'live' : 'dev';
  }


  // cf flow control

  public void function onError( any exception, string event ) {
    var args = arguments;
    args.config = variables.cfg;
    variables.mstng.handleExceptions( argumentCollection = args );
  }

  public string function onMissingView( struct rc ) {
    if ( util.fileExistsUsingCache( variables.root & '/views/' & getSection() & '/' & getItem() & '.cfm' ) ) {
      return view( getSection() & '/' & getItem() );
    }

    if ( util.fileExistsUsingCache(
      variables.root & '/subsystems/' & getSubsystem() & '/views/' & getSection() & '/' & getItem() & '.cfm'
    ) ) {
      return view( getSubsystem() & ':' & getSection() & '/' & getItem() );
    }

    if ( structKeyExists( request.context, 'fallbackView' ) ) {
      return view( request.context.fallbackView );
    }

    return view( ':app/notfound' );
  }
}