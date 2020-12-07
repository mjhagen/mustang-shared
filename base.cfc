component {
  public component function init( fw1Config ) {
    variables.basePath = getDirectoryFromPath( getBaseTemplatePath( ) );
    variables.root = getRoot( );
    variables.name = hash( variables.basePath & cgi.server_name );
    variables.framework = fw1Config;

    return this;
  }

  public struct function readConfig( string site = cgi.server_name, string configRoot = variables.root ) {
    if ( !structKeyExists( url, 'reload' ) ) {
      lock name="lock_mustang_#variables.name#_config_read" timeout="3" type="readonly" {
        var cachedConfig = cacheGet( 'config_#variables.name#' );

        if ( !isNull( cachedConfig ) ) {
          param cachedConfig.appIsLive=true;

          if ( cachedConfig.appIsLive ) {
            return cachedConfig;
          }
        }
      }
    }

    var result = { 'webroot' = getDefaultWebroot() };
    var mustangSharedRoot = getMustangRoot();

    var globalConfig = deserializeJSON( fileRead( mustangSharedRoot & '/config/global.json', 'utf-8' ) );
    mergeStructs( globalConfig, result );
    if ( fileExists( configRoot & '/config/default.json' ) ) {
      var defaultConfig = deserializeJSON( fileRead( configRoot & '/config/default.json', 'utf-8' ) );
      mergeStructs( defaultConfig, result );
    }

    site = site.replaceNoCase( 'www.', '' );

    if ( fileExists( configRoot & '/config/' & site & '.json' ) ) {
      var siteConfig = deserializeJSON( fileRead( configRoot & '/config/' & site & '.json', 'utf-8' ) );

      if ( siteConfig.keyExists( 'include' ) ) {
        var includeConfig = deserializeJSON( fileRead( configRoot & '/config/#siteConfig.include#', 'utf-8' ) );
        mergeStructs( includeConfig, result );
      }

      mergeStructs( siteConfig, result );
    }

    var machineName = getMachineName();

    if ( fileExists( configRoot & '/config/#machineName.lCase()#.json' ) ) {
      var machineConfig = deserializeJSON( fileRead( configRoot & '/config/#machineName#.json', 'utf-8' ) );
      mergeStructs( machineConfig, result );
    }

    var useCommandbox = false;

    if ( fileExists( configRoot & '/config/commandbox.json' ) ) {
      if ( server.keyExists( 'system' ) ) {
        param server.system.properties={};
        if ( server.system.properties.keyExists( 'sun.java.command' ) &&
             server.system.properties[ 'sun.java.command' ] contains '.CommandBox' ) {
          useCommandbox = true;
        }
      }

      if ( !useCommandbox ) {
        try {
          createObject("java", "runwar.options.ServerOptions");
          useCommandbox = true;
        } catch ( any e ) {}
      }

      if ( useCommandbox ) {
        var commandboxConfig = deserializeJSON( fileRead( configRoot & '/config/commandbox.json', 'utf-8' ) );
        mergeStructs( commandboxConfig, result );
      }
    }

    lock name="lock_mustang_#variables.name#_config_write" timeout="3" type="exclusive" {
      cachePut( 'config_#variables.name#', result );
    }

    return result;
  }

  public void function mergeStructs( required struct from, struct to = { } ) {
    from.each(function(key, value){
      if ( isStruct( value ) && to.keyExists( key ) && isStruct( to[ key ] ) ) {
        mergeStructs( value, to[ key ] );
      } else {
        to[ key ] = value;
      }
    });
  }

  public void function addToConstants( required struct websiteSpecificConstants ) {
    mergeStructs( websiteSpecificConstants, variables.framework.diConfig.constants );
  }

  public string function getRoot( string basePath = variables.basePath ) {
    var tmp = fixPath( basePath );
    return tmp.listDeleteAt( tmp.listLen( "/" ), "/" ) & "/";
  }

  public string function getMustangRoot( ) {
    return getDirectoryFromPath( getCurrentTemplatePath( ) );
  }

  public void function cleanXHTMLQueryString( ) {
    for ( var kv in url ) {
      if ( kv contains ";" ) {
        url[ kv.listRest( ";" ) ] = url[ kv ];
        url.delete( kv );
      }
    };
  }

  public string function fixPath( string originalPath ) {
    var output = originalPath.listChangeDelims( '/', '\/' );

    if ( !server.os.name contains "Windows" && originalPath.left( 1 ) == "/" ) {
      output = "/" & output;
    }

    return output;
  }

  public string function getDbCreate( required struct config ) {
    if ( !url.keyExists( "reload" ) || !url.keyExists( "nuke" ) ) {
      return "none";
    }

    if ( compare( url.reload, config.reloadpw ) != 0 ) {
      return "none";
    }

    return "update";
  }

  public void function loadListener( bf ) {
    // ACF / Lucee compatibility services:
    if ( !server.keyExists( "lucee" ) ) {
      bf.declareBean( "threadfix", "mustang.compatibility.acf.threadfix" );
    }
  }

  public void function handleExceptions( required struct config, any exception, string event ) {
    exception = duplicate( exception );

    if ( exception.keyExists( "Cause" ) ) {
      exception = duplicate( exception.cause );
    }

    param exception.message="Uncaught Error";
    param exception.errorCode=500;
    param exception.detail="";

    var errorCode = duplicate( exception.errorCode );

    if ( !isNumeric( errorCode ) ) {
      exception.message &= ' (code: #errorCode#)';
      errorCode = 500;
    }

    var pc = getPageContext( );

    if ( server.keyExists( "lucee" ) ) {
      try {
        cfcontent( reset = true );
        cfheader( statusCode = errorCode, statusText = exception.message );
      } catch ( any e ) {}
    } else {
      pc.getCfoutput( ).clearAll( );
      pc.getResponse( )
        .getResponse( )
        .setStatus( errorCode, exception.message );
    }

    var showDebugError = config.debugIP.listFind( cgi.remote_addr );

    if ( cgi.path_info contains "/api/" || cgi.path_info contains "/adminapi/" || showDebugError || config.showDebug ) {
      if ( server.keyExists( "lucee" ) ) {
        try {
          cfcontent( type = "text/plain" );
        } catch ( any e ) {}
      } else {
        pc.getResponse( )
          .setContentType( "text/plain" );
      }

      writeOutput( "Error: " & exception.message );
      writeOutput( chr( 13 ) & chr( 10 ) & "Detail: " & exception.detail );

      if ( showDebugError ) {
        writeOutput( chr( 13 ) & chr( 10 ) & "Stacktrace: " & exception.stackTrace );
      }

      abort;
    }

    if ( !showDebugError && config.keyExists( 'rollbar' ) ) {
      runAsync( function() {
        try {
          request.rollbarUserInfo = isNull( request.context.auth.user ) ? {} : {
              'id' = request.context.auth.user.id
            , 'username' = request.context.auth.user.username
            , 'email' = request.context.auth.user.email
            , 'extra' = 'test'
          };
          config.rollbar.environment = cgi.SERVER_NAME;
          var rollbar = new mustang.lib.rollbar.Rollbar( config.rollbar );
          rollbar.reportMessage( exception.message, "critical", exception, request.rollbarUserInfo );
        } catch ( any e ) {
          writeLog( 'Failed to send error to Rollbar: #e.message# (#e.detail#).', 'fatal' );
        }
      } );
    } else {
      var errorDump = "";
      savecontent variable="errorDump" {
        writeOutput( "Error: " & exception.message );
        writeOutput( "<br />Detail: " & exception.detail );
        writeOutput( "<br />Stacktrace: <pre>" & exception.stackTrace & "</pre>" );
        writeDump( cgi );
      }
      fileWrite( config.paths.errors & "/uncaught-error-#createUUID()#.html", errorDump, "utf-8" );
    }

    var webroots = [ 'webroot', 'www' ];
    var fallbackErrorFile = 'error.html';

    for ( webroot in webroots ) {
      if ( fileExists( variables.root & "/#webroot#/error-#errorCode#.html" ) ) {
        include "/#config.root#/#webroot#/error-#errorCode#.html";
        writeOutput( '<!-- Message: #exception.message# | Detail: #exception.detail# -->' );
        abort;
      } else if ( fileExists( variables.root & "/#webroot#/#fallbackErrorFile#" ) ) {
        include "/#config.root#/#webroot#/#fallbackErrorFile#";
        writeOutput( '<!-- Message: #exception.message# | Detail: #exception.detail# -->' );
        abort;
      }
    }
  }

  public void function clearCache() {
    // clear query cache:
    createObject( 'java', 'coldfusion.server.ServiceFactory' ).getDataSourceService().purgeQueryCache();

    // clear ehcache:
    var allCacheIds = cacheGetAllIds();
    if ( !allCacheIds.isEmpty() ) {
      cacheRemove( allCacheIds.toList() );
    }
  }

  public void function addToJavaPaths( javaSettings, absolutePath ) {
    param javaSettings.loadPaths = [];

    var existingFileNames = javaSettings.loadPaths.map( function( path ) {
      return getFileFromPath( path );
    } );

    if ( fileExists( absolutePath ) ) {
      javaSettings.loadPaths.add( absolutePath );
    } else if ( directoryExists( absolutePath ) ) {
      javaSettings.loadPaths.addAll(
        directoryList( absolutePath, true, 'path', '*.jar' ).filter( function( path ) {
          return !existingFileNames.find( getFileFromPath( path ) );
        } )
      );
    }
  }

  private string function getDefaultWebroot() {
    return ( cgi.https == 'on' ? 'https' : 'http' ) & '://' & cgi.http_host;
  }

  public string function getMachineName() {
    if ( server.keyExists( 'lucee' ) ) return cgi.local_host;
    return createObject( 'java', 'java.net.InetAddress' ).getLocalHost().getHostName();
  }

  public struct function listAllOrmEntities( cfcLocation ) {
    var cacheKey = 'orm-entities';
    var allOrmEntities = cacheGet( cacheKey );

    if ( !isNull( allOrmEntities ) ) return allOrmEntities;

    var allOrmEntities = {};
    var allEntities = ormGetSessionFactory().getStatistics().getEntityNames();

    for ( var entityName in allEntities ) {
      var entity = getMetadata( entityNew( entityName ) );
      result[ entityName ] = { 'name' = entityName, 'table' = isNull( entity.table ) ? entityName : entity.table };
    }

    cachePut( cacheKey, allOrmEntities );

    return allOrmEntities;
  }
}