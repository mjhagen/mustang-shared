component accessors=true {
  property beanFactory;

  property dataService;
  property fileService;
  property imageScalerService;
  property logService;
  property queryService;
  property utilityService;

  property ds;
  property config;
  property datasource;
  property fw;
  property root;
  property websiteId;
  property navigationType;

  property string allLanguages;

  // CONSTRUCTOR

  public component function init( ds, websiteId, config, fw ) {
    param arguments.ds = "";

    fw.frameworkTrace( '<b>webmanager</b>: webmanagerService initialized.' );

    structAppend( variables, arguments, true );

    param config.showDebug = false;
    param config.redirectToMainUrl = true;

    variables.supportedLocales = {
      'nl' = 'nl_NL',
      'uk' = 'en_US',
      'fr' = 'fr_FR',
      'de' = 'de_DE'
    };
    variables.allLanguages = structKeyList( variables.supportedLocales );
    variables.safeDelim = chr( 0182 );
    variables.defaultLanguage = lCase( listLast( config.defaultLanguage, '_' ) );
    variables.datasource = arguments.ds;
    variables.queryOptions = {
      'datasource' = variables.datasource,
      'cachedWithin' = createTimespan( 0, 0, 5, 0 )
    };
    variables.resizeBeforeServe = 'jpg,jpeg,png,gif';

    return this;
  }

  // PUBLIC

  public boolean function actionHasView( required string action ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: actionHasView( #action# ) called. Looking for view: #variables.root & '/views/' & replace( action, '.', '/', 'all' ) & '.cfm'#' );

    return variables.utilityService.fileExistsUsingCache( variables.root & '/views/' & replace( action, '.', '/', 'all' ) & '.cfm' );
  }

  public void function appendPageDataToRequestContext( required struct requestContext ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: appendPageDataToRequestContext() called.' );

    var seoPathArray = seoPathAsArray();

    var pageData = {
      'pageTemplate' = '',
      'pageDetails' = {},
      'modules' = {},
      'articles' = [],
      'onPage' = false,
      'navPath' = [],
      'stylesheets' = [],
      'security' = {}
    };

    pageData[ 'basePath' ] = getBasePath( seoPathArray );
    pageData[ 'currentBaseMenuItem' ] = getCurrentBaseMenuItem( seoPathArray );
    pageData[ 'currentMenuItem' ] = getCurrentMenuItem( seoPathArray );
    pageData[ 'pageTitle' ] = getPageTitle( seoPathArray );
    pageData[ 'websiteDetails' ] = getWebsiteDetails();
    pageData[ 'currentBaseMenuItemId' ] = -1;
    pageData[ 'navigation' ] = [];

    switch ( variables.navigationType ) {
      case 'full':
        pageData[ 'fullNavigation' ] = getFullNavigation( variables.websiteId );
        break;
    }

    var pathLength = arrayLen( seoPathArray );

    for ( var i = 1; i <= pathLength; i++ ) {
      var seoPathArrayAtCurrentLevel = variables.utilityService.arrayTrim( seoPathArray, i );
      var currentMenuId = getMenuIdFromPath( seoPathArrayAtCurrentLevel );

      if ( i <= 2 ) {
        pageData[ 'currentBaseMenuItemId' ] = currentMenuId;
      }

      if ( i == pathLength ) {
        pageData.articles = getArticles( currentMenuId );
        pageData.pageDetails = getPageDetails( currentMenuId );
        // pageData.security = getClientSecurity( currentMenuId );
        pageData.modules = getActiveModules( currentMenuId );
        pageData.onPage = ( pageData.articles.len() && pageData.articles[1].articleId == pageData.pageDetails.pageId );
      }

      if ( currentMenuId > 0 ) {
        if ( structKeyExists( pageData, 'navigation' ) ) {
          pageData[ 'navigation' ][ i ] = getMenuItems( currentMenuId );
        }
        pageData[ 'navPath' ][ i ] = getNavPath( seoPathArray, i );
      }
    }

    pageData[ 'pageTemplate' ] = getTemplate( pageData );
    pageData[ 'currentLevel' ] = arrayLen( pageData.navPath ) - 1;

    structAppend( requestContext, pageData );
  }

  public string function getActionFromPath( array seoPathArray ) {
    if ( isNull( seoPathArray ) ) {
      seoPathArray = seoPathAsArray();
    }

    if ( !arrayLen( seoPathArray ) ) {
      return 'main.home';
    }

    var firstItemIndex = 1;
    var firstItem = seoPathArray[ 1 ];

    if ( isALanguage( firstItem ) ) {
      firstItemIndex = 2;
    }

    if ( !arrayIsDefined( seoPathArray, firstItemIndex ) ) {
      return 'main.home';
    }

    return 'main.' & asFw1Item( seoPathArray[ firstItemIndex ] );
  }

  public array function getNavigation( required numeric parentId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getNavigation() called.' );
    var sql = '
      SELECT    assetcontent_sTitleText                               AS name,
                dbo.variableFormatMstng( assetcontent_sTitleText )    AS formatted,
                mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID AS parentId,
                assetmeta_nID                                         AS menuId,
                assetmeta_nSortKey                                    AS sortKey

      FROM      mid_assetmetaAssetmeta
                INNER JOIN vw_selectAsset ON mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildId = vw_selectAsset.assetmeta_nID

      WHERE     assetmeta_x_nBwsId = :websiteId
        AND     assetmeta_x_nTypeId = 2
        AND     assetmeta_x_nBmId = 14
        AND     assetmeta_x_nStatusId = 100
        AND     mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentId = :parentId
        AND     GETDATE() BETWEEN assetmeta_dOnlineDateTime AND assetmeta_dOfflineDateTime
        AND     LEFT( assetcontent_sTitleText, 1 ) <> ''_''

      ORDER BY  sortKey,
                formatted
    ';

    var queryParams = { 'parentId' = arguments.parentId, 'websiteId' = variables.websiteId };

    return variables.dataService.queryToTree(
      variables.queryService.execute( sql, queryParams, variables.queryOptions ),
      arguments.parentId
    );
  }

  public array function getMenuItems( required numeric parentId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getMenuItems() called.' );
    var sql = '
      SELECT    assetcontent_sTitleText

      FROM      mid_assetmetaAssetmeta
                INNER JOIN vw_selectAsset ON mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildId = vw_selectAsset.assetmeta_nID

      WHERE     assetmeta_x_nBwsId = :websiteId
        AND     assetmeta_x_nTypeId = 2
        AND     assetmeta_x_nBmId = 14
        AND     assetmeta_x_nStatusId = 100
        AND     mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentId = :parentId
        AND     GETDATE() BETWEEN assetmeta_dOnlineDateTime AND assetmeta_dOfflineDateTime
        AND     LEFT( assetcontent_sTitleText, 1 ) <> ''_''

      ORDER BY  assetmeta_nSortKey,
                assetcontent_sTitleText
    ';

    var queryParams = { 'parentId' = parentId, 'websiteId' = variables.websiteId };

    var navigationQuery = variables.queryService.execute( sql, queryParams, variables.queryOptions );

    return listToArray( valueList( navigationQuery.assetcontent_sTitleText, variables.safeDelim ), variables.safeDelim );
  }

  public any function getArticle( required numeric articleId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getArticle() called.' );
    var sql = '
      SELECT    assetmeta_nid                AS [articleId],
                assetmeta_dcreationdatetime  AS [creationDate],
                assetcontent_stitletext      AS [title],
                assetcontent_sintrotext      AS [teaser],
                assetcontent_sbodytext       AS [body],
                assetmeta_nSortKey           AS [sortKey]

      FROM      vw_selectAsset

      WHERE     assetmeta_x_nBwsId = :websiteId
        AND     assetmeta_x_nTypeId = 3
        AND     assetmeta_x_nBmId = 14
        AND     assetmeta_x_nStatusId = 100
        AND     assetmeta_nid = :articleId

      ORDER BY  assetmeta_nSortKey,
                assetcontent_sTitleText
    ';

    var queryParams = { 'articleId' = articleId, 'websiteId' = variables.websiteId };

    var queryResult = variables.queryService.execute( sql, queryParams, variables.queryOptions );

    if ( queryResult.recordCount == 0 ) {
      return;
    }

    var article = variables.queryService.toArray( queryResult )[ 1 ];

    article[ 'images' ] = getArticleImages( article.articleId );

    return article;
  }

  public array function getArticles( required numeric pageId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getArticles() called.' );
    var sql = '
      SELECT    vw_selectAsset.assetmeta_nid                                      AS [articleId],
                vw_selectAsset.assetmeta_dcreationdatetime                        AS [creationDate],
                vw_selectAsset.assetcontent_stitletext                            AS [title],
                dbo.variableFormatMstng( vw_selectAsset.assetcontent_stitletext ) AS [formatted],
                vw_selectAsset.assetcontent_sintrotext                            AS [teaser],
                vw_selectAsset.assetcontent_sbodytext                             AS [body],
                vw_selectAsset.assetmeta_nSortKey                                 AS [sortKey]

      FROM      mid_assetmetaAssetmeta
                INNER JOIN vw_selectAsset ON mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildId = vw_selectAsset.assetmeta_nID

      WHERE     vw_selectAsset.assetmeta_x_nBwsId = :websiteId
        AND     vw_selectAsset.assetmeta_x_nTypeId = 3
        AND     vw_selectAsset.assetmeta_x_nBmId = 14
        AND     vw_selectAsset.assetmeta_x_nStatusId = 100
        AND     (
                  mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentId = :pageId OR
                  vw_selectAsset.assetmeta_nid = :pageId
                )

      ORDER BY  vw_selectAsset.assetmeta_nSortKey,
                vw_selectAsset.assetcontent_sTitleText
    ';

    var queryParams = { 'pageId' = pageId, 'websiteId' = variables.websiteId };

    return variables.queryService.toArray( variables.queryService.execute( sql, queryParams, variables.queryOptions ) ).map( function( article ) {
      article.images = getArticleImages( article.articleId );
      article.tags = getArticleShortcuts( article.articleId );
      return article;
    } );
  }

  public struct function getActiveModules( required numeric pageId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getActiveModules() called.' );

    var sql = '
      SELECT    vw_selectAsset.assetmeta_x_nBmID AS moduleId,
                vw_selectAsset.assetcontent_sTitleText AS moduleConfigA,
                vw_selectAsset.assetcontent_sIntroText AS moduleConfigB,
                vw_selectAsset.assetcontent_sBodyText AS moduleConfigC,
                lst_bm.bm_sDirName AS moduleDir

      FROM      vw_selectAsset
                INNER JOIN mid_assetmetaAssetmeta ON vw_selectAsset.assetmeta_nID = mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildID
                INNER JOIN lst_bm ON vw_selectAsset.assetmeta_x_nBmID = lst_bm.bm_nID

      WHERE     vw_selectAsset.assetmeta_x_nTypeID = 10
        AND     lst_bm.bm_bActive = 1
        AND     mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID = :pageId
        AND     vw_selectAsset.assetmeta_x_nBwsID = :websiteId
    ';

    var queryParams = { 'pageId' = pageId, 'websiteId' = variables.websiteId };

    var activeModules = variables.queryService.toArray( variables.queryService.execute( sql, queryParams, variables.queryOptions ) );
    var moduleContent = {};

    for ( var activeModule in activeModules ) {
      var moduleConfig = [
        activeModule.moduleConfigA,
        activeModule.moduleConfigB,
        activeModule.moduleConfigC
      ];
      var moduleSpecificService = beanFactory.getBean( '#activeModule.moduleDir#Service' );
      moduleContent[ activeModule.moduleDir ] = moduleSpecificService.getModuleContent( moduleConfig );
    }

    return moduleContent;
  }

  public any function getArticleFromPath( required string pathToArticle ) {
    return getArticle( getArticleIdFromPath( pathToArticle ) );
  }

  public string function getLanguageFromPath( array seoPathArray ) {
    if ( isNull( seoPathArray ) ) {
      seoPathArray = seoPathAsArray();
    }

    if ( arrayLen( seoPathArray ) && isALanguage( seoPathArray[ 1 ] ) ) {
      return asLocale( seoPathArray[ 1 ] );
    }

    return '';
  }

  public void function relocateOnce( string domainname = '' ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: relocateOnce() called.' );

    if ( domainname == '' || domainname == cgi.server_name || !isLiveUrl() || !config.redirectToMainUrl ) {
      variables.fw.frameworkTrace( '<b>webmanager</b>: relocateOnce() aborted.' );
      return;
    }

    var protocol = 'http' & ( isHttps() ? 's' : '' ) & '://';
    var path = cgi.path_info & ( cgi.script_name == '/index.cfm' ? len( cgi.path_info ) ? '' : '/' : cgi.script_name );
    var querystring = ( len( trim( cgi.query_string ) ) ? '?' & cgi.query_string : '' );
    var relocateTo = replace( protocol & domainname & path & querystring, '/index.cfm', '/', 'one' );

    location( relocateTo, false, 301 );
  }

  public array function seoPathAsArray() {
    variables.fw.frameworkTrace( '<b>webmanager</b>: seoPathAsArray() called.' );

    var seoPath = variables.utilityService.fixPathInfo();

    if ( structKeyExists( variables.config, 'rootWebmanagerPath' ) ) {
      if ( isRoot() ) {
        seoPath = variables.config.rootWebmanagerPath;
      } else {
        seoPath = variables.config.rootWebmanagerPath & seoPath;
      }
    }

    var tmp = listToArray( seoPath, '/' );
    var seoPathArray = [];

    for ( var item in tmp ) {
      arrayAppend( seoPathArray, reReplace( item, '^[-_]', '', 'one' ) );
    }

    if ( arrayIsEmpty( seoPathArray ) || !listFindNoCase( variables.allLanguages, seoPathArray[ 1 ] ) ) {
      arrayPrepend( seoPathArray, variables.defaultLanguage );
    }

    return seoPathArray;
  }

  public void function serveMedia( required struct requestContext ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: serveMedia() called.' );
    param requestContext.file="";
    param requestContext.s="m";

    if ( !variables.utilityService.fileExistsUsingCache( '#variables.config.mediaRoot#/sites/site#variables.websiteId#/images/#requestContext.file#' ) ) {
      throw( 'File does not exist', 'webmanagerService.serveMedia.fileNotFoundError' );
    }

    var fileExtension = listLast( requestContext.file, '.' );
    var cacheFor = dateAdd( 'ww', 1, now() );

    if ( listFind( variables.resizeBeforeServe, fileExtension ) ) {
      if ( !variables.utilityService.fileExistsUsingCache( '#variables.root#/www/inc/img/resized/#requestContext.s#-#requestContext.file#' ) ) {
        variables.imageScalerService.setDestinationDir( '#variables.root#/www/inc/img/resized' );
        variables.imageScalerService.resizeFromPath(
          variables.config.mediaRoot & '/sites/site#variables.websiteId#/images/#requestContext.file#',
          requestContext.file,
          requestContext.s
        );
        variables.utilityService.cfheader( name = 'Last-Modified', value = '#getHTTPTimeString( now() )#' );
      }
      var fileToServe = '#variables.root#/www/inc/img/resized/#requestContext.s#-#requestContext.file#';
    } else {
      var fileToServe = variables.config.mediaRoot & '/sites/site#variables.websiteId#/images/#requestContext.file#';
    }

    variables.utilityService.cfheader( statuscode = 200, statustext = 'OK' );
    variables.utilityService.cfheader( name = 'Expires', value = '#getHTTPTimeString( cacheFor )#' );
    variables.utilityService.cfheader( name = 'Cache-Control', value = 'public, max-age=604800' );
    variables.utilityService.cfcontent( reset = true, file = fileToServe, type = 'image/#fileExtension#' );
    abort;
  }

  public struct function validate( required component beanToValidate ) {
    var validator = new hyrule.system.core.Hyrule();
    return validator.validate( beanToValidate );
  }

  public array function searchArticles( required string searchTerm, string language = 'nl', boolean ignoreDate = false ) {
    if ( !len( trim( searchTerm ) ) ) {
      return [];
    }

    var languageId = getLanguageId( language );

    var sql = '
      EXEC sp_fullTextSearch
        @searchTerm = :searchTerm,
        @bwsID = :bwsID,
        @languageID = :languageID,
        @ignoreDate = :ignoreDate
    ';

    var queryParams = {
      'searchTerm' = left( trim( searchTerm ), 64 ),
      'bwsID' = variables.websiteId,
      'languageID' = languageID,
      'ignoreDate' = { 'value' = ignoreDate, 'cfsqltype' = 'cf_sql_bit' }
    };

    var searchResult = variables.queryService.execute( sql, queryParams, variables.queryOptions );

    return variables.queryService.toArray( searchResult );
  }

  public array function getPathFromId( required numeric articleId ) {
    var path = [];
    var parent = { id = articleId };

    while ( parent.id > 0 ) {
      parent = getParentFromId( parent.id );
      arrayPrepend( path, parent.name );
    };

    return path;
  }

  public boolean function isLiveUrl() {
    var nonLiveWords = listToArray( 'dev,staging,home,local,mac,mjh,jd' );

    for ( var part in nonLiveWords ) {
      if ( listFindNoCase( cgi.server_name, part, '.' ) ) {
        return false;
      }
    }

    return true;
  }

  public void function sitemap() {
    if ( cgi.path_info contains 'sitemap.xml' ) {
      include '/mustang/lib/webmanager/includes/createsitemap.cfm';
      abort;
    }
  }

  public void function robotstxt() {
    if ( cgi.path_info contains 'robots.txt' ) {
      utilityService.cfheader( statuscode = 200, statustext = 'OK' );
      utilityService.cfcontent( reset = true, type = 'text/plain' );
      writeOutput(
        'User-Agent: *' & chr( 10 ) &
        'Allow: /' & chr( 10 ) &
        'Disallow: /css/' & chr( 10 ) &
        'Disallow: /scripts/' & chr( 10 ) &
        'Disallow: /modules/' & chr( 10 ) &
        'Disallow: /nl/extranet/' & chr( 10 ) &
        'Disallow: /extranet/' & chr( 10 ) &
        'Disallow: /nl/login/' & chr( 10 ) &
        'Disallow: /login/' & chr( 10 ) &
        'Disallow: /nl/_login/' & chr( 10 ) &
        'Disallow: /_login/' & chr( 10 ) &
        'Sitemap: http#variables.config.useHttps ? 's' : ''#://#cgi.server_name#/sitemap.xml'
      );
      abort;
    }
  }

  public numeric function getMenuIdFromPath( required any path ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getMenuIdFromPath() called.' );
    var pathArray = isArray( path ) ? path : listToArray( path, '/' );
    var pathLength = arrayLen( pathArray );

    if ( pathLength == 0 ) {
      return -1;
    }

    var sql_from = ' FROM vw_selectAsset AS nav_level_1 ';
    var sql_where = ' WHERE nav_level_1.assetmeta_x_nBwsId = :websiteId
                        AND nav_level_1.assetmeta_x_nTypeId IN ( 2, 3 )
                        AND nav_level_1.assetmeta_x_nBmId = 14
                        AND dbo.variableFormatMstng( nav_level_1.assetcontent_sTitleText ) IN (
                              :menuName_1,
                              ''_'' + :menuName_1,
                              REPLACE( :menuName_1, ''-'', ''_'' ),
                              ''_'' + REPLACE( :menuName_1, ''-'', ''_'' )
                            )
        ';
    var queryParams = { 'menuName_1' = pathArray[ 1 ], 'websiteId' = variables.websiteId };

    for ( var i = 2; i <= pathLength; i++ ) {
      sql_from &= '
        INNER JOIN mid_assetmetaAssetmeta AS link_#i-1#_#i#
          ON nav_level_#i-1#.assetmeta_nId = link_#i-1#_#i#.assetmetaAssetmeta_x_nParentID
        INNER JOIN vw_selectAsset AS nav_level_#i#
          ON link_#i-1#_#i#.assetmetaAssetmeta_x_nChildId = nav_level_#i#.assetmeta_nID
      ';
      sql_where &= ' AND nav_level_#i#.assetmeta_x_nBwsId = :websiteId
                     AND nav_level_#i#.assetmeta_x_nTypeId IN ( 2, 3 )
                     AND nav_level_#i#.assetmeta_x_nBmId = 14
                     AND dbo.variableFormatMstng( nav_level_#i#.assetcontent_sTitleText ) IN (
                           :menuName_#i#,
                           ''_'' + :menuName_#i#,
                           REPLACE( :menuName_#i#, ''-'', ''_'' ),
                           ''_'' + REPLACE( :menuName_#i#, ''-'', ''_'' )
                         )
      ';
      queryParams[ 'menuName_#i#' ] = pathArray[ i ];
    }

    var sql_select = ' SELECT DISTINCT nav_level_#pathLength#.assetmeta_nID ';
    var sql = sql_select & sql_from & sql_where;

    var pathQuery = variables.queryService.execute( sql, queryParams, variables.queryOptions );

    if ( pathQuery.recordCount == 1 ) {
      return pathQuery.assetmeta_nID[ 1 ];
    }

    return -1;
  }

  public array function getCompleteNavigation() {
    return getFullNavigation( includeHidden = true );
  }

  public array function getFullNavigation( numeric websiteId = variables.websiteId, boolean includeHidden = false ) {
    var hiddenNav = includeHidden ? '' : 'AND     LEFT( tbl_assetContent.assetcontent_sTitleText, 1 ) <> ''_''';

    var sql = '
      SELECT    tbl_assetMeta.assetmeta_x_nBwsID AS websiteId,
                mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID AS parentId,
                tbl_assetMeta.assetmeta_nID AS menuId,
                tbl_assetContent.assetcontent_sTitleText AS name,
                dbo.variableFormatMstng( tbl_assetContent.assetcontent_sTitleText ) AS formatted,
                parentMenu.assetmeta_nSortKey AS parentSortKey,
                tbl_assetMeta.assetmeta_nSortKey AS sortKey

      FROM      mid_assetmetaAssetcontent
                INNER JOIN tbl_assetContent ON mid_assetmetaAssetcontent.assetmetaAssetcontent_x_nAssetContentID = tbl_assetContent.assetcontent_nID
                INNER JOIN tbl_assetMeta ON mid_assetmetaAssetcontent.assetmetaAssetcontent_x_nAssetMetaID = tbl_assetMeta.assetmeta_nID
                INNER JOIN mid_assetmetaAssetmeta ON tbl_assetMeta.assetmeta_nID = mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildID
                INNER JOIN tbl_assetMeta AS parentMenu ON mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID = parentMenu.assetmeta_nID

      WHERE     tbl_assetMeta.assetmeta_x_nBwsID = :websiteId
        AND     tbl_assetMeta.assetmeta_x_nStatusID = 100
        AND     tbl_assetMeta.assetmeta_x_nTypeID = 2
        AND     tbl_assetMeta.assetmeta_x_nBmID = 14
        #hiddenNav#

      ORDER BY  parentSortKey, parentId, sortKey, menuId
    ';

    var queryParams = { 'websiteId' = variables.websiteId };

    return variables.dataService.queryToTree( variables.queryService.execute( sql, queryParams, variables.queryOptions ) );
  }

  public void function logVisit( page ) {
    logService.writeLogLevel( text = page, level = 'information' );
  }


  public string function linkExpander( required body, publishOnURL = '', reload = false ) {
    reMatchNoCase( 'href="([^"]+)"', body )
      .map( function ( linkMatch ) {
        var link = {
          replaceThis = linkMatch.mid( 7, linkMatch.len() - 7 ),
          withThis = ''
        };

        var cachedLink = cacheGet( hash( link.replaceThis ) );

        if ( !isNull( cachedLink ) ) {
          return cachedLink;
        }

        var linkToIndex = link.replaceThis.replaceNoCase( 'amp;', '', 'all' );

        if ( linkToIndex.findNoCase( 'client/modules/links/index.cfm?fuseaction=linkHandler' ) ) {
          var testLink={};

          cfhttp( url=linkToIndex, redirect=false, result="testLink" );

          param testLink.responseheader.status_code=200;

          // file links:
          if ( testLink.keyExists( 'fileContent' ) && !isSimpleValue( testLink.fileContent ) ) {
            replaceWith = linkToIndex;

            if ( testLink.responseheader.keyexists( 'content-disposition' ) &&
                 testLink.responseheader[ 'content-disposition' ].trim().len() ) {
              var expandedlink = '#publishOnURL#/media/files/#testLink.responseheader[ 'content-disposition' ].listlast( '=' )#';
            }

          // regular links:
          } else {
            //  404 Not found
            if ( testLink.responseheader.status_code == '404' ) {
              linkToIndex = linkToIndex & ( linkToIndex.find('?')?'&':'?') & 'reload=1';
              cfhttp( url=linkToIndex, redirect=false, result=testLink );
            }

            //  Working link
            if ( testLink.responseheader.location.trim().len() ) {
              link.withThis = testLink.responseheader.location
                .replace( '_', '-', 'all' )
                .replace( '/#defaultLanguage#/', '/' );
            }
          }
        }

        return link;
      } )
      .filter( function ( link ) { return link.withThis.len(); } )
      .each( function ( link ) {
        cachePut( hash( link.replaceThis ), link );
        body = body.replaceNoCase( link.replaceThis, link.withThis, 'all' );
      } );

    return body.trim();
  }


  // PRIVATE

  private struct function getParentFromId( required numeric childId ) {
    var sql = '
      SELECT    TOP 1
                dbo.variableFormatMstng( vw_selectAsset.assetcontent_sTitleText ) AS parentName,
                mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID AS parentId

      FROM      vw_selectAsset
                INNER JOIN mid_assetmetaAssetmeta ON vw_selectAsset.assetmeta_nID = mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildID
                INNER JOIN tbl_assetMeta ON mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID = tbl_assetMeta.assetmeta_nID

      WHERE     tbl_assetMeta.assetmeta_x_nTypeID IN ( 2, 3, 4 )
        AND     vw_selectAsset.assetmeta_nID = :childId
    ';
    var queryParams = { 'childId' = childId };
    var parent = variables.queryService.execute( sql, queryParams, variables.queryOptions );
    return { id = parent.parentId[ 1 ], name = parent.parentName };
  }

  private numeric function getLanguageId( required string sLanguage ) {
    var sql = ' SELECT    language_nID
                FROM      lst_language
                WHERE     language_sAbbreviation = :sLanguage';

    var queryParams = { 'sLanguage' = sLanguage };

    var result = variables.queryService.execute( sql, queryParams, variables.queryOptions );
    return val( result.language_nId[ 1 ] );
  }

  private string function getBasePath( required array seoPathArray ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getBasePath() called.' );

    if ( seoPathArray[ 1 ] != variables.defaultLanguage ) {
      return '/#seoPathArray[ 1 ]#';
    }

    return '';
  }

  private string function getNavPath( required array seoPathArray, numeric level ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getNavPath() called.' );
    var result = '';
    for ( var i = 2; i <= level; i++ ) {
      if ( !arrayIsDefined( seoPathArray, i ) ) {
        continue;
      }
      result &= '/#seoPathArray[ i ]#';
    }
    return result;
  }

  private string function getCurrentBaseMenuItem( required array seoPathArray ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getCurrentBaseMenuItem() called.' );

    if ( arrayLen( seoPathArray ) > 1 ) {
      return seoPathArray[ 2 ];
    }

    return '';
  }

  private string function getCurrentMenuItem( required array seoPathArray ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getCurrentMenuItem() called.' );
    return seoPathArray[ arrayLen( seoPathArray ) ];
  }

  private string function getPageTitle( required array seoPathArray, string titleDelimiter = ' - ' ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getPageTitle() called.' );

    if ( arrayIsEmpty( seoPathArray ) ) {
      return '';
    }

    var allLocales = structKeyArray( variables.supportedLocales );

    var seoPathArray_copy = duplicate( seoPathArray );

    if ( arrayFindNoCase( allLocales, seoPathArray[ 1 ] ) ) {
      arrayDeleteAt( seoPathArray_copy, 1 );
    }

    var reversedSeoPath = variables.utilityService.arrayReverse( seoPathArray_copy );
    var fullPath = arrayToList( reversedSeoPath, variables.safeDelim );
    var asTitle = replace( fullPath, variables.safeDelim, titleDelimiter, 'all' );

    return asTitle;
  }

  private numeric function getArticleIdFromPath( required any path ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getArticleIdFromPath() called.' );
    return getMenuIdFromPath( path );
  }

  private struct function getPageDetails( pageId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getPageDetails() called.' );
    var sql = '
      SELECT    assetmeta_nID               AS pageId,
                assetcontent_sTitleText     AS name,
                assetmeta_nRating           AS template,
                assetcontent_sPath          AS htmlKeywords,
                ISNULL( assetcontent_sName, assetcontent_sTitleText ) AS htmlTitle,
                assetcontent_sFileExtension AS htmlDescription,
                assetcontent_sIntroText     AS unknown_1,
                assetcontent_sBodyText      AS unknown_2

      FROM      vw_selectAsset

      WHERE     assetmeta_nid = :pageId
        AND     assetmeta_x_nBwsId = :websiteId
        AND     assetmeta_x_nBmId = 14
        AND     assetmeta_x_nStatusId = 100
        AND     assetmeta_x_nTypeId IN ( 2, 3 )
        AND     GETDATE() BETWEEN assetmeta_dOnlineDateTime AND assetmeta_dOfflineDateTime
    ';

    var queryResult = variables.queryService.execute( sql, { 'pageId' = pageId, 'websiteId' = variables.websiteId }, variables.queryOptions );

    return queryResult.recordCount == 0
      ? {}
      : variables.queryService.toArray( queryResult )[ 1 ];
  }

  private struct function getWebsiteDetails() {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getWebsiteDetails() called.' );

    var queryResult = variables.queryService.execute(
      'SELECT * FROM tbl_bws WHERE bws_nId = :websiteId',
      { 'websiteId' = variables.websiteId },
      variables.queryOptions
    );

    return queryResult.recordCount == 0 ? {} : variables.queryService.toArray( queryResult )[ 1 ];
  }

  private array function getArticleImages( required numeric articleId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getArticleImages() called.' );
    var sql = '
      SELECT    vw_selectAsset.assetcontent_sFileExtension AS src,
                vw_selectAsset.assetcontent_sTitleText AS alt,
                vw_selectAsset.assetcontent_sName AS byline,
                vw_selectAsset.assetcontent_sIntroText AS other

      FROM      vw_selectAsset
                INNER JOIN mid_assetmetaAssetmeta ON vw_selectAsset.assetmeta_nID = mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nChildID

      WHERE     mid_assetmetaAssetmeta.assetmetaAssetmeta_x_nParentID = :articleId
        AND     vw_selectAsset.assetmeta_x_nBwsID = :websiteId
        AND     vw_selectAsset.assetmeta_x_nTypeID = 1
        AND     vw_selectAsset.assetmeta_x_nBmID IS NULL
        AND     vw_selectAsset.assetmeta_x_nStatusID = 100

      ORDER BY  vw_selectAsset.assetmeta_nSortKey
    ';

    var queryParams = { 'articleId' = articleId, 'websiteId' = variables.websiteId };

    return variables.queryService.toArray( variables.queryService.execute( sql, queryParams, variables.queryOptions ) );
  }

  private array function getArticleShortcuts( required numeric articleId ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getArticleShortcuts() called.' );
    var sql = '
      SELECT    tag_am.assetmeta_nID AS id,
                tag_ac.assetcontent_sTitleText AS name,
                tag_ac.assetcontent_x_nLanguageID AS languageId

      FROM      mid_assetmetaAssetcontent AS article_amac
                INNER JOIN mid_assetmetaAssetcontent  AS link_amac    ON link_amac.assetmetaAssetcontent_x_nAssetContentID = article_amac.assetmetaAssetcontent_x_nAssetContentID
                INNER JOIN tbl_assetMeta              AS link_am      ON link_am.assetmeta_nID = link_amac.assetmetaAssetcontent_x_nAssetMetaID
                INNER JOIN mid_assetmetaAssetmeta     AS linktag_amam ON linktag_amam.assetmetaAssetmeta_x_nChildID = link_am.assetmeta_nID
                INNER JOIN tbl_assetMeta              AS tag_am       ON tag_am.assetmeta_nID = linktag_amam.assetmetaAssetmeta_x_nParentID
                INNER JOIN mid_assetmetaAssetcontent  AS tag_amac     ON tag_amac.assetmetaAssetcontent_x_nAssetMetaID = tag_am.assetmeta_nID
                INNER JOIN tbl_assetContent           AS tag_ac       ON tag_ac.assetcontent_nID = tag_amac.assetmetaAssetcontent_x_nAssetContentID

      WHERE     link_am.assetmeta_x_nTypeID = 15
        AND     link_am.assetmeta_x_nStatusID = 100
        AND     link_am.assetmeta_x_nBmID = 8
        AND     link_am.assetmeta_x_nBwsID = :websiteId
        AND     tag_am.assetmeta_x_nTypeID = 14
        AND     tag_am.assetmeta_x_nStatusID = 100
        AND     tag_am.assetmeta_x_nBmID = 8
        AND     tag_am.assetmeta_x_nBwsID = :websiteId
        AND     article_amac.assetmetaAssetcontent_x_nAssetMetaID = :articleId

      ORDER BY ISNULL(link_am.assetmeta_nSortKey, 9999)
    ';

    var queryParams = { 'articleId' = articleId, 'websiteId' = variables.websiteId };

    return variables.queryService.toArray( variables.queryService.execute( sql, queryParams, variables.queryOptions ) );
  }

  private string function getTemplate( required struct requestContext ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: getTemplate() called.' );
    var defaultTemplate = 'main.default';

    if ( !structKeyExists( requestContext, 'pageDetails' ) ||
    !structKeyExists( requestContext.pageDetails, 'template' ) ||
    !len( requestContext.pageDetails.template ) ||
    !isNumeric( requestContext.pageDetails.template ) ||
    requestContext.pageDetails.template < 1 ||
    requestContext.pageDetails.template > arrayLen( variables.config.templates ) ) {
      return defaultTemplate;
    }

    return variables.config.templates[ requestContext.pageDetails.template ];
  }

  private array function getClientSecurity( required numeric menuId ) {
    var sql = '
      SELECT    assetcontent_sIntroText,
                assetcontent_sBodyText

      FROM      tbl_assetcontent
                INNER JOIN mid_assetmetaAssetcontent ON assetcontent_nID = assetmetaAssetcontent_x_nAssetcontentID

      WHERE     assetmetaAssetcontent_x_nAssetmetaID = :menuId
    ';

    var queryParams = { 'menuId' = menuId };

    return variables.queryService.toArray( variables.queryService.execute( sql, queryParams, variables.queryOptions ) );
  }

  private boolean function isALanguage( required string potentialLanguage ) {
    return listFindNoCase( getAllLanguages(), potentialLanguage );
  }

  private string function asLocale( required string webmanagerLanguage ) {
    variables.fw.frameworkTrace( '<b>webmanager</b>: asLocale() called.' );
    return variables.supportedLocales[ webmanagerLanguage ];
  }

  private boolean function isLocale( required string possibleLocale ) {
    return structKeyExists( variables.supportedLocales, possibleLocale );
  }

  private string function asFw1Item( required string unformattedItem ) {
    return replace( reReplace( listFirst( unformattedItem ), '^[-_]', '', 'one' ), '-', '_', 'all' );
  }

  private boolean function isRoot() {
    var pathLength = listLen( cgi.path_info, '/' );
    if ( pathLength == 0 ) {
      return true;
    } else if ( pathLength == 1 ) {
      return isLocale( listFirst( cgi.path_info, '/' ) );
    }

    return false;
  }

  private boolean function isHttps() {
    var httpHeaders = fw.getHttpRequestHeaders();

    if ( structKeyExists( httpHeaders, 'X-Forwarded-Proto' ) ) {
      return httpHeaders[ 'X-Forwarded-Proto' ] == 'https' ? true : false;
    }

    return cgi.server_port_secure == 1;
  }
}