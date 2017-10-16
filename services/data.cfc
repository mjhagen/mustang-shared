component accessors=true {
  property jsonService;
  property jsonJavaService;
  property utilityService;
  property logService;

  // sanitation functions:

  public numeric function sanitizeNumericValue( required string source ) {
    var result = reReplace( source, '[^\d-\.]+', '', 'all' );

    if ( isNumeric( result ) ) {
      return result;
    }

    throw( type = "dataService.sanitizeNumericValue", message = "Value could not be converted to a number.", detail = "Original value: #source#." );
  }

  public numeric function sanitizePercentageValue( required string source ) {
    try {
      var result = sanitizeNumericValue( source );
    } catch ( dataService e ) {
      throw( type = "dataService.sanitizePercentageValue", message = e.message, detail = e.detail );
    }

    if ( val( result ) == 0 ) {
      return 0;
    }

    if ( result > 100 ) {
      result = result / 100;
    }

    if ( result > 1 ) {
      result = result / 100;
    }

    if ( result < 0.01 ) {
      result = result * 100;
    }

    return result;
  }

  // This method makes an educated guess about the date format
  public date function sanitizeDateValue( required string source ) {
    var result = source;
    var dateFormats = {
      admy = [ 3, 2, 1 ],
      bmdy = [ 3, 1, 2 ],
      cymd = [ 1, 2, 3 ]
    };

    try {
      source = dateDeFuckulator( source );

      source = reReplace( source, '\D+', '-', 'all' );

      if ( !listLen( source, '-' ) >= 3 ) {
        if ( __isValidDate( source ) ) {
          return source;
        }

        throw(
          type = "dataService.sanitizeDateValue.noDateDetectedError",
          message = "Error sanitizing date string (#source#).",
          detail = "Could not detect date format in '#source#'"
        );
      }

      if ( arrayLen( arguments ) >= 2 ) {
        // Use the provided date formatter:
        dateFormats = { "#arguments[ 2 ]#" = dateFormats[ arguments[ 2 ] ] };
      } else {
        if ( len( listGetAt( source, 1, '-' ) ) == 4 ) {
          // last item can't be the YEAR
          structDelete( dateFormats, 'bmdy' );
          structDelete( dateFormats, 'admy' );
        }

        if ( len( listGetAt( source, 3, '-' ) ) == 4 ) {
          // last item is probably the YEAR
          structDelete( dateFormats, 'cymd' );
        }

        if ( listGetAt( source, 1, '-' ) > 12 ) {
          // first item can't be the MONTH
          structDelete( dateFormats, 'bmdy' );
        }

        if ( listGetAt( source, 2, '-' ) > 12 ) {
          // second item can't be the MONTH
          structDelete( dateFormats, 'admy' );
          structDelete( dateFormats, 'cymd' );
        }
      }

      var sortedKeys = listToArray( listSort( structKeyList( dateFormats ), 'text' ) );

      for ( var key in sortedKeys ) {
        var currentDateFormat = dateFormats[ key ];

        result = createDate(
          listGetAt( source, currentDateFormat[ 1 ], '-' ),
          listGetAt( source, currentDateFormat[ 2 ], '-' ),
          listGetAt( source, currentDateFormat[ 3 ], '-' )
        );

        try {
          var testDate = lsDateFormat( result, 'dd/mm/yyyy' );
          return result;
        } catch ( any e ) {
        }
      }

      return result;
    } catch ( any e ) {
      rethrow;
    }

    throw( type = "dataService.sanitizeDateValue", message = "Value could not be converted to a date.", detail = "Original value: #source#." );
  }

  public integer function sanitizeIntegerValue( required string source ) {
    try {
      var result = int( sanitizeNumericValue( source ) );
    } catch ( dataService e ) {
      throw( type = "dataService.sanitizePercentageValue", message = e.message, detail = e.detail );
    }

    if ( isValid( "integer", result ) ) {
      return javaCast( "int", result );
    }

    throw( type = "dataService.sanitizeIntegerValue", message = "Value could not be converted to an integer.", detail = "Original value: #source#." );
  }

  // other data integrity and utility functions:

  public boolean function isGUID( required string text ) {
    if ( len( text ) < 32 ) {
      return false;
    }

    var validGUID = isValid( "guid", text );

    if ( validGUID ) {
      return true;
    }

    return isValid( "guid", __formatAsGUID( text ) );
  }

  public boolean function arrayOfStructsContains( string needle, array haystack, string key ) {
    for ( var str in haystack ) {
      if ( str[ key ] == needle ) {
        return true;
      }
    }
    return false;
  }

  public any function keyValuePairFind( any data, string key, string value, string scope = "one" ) {
    var itemsWithKey = structFindKey( { data = data }, key, "all" );
    var result = [ ];

    for ( var item in itemsWithKey ) {
      if ( item.value == value ) {
        if ( scope == "one" ) {
          return item.owner;
        }
        arrayAppend( result, item.owner );
      }
    }

    if ( !arrayIsEmpty( result ) ) {
      return result;
    }

    return;
  }

  /**
    By Tomalak
    See: https://stackoverflow.com/a/2653972/2378532
   */
  public array function arrayOfStructsSort( required array base, string pathToSubElement = "", string sortType = "textnocase", string sortOrder = "ASC" ) {
    var baseLength = arrayLen( base );
    var tmpStruct = { };

    for ( var i = 1; i <= baseLength; i++ ) {
      tmpStruct[ i ] = base[ i ];
    }

    var keys = structSort( tmpStruct, sortType, sortOrder, pathToSubElement );
    var keysLength = arrayLen( keys );
    var returnVal = [ ];

    for ( var i = 1; i <= keysLength; i++ ) {
      returnVal[ i ] = tmpStruct[ keys[ i ] ];
    }

    return returnVal;
  }

  public string function dateDeFuckulator( string potentialDate ) {
    potentialDate = reReplace( potentialDate, '\W', '/', 'all' );
    potentialDate = reReplace( potentialDate, '(\d+)(?:[a-zA-Z]+)', '\1', 'all' );

    var months = listToArray( "jan,feb,mar,apr,may,jun,jul,aug,sep,oct,nov,dec" );

    var i = 0;
    for ( var m in months ) {
        i++;
        if ( potentialDate contains m ) {
            return replaceNoCase( potentialDate, m, i, 'one' );
        }
    }

    return potentialDate;
  }

  public boolean function hasMissingStructKeys( required struct inputStruct, required array structKeys ) {
    for ( var key in structKeys ) {
      if ( !structKeyExists( inputStruct, key ) ) {
        return true;
      }
    }
    return false;
  }

  // convenience functions

  public any function processEntity( any data,
                                 numeric level = 0,
                                 numeric maxLevel = 1,
                                 boolean basicsOnly = false ) {
    if( level == 0 ) {
      variables.utilityService.setCFSetting( "requesttimeout", 10 );
    }

    var useJsonService = variables.jsonService;

    if ( !isNull( variables.jsonJavaService ) && isObject( variables.jsonJavaService ) ) {
      useJsonService = variables.jsonJavaService;
    }

    level = max( 0, level );
    maxLevel = min( 5, maxLevel );

    if( isNull( data ) || (
          maxLevel > 0 &&
          level > maxLevel &&
          !isSimpleValue( data )
        )) {
      return;
    }

    var nextLevel = level + 1;
    var maxArrayItt = 100;
    var result = "";

    // data parsing:
    if( isSimpleValue( data )) {
      var result = data;

    } else if( isArray( data )) {
      var result = [];
      var itemCounter = 0;
      for( var el in data ) {
        if( ++itemCounter > maxArrayItt ) {
          arrayAppend( result, "capped at #maxArrayItt# results" );
          break;
        } else {
          var newData = this.processEntity( el, level, maxLevel, basicsOnly );
          if( !isNull( newData )) {
            arrayAppend( result, newData );
          }
        }
      }

    } else if( isObject( data )) {
      if( !isInstanceOf( data, "basecfc.base" )) {
        if( level == 0 ) {
          throw( "Doesn't work on non-basecfc objects" );
        }
        return;
      }

      var allowedFieldTypes = "id,column,many-to-one,one-to-many,many-to-many"; // level 0 only

      if( level > 1 || basicsOnly ) {
        allowedFieldTypes = "id,column,many-to-one";
      }

      if( level >= maxLevel && !maxLevel == 0 ) {
        allowedFieldTypes = "id,column";
      }

      var result = { };
      var allFields = data.getInstanceVariables().properties;

      for( var key in allFields ) {
        var fieldProperties = {
          "inapi" = true,
          "fieldtype" = "column",
          "dataType" = ""
        };

        structAppend( fieldProperties, allFields[ key ], true );

        if ( listFindNoCase( "numeric,string,boolean", fieldProperties.fieldtype ) ) {
          fieldProperties.fieldtype = "column";
        }

        if ( !fieldProperties.inapi ) {
          continue;
        }

        if ( !listFindNoCase( allowedFieldTypes, fieldProperties.fieldtype ) ) {
          continue;
        }

        if ( !structKeyExists( data, "get#fieldProperties.name#" ) ) {
          continue;
        }

        var value = variables.utilityService.cfinvoke( data, "get#fieldProperties.name#" );

        if( isNull( value )) {
          continue;
        }

        if( fieldProperties.dataType == "json" ) {
          try {
            structAppend( result, useJsonService.deserialize( value ) );
          } catch ( any e ) {
            variables.logService.dumpToFile( { "dataService.processEntity()" = {
              "Exception" = e,
              "Data" = value,
              "Property" = fieldProperties
            } }, true );
          }
          continue;
        }


        if( fieldProperties.fieldtype contains "to-many" ) {
          basicsOnly = true; // next level only allow to-one
        }

        result[ fieldProperties.name ] = this.processEntity( value, nextLevel, maxLevel, basicsOnly );
      }

    } else if( isStruct( data )) {
      var result = { };
      for( var key in data ) {
        var value = data[ key ];
        result[ key ] = this.processEntity( value, nextLevel, maxLevel, basicsOnly );
      }

    }

    return result;
  }

  public any function deOrm( any data, numeric level = 0, numeric maxLevel = 1, boolean basicsOnly = false ) {
    level = max( 0, level );
    maxLevel = min( 5, maxLevel );

    if( level == 0 ) {
      variables.utilityService.setCFSetting( "requesttimeout", 10 );
    }

    var useJsonService = variables.jsonService;

    if ( !isNull( variables.jsonJavaService ) && isObject( variables.jsonJavaService ) ) {
      useJsonService = variables.jsonJavaService;
    }

    if( isNull( data ) || ( maxLevel > 0 && level > maxLevel && !isSimpleValue( data ) ) ) {
      return;
    }

    var nextLevel = level + 1;
    var maxArrayItt = 100;
    var result = "";

    // data parsing:
    if( isSimpleValue( data ) ) {
      var result = data;
    } else if( isArray( data ) ) {
      var result = [ ];
      var itemCounter = 0;
      for( var el in data ) {
        if( ++itemCounter > maxArrayItt ) {
          arrayAppend( result, "capped at #maxArrayItt# results" );
          break;
        } else {
          var newData = deOrm( el, level, maxLevel, basicsOnly );
          if( !isNull( newData ) ) {
            arrayAppend( result, newData );
          }
        }
      }
    } else if( isObject( data ) ) {
      var allowedFieldTypes = "id,column,many-to-one,one-to-many,many-to-many"; // level 0 only

      if( level > 1 || basicsOnly ) {
        allowedFieldTypes = "id,column,many-to-one";
      }

      if( level >= maxLevel && !maxLevel == 0 ) {
        allowedFieldTypes = "id,column";
      }

      var result = { };
      var allFields = getInheritedProperties( data );

      for( var key in allFields ) {
        var fieldProperties = {
          "inapi" = true,
          "fieldtype" = "column",
          "dataType" = ""
        };

        structAppend( fieldProperties, allFields[ key ], true );

        if ( listFindNoCase( "numeric,string,boolean", fieldProperties.fieldtype ) ) {
          fieldProperties.fieldtype = "column";
        }

        if ( !fieldProperties.inapi ) {
          continue;
        }

        if ( !listFindNoCase( allowedFieldTypes, fieldProperties.fieldtype ) ) {
          continue;
        }

        if ( !structKeyExists( data, "get#fieldProperties.name#" ) ) {
          continue;
        }

        var value = variables.utilityService.cfinvoke( data, "get#fieldProperties.name#" );

        if( isNull( value ) ) {
          continue;
        }

        if( fieldProperties.dataType == "json" ) {
          try {
            structAppend( result, useJsonService.deserialize( value ) );
          } catch ( any e ) {
          }
          continue;
        }


        if( fieldProperties.fieldtype contains "to-many" ) {
          basicsOnly = true; // next level only allow to-one
        }

        result[ fieldProperties.name ] = deOrm( value, nextLevel, maxLevel, basicsOnly );
      }
    } else if( isStruct( data ) ) {
      var result = { };
      for( var key in data ) {
        var value = data[ key ];
        result[ key ] = deOrm( value, nextLevel, maxLevel, basicsOnly );
      }
    }

    return result;
  }

  /**
    * a struct containing this objects and its ancestors properties
    */
  public struct function getInheritedProperties( object ) {
    var md = getMetaData( object );
    var result = { };

    while ( structKeyExists( md, "extends" ) ) {
      if ( structKeyExists( md, "properties" ) && isArray( md.properties ) ) {
        var numberOfProperties = arrayLen( md.properties );

        for ( var i = 1; i <= numberOfProperties; i++ ) {
          var property = md.properties[ i ];

          if ( !structKeyExists( result, property.name ) ) {
            result[ property.name ] = { };
          }

          if ( structKeyExists( property, "cfc" ) ) {
            property.entityName = getEntityName( property.cfc );
            property.tableName = getTableName( property.cfc );
          }

          structAppend( result[ property.name ], property, false );
        }
      }
      md = md.extends;
    }

    return result;
  }

  public void function nil( ) {
  }

  public boolean function notEmpty( any variable ) {
    if( isNull( variable ) || !isSimpleValue( variable ) || !len( trim( variable ) ) ) {
      return false;
    }

    return true;
  }

  // conversion / mapping functions

  public array function xmlToArrayOfStructs( required any xmlSource, struct mapBy = { id = "id", name = "name" } ) {
    var result = [ ];

    if ( !isArray( xmlSource ) ) {
      xmlSource = [ xmlSource ];
    }

    if ( arrayIsEmpty( xmlSource ) ) {
      return [ ];
    }

    if ( structIsEmpty( mapBy ) ) {
      for ( var el in xmlSource[ 1 ].XmlChildren ) {
        mapBy[ el.xmlName ] = el.xmlName;
      }
    }

    for ( var item in xmlSource ) {
      var converted = { };
      for ( var key in mapBy ) {
        if ( structKeyExists( item, mapBy[ key ] ) ) {
          var value = item[ mapBy[ key ] ];

          if ( len( trim( value.XmlText ) ) ) {
            value = value.XmlText;
          } else if ( structKeyExists( value, "Items" ) && structKeyExists( value.Items, "XmlChildren" ) ) {
            value = xmlToArrayOfStructs( value.Items.XmlChildren, { } );
          } else {
            value = "";
          }

          converted[ key ] = value;
        }
      }
      arrayAppend( result, converted );
    }

    return result;
  }

  public any function xmlFilter( xml data, string xPathString = "//EntityTypes/PvEntityTypeData", struct filter ) {
    if ( !isNull( filter ) && !structIsEmpty( filter ) ) {
      var filters = [ ];
      for ( var key in filter ) {
        var values = listToArray( filter[ key ], "|" );

        if( arrayLen( values ) == 1 ) {
          arrayAppend( filters, '#key#="#xmlFormat( values[ 1 ] )#"' );
        } else {
          var multipleValues = __toXpathStringOr( values );
          arrayAppend( filters, '#key#[#multipleValues#]' );
        }
      }
      xPathString &= "[" & arrayToList( filters, " and " ) & "]";
    }

    return xmlSearch( data, xPathString );
  }

  public string function xmlFromStruct( struct source, string prefix = "", string namespace ) {
    var result = "";
    var ns = len( trim( prefix ) ) ? "#prefix#:" : "";
    var xmlns = !isNull( namespace ) && len( trim( namespace ) )
      ? ' xmlns="#namespace#"'
      : "";

    for ( var key in source ) {
      if ( !structKeyExists( source, key ) ) {
        result &= "<#ns##key##xmlns# />";
        continue;
      }

      var value = source[ key ];

      if ( isStruct( value ) ) {
        result &= "<#ns##key##xmlns#>" & xmlFromStruct( value, prefix ) & "</#ns##key#>";

      } else if ( isArray( value ) ) {
        result &= "<#ns##key##xmlns#>";
        for ( var item in value ) {
          result &= xmlFromStruct( item, prefix );
        }
        result &= "</#ns##key#>";

      } else if ( isSimpleValue( value ) ) {
        result &= "<#ns##key##xmlns#>#xmlFormat( value )#</#ns##key#>";

      }
    }

    return result;
  }

  /**
   * Convert a date in ISO 8601 format to a CFML date object.
   */
  public date function convertToCfDate( required string source ) {
    source = trim( source );

    var result = parseDateTime( reReplace( source, "(\d{4})-?(\d{2})-?(\d{2})T([\d:]+).*", "\1-\2-\3 \4" ) );

    if ( right( source, 1 ) == "Z" ) {
      result = dateConvert( "utc2local", result );
    }

    return result;
  }

  /**
   * Convert a CFML date object to an ISO 8601 formatted date string.
   * Output like this: 2014-07-08T12:05:25.8Z
   */
  public string function convertToIso8601( required date datetime, boolean convertToUTC = true ) {
    if ( convertToUTC ) {
      datetime = dateConvert( "local2utc", datetime );
    }
    return ( dateFormat( datetime, "yyyy-mm-dd" ) & "T" & timeFormat( datetime, "HH:mm:ss" ) & ".0Z" );
  }

  public string function convertToCfDatePart( required string part ) {
    var validDateParts = listToArray( "yyyy,q,m,d,w,ww,h,n,s" );

    if( arrayFindNoCase( validDateParts, part ) ) {
      return part;
    }

    switch( part ) {
      case 'years':     case 'year':    case 'y':   return validDateParts[ 1 ];
      case 'quarters':  case 'quarter':             return validDateParts[ 2 ];
      case 'months':    case 'month':               return validDateParts[ 3 ];
      case 'days':      case 'day':                 return validDateParts[ 4 ];
      case 'weekdays':  case 'weekday': case 'wd':  return validDateParts[ 5 ];
      case 'weeks':     case 'week':                return validDateParts[ 6 ];
      case 'hours':     case 'hour':                return validDateParts[ 7 ];
      case 'minutes':   case 'minute':              return validDateParts[ 8 ];
      case 'seconds':   case 'second':              return validDateParts[ 9 ];
    }

    throw( type = "dataService.convertToCFDatePart", message = "Invalid date part" );
  }

  public array function dataAsArray( data, xpath = "", filter = { }, map = { id = "id", name = "name" } ) {
    var filtered = xmlFilter( data, xpath, filter );
    return xmlToArrayOfStructs( filtered, map );
  }

  public boolean function isIso8601Date( required string value ) {
    var regex = "^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$";
    return reFind( regex, value );
  }

  /**
    * Builds nested structs into a single struct.
    * Updated v2 by author Simeon Cheeseman.
    * Updated v3 by author Mingo Hagen.
    * @param    stObject   Structure to flatten. (Required)
    * @param    delimiter  Value to use in new keys. Defaults to a period. (Optional)
    * @param    prefix     Value placed in front of flattened keys. Defaults to nothing. (Optional)
    * @param    stResult   Structure containing result. (Optional)
    * @param    addPrefix  Boolean value that determines if prefix should be used. Defaults to true. (Optional)
    * @return   Returns a structure.
    * @author   Tom de Manincor (tomdeman@gmail.com)
    * @version  2, September 2, 2011
    */
  public struct function flattenStruct( required struct original, string delimiter = ".", struct flattened = { }, string prefix_string = "" ) {
    var names = structKeyArray( original );

    for ( var name in names ) {
      if ( isStruct( original[ name ] ) ) {
        flattened = flattenStruct( original[ name ], delimiter, flattened, prefix_string & name & delimiter );
      } else {
        flattened[ prefix_string & name ] = original[ name ];
      }
    }

    return flattened;
  }

  public struct function mapToTemplateFields( data, template ) {
    var flattenedData = flattenStruct( data );
    var result = { };

    for ( var key in flattenedData ) {
      try {
        var mappedKey = evaluate( "template.#key#" );
        result[ mappedKey ] = flattenedData[ key ];
      } catch ( any e ) {
      }
    }

    return result;
  }

  public array function queryToTree( required query inputQuery, numeric parentId=0 ) {
    var asArrayOfStructs = queryToArrayOfStructs( inputQuery );
    var parents = { '#arguments.parentId#' = { "children" = [ ] } };

    for ( var row in asArrayOfStructs ) {
      parents[ row.menuId ] = row;
      parents[ row.menuId ].children = [ ];
    }

    for ( var row in asArrayOfStructs ) {
      if ( !structKeyExists( parents, row.parentId ) ) {
        continue;
      }

      var parent = parents[ row.parentId ];

      arrayAppend( parent.children, parents[ row.menuId ] );
    }

    return parents[ arguments.parentId ].children;
  }

  /** Converts query to an array full of structs
    *
    * @inputQuery    A ColdFusion query
    */
  public array function queryToArrayOfStructs( required query inputQuery ) {
    var result = [ ];
    var cols = inputQuery.getMeta( ).getColumnLabels( );
    var noOfCols = arrayLen( cols );

    for( var i = 1; i <= inputQuery.recordCount; i++ ) {
      var row = { };
      for( var j = 1; j <= noOfCols; j++ ) {
        var col = cols[ j ];
        row[ col ] = inputQuery[ col ][ i ];
      }
      arrayAppend( result, row );
    }

    return result;
  }

  // private functions

  private string function __formatAsGUID( required string text ) {
    var massagedText = reReplace( text, '\W', '', 'all' );

    if ( len( massagedText ) < 32 ) {
      return text; // return original (not my problem)
    }

    massagedText = insert( '-', massagedText, 20 );
    massagedText = insert( '-', massagedText, 16 );
    massagedText = insert( '-', massagedText, 12 );
    massagedText = insert( '-', massagedText, 8 );

    return massagedText;
  }

  private boolean function __isValidDate( required potentialDate ) {
    if ( __getClassName( potentialDate ) contains "date" ) {
      return true;
    }

    if ( !isSimpleValue( potentialDate ) ) {
      return false;
    }

    try {
      lsParseDateTime( potentialDate, getLocale( ) );
      return true;
    } catch ( any e ) {
      return false;
    }
  }

  /**
    * Returns a variable's underlying java Class name.
    * @param data A variable.
    */
  private string function __getClassName( required any data ) {
    try {
      return data.getClass( ).getName( );
    } catch ( any e ) {
      return "";
    }
  }

  private string function __toXpathStringOr( required array source ) {
    var result = [];

    for( var item in source ) {
      arrayAppend( result, ". = '" & xmlFormat( trim( item ) ) ) & "'";
    }

    return arrayToList( result, " or " );
  }
}
