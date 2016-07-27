component accessors=true {
  property jsonService;

  // sanitation functions:

  public numeric function sanitizeNumericValue( required string source ) {
    var result = reReplace( source, '[^\d-\.]+', '', 'all' );

    if( isNumeric( result )) {
      return result;
    }

    throw( type="dataService.sanitizeNumericValue", message="Value could not be converted to a number.", detail="Original value: #source#." );
  }

  public numeric function sanitizePercentageValue( required string source ) {
    try {
      var result = sanitizeNumericValue( source );
    } catch ( dataService e ) {
      throw( type="dataService.sanitizePercentageValue", message=e.message, detail=e.detail );
    }

    if( val( result ) == 0 ) {
      return 0;
    }

    if( result > 100 ) {
      result = result / 100;
    }

    if( result > 1 ) {
      result = result / 100;
    }

    if( result < 0.01 ) {
      result = result * 100;
    }

    return result;
  }

  public date function sanitizeDateValue( required string source ) {
    // This method makes an educated guess about the date format
    var result = source;
    var dateFormats = {
          admy=[3,2,1],
          bmdy=[3,1,2],
          cymd=[1,2,3]
        };

    try {
      source = reReplace( source, '\D+', '-', 'all' );

      if( !listLen( source, '-' ) >= 3 ) {
        if( __isValidDate( source )) {
          return source;
        }

        throw( type="dataService.sanitizeDateValue", message="Error sanitizing date string (#source#).", detail="Could not detect date format in '#source#'" );
      }

      if( arrayLen( arguments ) >= 2) {
        // Use the provided date formatter:
        dateFormats = {
          "#arguments[2]#" = dateFormats[arguments[2]]
        };
      } else {
        if( len( listGetAt( source, 1, '-' )) == 4 ) {
          // last item can't be the YEAR
          structDelete( dateFormats, 'bmdy' );
          structDelete( dateFormats, 'admy' );
        }

        if( len( listGetAt( source, 3, '-' )) == 4) {
          // last item is probably the YEAR
          structDelete( dateFormats, 'cymd' );
        }

        if( listGetAt( source, 1, '-' ) > 12) {
          // first item can't be the MONTH
          structDelete( dateFormats, 'bmdy' );
        }

        if( listGetAt( source, 2, '-' ) > 12) {
          // second item can't be the MONTH
          structDelete( dateFormats, 'admy' );
          structDelete( dateFormats, 'cymd' );
        }
      }

      var sortedKeys = listToArray( listSort( structKeyList( dateFormats ), 'text' ));

      for( var key in sortedKeys ) {
        var currentDateFormat = dateFormats[key];

        result = createDate(
          listGetAt( source, currentDateFormat[1], '-' ),
          listGetAt( source, currentDateFormat[2], '-' ),
          listGetAt( source, currentDateFormat[3], '-' )
        );

        try {
          var testDate = lsDateFormat( result, 'dd/mm/yyyy' );
          return result;
        } catch ( any e ) {}
      }

      return result;
    } catch ( any e ) {
      rethrow;
    }

    throw( type="dataService.sanitizeDateValue", message="Value could not be converted to a date.", detail="Original value: #source#." );
  }

  public integer function sanitizeIntegerValue( required string source ) {
    try {
      var result = int( sanitizeNumericValue( source ));
    } catch ( dataService e ) {
      throw( type="dataService.sanitizePercentageValue", message=e.message, detail=e.detail );
    }

    if( isValid( "integer", result )) {
      return javaCast( "int", result );
    }

    throw( type="dataService.sanitizeIntegerValue", message="Value could not be converted to an integer.", detail="Original value: #source#." );
  }

  // other data integrity and utility functions:

  public boolean function isGUID( required string text ) {
    if( len( text ) < 32 ) {
      return false;
    }

    var validGUID = isValid( "guid", text );

    if( validGUID ) {
      return true;
    }

    return isValid( "guid", __formatAsGUID( text ));
  }

  // convenience functions

  public any function processEntity( any data,
                                 numeric level=0,
                                 numeric maxLevel=0 ) {
    if( isNull( data )) {
      return;
    }

    // doesn't work on non-basecfc objects
    if( isObject( data ) && !structKeyExists( data, "getID" )) {
      return;
    }

    // beyond maxLevel depth, only return ID and name (or the value if it's a string)
    if( maxLevel != 0 && level >= maxLevel ) {
      if( isObject( data ) && structKeyExists( data, "getID" )) {
        return data.getID();
      } else if ( !isSimpleValue( data )) {
        return;
      }
    }

    // object caching:
    if( level == 0 ) {
      request.cacheID = createUUID();
    }

    param request.objCache={};

    if( !structKeyExists( request.objCache, request.cacheID )) {
      request.objCache[request.cacheID] = {};
    }

    var cache = request.objCache[request.cacheID];

    try {

      // data parsing:
      if( isSimpleValue( data )) {
        var result = data;

      } else if( isObject( data )) {
        var result = {};
        var md = getMetadata( data );

        if( structKeyExists( data, "getID" ) && structKeyExists( cache, data.getID())) {
          result = cache[data.getID()];
        } else {
          do {
            if( structKeyExists( md, "properties" )) {
              for( var i=1; i<=arrayLen( md.properties ); i++ ) {
                var prop = md.properties[i];

                param boolean prop.inapi=true;
                param string prop.fieldtype="column";

                if( prop.inapi && structKeyExists( data, "get" & prop.name )) {
                  var allowedFieldTypes = "id,column,many-to-one,many-to-many,one-to-many";

                  if( level >= 3 ) {
                    allowedFieldTypes = "id,column,many-to-one";
                  }

                  if( level >= 4 ) {
                    allowedFieldTypes = "id,column";
                  }

                  if( level >= 4 && !listFindNoCase( "id,name", prop.name )) {
                    continue;
                  }

                  if( listFindNoCase( allowedFieldTypes, prop.fieldtype )) {
                    var value = evaluate( "data.get#prop.name#()" );
                    if( !isNull( value )) {
                      if( isObject( value ) && structKeyExists( value, "getID" ) && structKeyExists( cache, value.getID())) {
                        continue;
                      } else if( structKeyExists( prop, "dataType" ) && prop.dataType == "json" ) {
                        structAppend( result, jsonService.deserialize( value ));
                      } else {
                        result[prop.name] = processEntity( value, level + 1, maxLevel );
                      }
                    }
                  }
                }
              }
            }

            if( structKeyExists( md, "extends" )) {
              md = md.extends;
            }
          } while( structKeyExists( md, "extends" ) && structKeyExists( md, "properties" ));

          cache[data.getID()] = result;
        }

      } else if( isArray( data )) {
        var result = [];
        var itemCounter = 0;

        for( var i = 1; i <= arrayLen( data ); i++ ) {
          var el = data[i];
          var newData = processEntity( el, level + 1, maxLevel );

          if( !isNull( newData )) {
            itemCounter++;

            if( itemCounter > 100 ) {
              arrayAppend( result, "capped at 100 results" );
              break;
            }

            arrayAppend( result, newData );
          }
        }

      } else if( isStruct( data )) {
        var result = {};
        for( var key in data ) {
          result[key] = processEntity( data[key], level + 1, maxLevel );
        }

      }

      return result;
    } catch ( any e ) {
      return;
    }
  }

  public void function nil() {
  }

  // XML conversion functions

  public array function xmlToArrayOfStructs( required any xmlSource, required struct mapBy={id="id",name="name"} ) {
    var result = [];

    if( !isArray( xmlSource )) {
      xmlSource = [ xmlSource ];
    }

    if( arrayIsEmpty( xmlSource )) {
      return [];
    }

    if( structIsEmpty( mapBy )) {
      for( var el in xmlSource[ 1 ].XmlChildren ) {
        mapBy[ el.xmlName ] = el.xmlName;
      }
    }

    for( var item in xmlSource ) {
      var converted = {};
      for( var key in mapBy ) {
        if( structKeyExists( item, mapBy[ key ])) {
          var value = item[ mapBy[ key ]];

          if( len( trim( value.XmlText ))) {
            value = value.XmlText;
          } else if( structKeyExists( value, "Items" ) && structKeyExists( value.Items, "XmlChildren" )) {
            value = xmlToArrayOfStructs( value.Items.XmlChildren, {} );
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

  public any function xmlFilter( xml data, string xPathString="//EntityTypes/PvEntityTypeData", struct filter ) {
    if( !isNull( filter ) && !structIsEmpty( filter )) {
      var filters = [];
      for( var key in filter ) {
        arrayAppend( filters, '#key#="#filter[key]#"' );
      }
      xPathString &= "[" & arrayToList( filters, " and " ) & "]";
    }
    return xmlSearch( data, xPathString );
  }

  public string function xmlFromStruct( struct source, string prefix="", string namespace="" ) {
    var result = "";
    var ns = len( trim( prefix )) ? "#prefix#:" : "";
    var xmlns = len( trim( namespace )) ? ' xmlns="#namespace#"' : ""; // only on first element

    for( var key in source ) {
      if( isSimpleValue( source[ key ] )) {
        result &= "<#ns##key##xmlns#>#source[ key ]#</#ns##key#>";
      } else if( isStruct( source[ key ] )) {
        result &= "<#ns##key##xmlns#>" & xmlFromStruct( source[ key ], prefix ) & "</#ns##key#>";
      } else if( isArray( source[ key ] )) {
        for( var item in source[ key ] ) {
          result &= "<#ns##key##xmlns#>" & xmlFromStruct( item, prefix ) & "</#ns##key#>";
        }
      }
    }

    return result;
  }

  // private functions

  private string function __formatAsGUID( required string text ) {
    var massagedText = reReplace( text, '\W', '', 'all' );

    if( len( massagedText ) < 32 ) {
      return text; // return original (not my problem)
    }

    massagedText = insert( '-', massagedText, 20 );
    massagedText = insert( '-', massagedText, 16 );
    massagedText = insert( '-', massagedText, 12 );
    massagedText = insert( '-', massagedText, 8 );

    return massagedText;
  }

  private boolean function __isValidDate( required potentialDate ) {
    if( __getClassName( potentialDate ) contains "date" ) {
      return true;
    }

    if( !isSimpleValue( potentialDate )) {
      return false;
    }

    try {
      lsParseDateTime( potentialDate, getLocale());
      return true;
    } catch ( any e ) {
      return false;
    }
  }

  /** Returns a variable's underlying java Class name.
    *
    * @data A variable.
    */
  private string function __getClassName( required any data ) {
    try {
      return data.getClass().getName();
    } catch( any e ) {
      return "";
    }
  }
}