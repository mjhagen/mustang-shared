component accessors=true {
  property logService;
  property dataService;

  // PUBLIC

  public component function saveEntity( required string entityName ) {
    var formData = getFormData( );

    // Load existing, or create a new entity
    if ( structKeyExists( formData, "#entityName#id" ) ) {
      var entityToSave = entityLoadByPK( entityName, formData[ "#entityName#id" ] );
    } else {
      var entityToSave = entityNew( entityName );
      entitySave( entityToSave );
    }

    var entityProperties = entityToSave.getInheritedProperties( );
    var inlineEditProperties = structFindKey( entityProperties, "inlineedit", "all" );

    // add inline form as sub items to be saved along side the main entity:
    for ( var property in inlineEditProperties ) {
      var property = property.owner;
      var fieldPrefix = property.name;
      var prefixedFields = reMatchNoCase( "#fieldPrefix#_[^,]+", form.FIELDNAMES );
      var inlineData = { };

      if ( !arrayIsEmpty( prefixedFields ) ) {
        var subclass = fieldPrefix;

        if( structKeyExists( form, "_#fieldPrefix#_subclass" ) ) {
          subclass = form[ "_#fieldPrefix#_subclass" ];
          inlineData[ "__subclass" ] = subclass;
        }

        var pkField = "#subclass#id";

        if ( structKeyExists( form, pkField ) ) {
          structDelete( formData, pkField );
          inlineData[ pkField ] = form[ pkField ];
        }

        for ( var field in prefixedFields ) {
          structDelete( formData, field );

          if ( structKeyExists( form, field ) && len( form[ field ] ) ) {
            inlineData[ listRest( field, "_" ) ] = form[ field ];
          }
        }

        if ( !structIsEmpty( inlineData ) ) {
          formData[ fieldPrefix ] = inlineData;
        }
      }
    }

    transaction {
      var result = entityToSave.save( formData );
    }

    logService.writeLogLevel( "Entity '#entityName#' saved" );

    return result;
  }

  public void function deleteEntity( required string entityName ) {
    changeEntityDeletedState( entityName, true );
  }

  public void function restoreEntity( required string entityName) {
    changeEntityDeletedState( entityName, false );
  }

  // PRIVATE

  private void function changeEntityDeletedState( required string entityName, required boolean state ) {
    var formData = getFormData( );

    transaction {
      var entityToDelete = entityLoadByPK( entityName, formData[ "#entityName#id" ] );

      if ( !isNull( entityToDelete ) ) {
        entityToDelete.save( { "deleted" = state } );

        if ( entityToDelete.propertyExists( "log" ) ) {
          var logentry = entityNew( "logentry", { relatedEntity = entityToDelete } );
          logentry.enterIntoLog( state?'deleted':'restored' );
        }
      }
    }

    logService.writeLogLevel( "Entity '#entityName#' marked as #state?'deleted':'restored'#" );
  }

  private struct function getFormData( ) {
    var formData = { };
    structAppend( formData, url, true );
    structAppend( formData, form, true );

    return formData;
  }
}