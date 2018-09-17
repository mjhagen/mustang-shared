component accessors=true {
  // Taken from http://www.bennadel.com/blog/2528-asynctaskqueue-cfc---running-low-priority-tasks-in-a-single-cfthread.htm
  // de-ben-ified by mjhagen.

  property boolean runSingleThreaded;

  property logService;
  property utilityService;
  property taskQueue;
  property beanFactory;

  // constructor

  public component function init() {
    variables.taskQueue = [];
    variables.taskQueueID = lCase( createUUID() );
    variables.threadIndex = 1;
    variables.threadName = getNewAsyncThreadName();
    variables.isThreadRunning = false;
    variables.lockName = getAsyncTaskLockName();
    variables.lockTimeout = 30;

    param variables.runSingleThreaded = false;

    structAppend( variables, arguments, true );

    abortQueue();

    return this;
  }

  // public methods

  public component function getInstance() {
    return init( argumentCollection = arguments );
  }

  public void function addTask( required any taskMethod, any taskArguments = {} ) {
    if ( variables.runSingleThreaded ) {
      taskMethod( argumentCollection = taskArguments );
      return;
    }

    lock name=variables.lockName timeout=variables.lockTimeout {
      addNewTaskItem( taskMethod, taskArguments, variables.threadName );

      if ( variables.isThreadRunning ) {
        return;
      }

      variables.isThreadRunning = true;

      if ( !structKeyExists( server, 'lucee' ) ) {
        var threadfixService = variables.beanFactory.getBean( 'threadfix' );
        threadfixService.cacheScriptObjects();
      }

      thread action="run" name=variables.threadName priority="high" {
        do {
          lock name=variables.lockName timeout=variables.lockTimeout {
            var taskItem = getNextTaskItem();
          }

          while ( structKeyExists( local, 'taskItem' ) ) {
            try {
              taskItem.taskMethod( argumentCollection = taskItem.taskArguments );
            } catch ( any e ) {
              var exception = duplicate( e );
              variables.logService.writeLogLevel(
                'Error executing task (t. #variables.threadIndex#). (#exception.message#, #exception.detail#)',
                'asyncQueue',
                'error'
              );
              variables.logService.dumpToFile( exception, true, true );
              rethrow;
            }

            lock name=variables.lockName timeout=variables.lockTimeout {
              taskItem = getNextTaskItem();
            }
          }

          lock name=variables.lockName timeout=variables.lockTimeout {
            var isQueueEmpty = arrayIsEmpty( variables.taskQueue );
            var isQueueFull = !isQueueEmpty;

            if ( isQueueEmpty ) {
              variables.isThreadRunning = false;
              variables.threadName = getNewAsyncThreadName();
            }
          }
        } while ( isQueueFull );
      }
    }
  }

  public void function abortQueue() {
    lock name=variables.lockName timeout=variables.lockTimeout {
      for ( var queuedTasks in variables.taskQueue ) {
        try {
          thread action="terminate" name=queuedTasks.threadName;
        } catch ( any e ) {
        }
      }
      variables.taskQueue = [];
    }
  }

  // private methods

  private void function addNewTaskItem( required any taskMethod, required any taskArguments, required string threadName ) {
    if ( isArray( taskArguments ) ) {
      taskArguments = convertArgumentsArrayToCollection( taskArguments );
    }

    arrayAppend(
      variables.taskQueue,
      {
        'taskMethod' = taskMethod,
        'taskArguments' = taskArguments,
        'threadName' = threadName
      }
    );
  }

  private struct function convertArgumentsArrayToCollection( required array argumentsArray ) {
    var argumentsCollection = getEmptyArgumentsCollection();
    var numberOfArguments = arrayLen( argumentsArray );

    for ( var i = 1; i <= numberOfArguments; i++ ) {
      argumentsCollection[ i ] = argumentsArray[ i ];
    }

    return argumentsCollection;
  }

  private string function getAsyncTaskLockName() {
    return 'lock-#variables.taskQueueID#';
  }

  private any function getEmptyArgumentsCollection() {
    return arguments;
  }

  private string function getNewAsyncThreadName() {
    var index = ++variables.threadIndex;

    return 'thread-#variables.taskQueueID#-#index#';
  }

  private any function getNextTaskItem() {
    if ( arrayLen( variables.taskQueue ) ) {
      var taskItem = variables.taskQueue[ 1 ];

      arrayDeleteAt( variables.taskQueue, 1 );

      return taskItem;
    }
  }
}