#include "config.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <utime.h>
#include <assert.h>

#include <openssl/rand.h>

#include <mysql.h>

#include "fbase64.h"
#include "mkcookie.h"
#include "rate.h"

/* These three for COSIGN_MAXFACTORS. Shame we have to include openssl
   for that! */
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "srvcookiefs.h"

/* grabbed from monster.h. including monster.h is...problematic. */
struct connlist {
    struct sockaddr_in  cl_sin;
    SNET                *cl_sn;
    SNET                *cl_psn;
    struct connlist     *cl_next;
    union {
        time_t          cu_last_time;
#define cl_last_time    cl_u.cu_last_time
        pid_t           cu_pid;
#define cl_pid          cl_u.cu_pid
    } cl_u;
    struct rate         cl_pushpass;
    struct rate         cl_pushfail;
};


static int l_initialized = 0;
static MYSQL *l_sql = NULL;
static MYSQL *l_sock = NULL;

extern char                    *mysql_user;
extern char                    *mysql_pass;
extern char                    *mysql_database;
extern char                    *mysql_server;
extern char                    *mysql_tlskey;
extern char                    *mysql_tlscert;
extern char                    *mysql_tlsca;
extern int                     mysql_usessl;
extern int                     mysql_portnum;

#define BIND_LONG(x, y ) {                      \
    (x).buffer_type = MYSQL_TYPE_LONG;		\
    (x).buffer = (char *)&(y); }
#define BIND_STRING(x, y, y_sz, z) {     \
    assert((y_sz) != 4 );                \
    (x).buffer_type = MYSQL_TYPE_STRING; \
    (x).buffer = (char *)y;              \
    (x).buffer_length = y_sz;            \
    x.length = &z; }

/* These should really be in the outer project. */
enum {
  kLOGGED_OUT = 0,
  kACTIVE = 1
};

/* forward declarations */
int cookiedb_mysql_init( char *, int );
void cookiedb_mysql_destroy( );
int cookiedb_mysql_validate( char[255],int, int );
int cookiedb_mysql_logout( char[255] );
int cookiedb_mysql_read( char[255], struct cinfo * );
int cookiedb_mysql_write_login( char[255], struct cinfo * );
int cookiedb_mysql_register( char[255], char[255], char *[], int );
int cookiedb_mysql_service_to_login( char[255], char[255] );
int cookiedb_mysql_delete( char[255] );
int cookiedb_mysql_taste_cookies( void *head, struct timeval *now );
int cookiedb_mysql_eat_cookie( char[255], struct timeval *, time_t *, int *, int, int, int );
int cookiedb_mysql_touch( char[255] );
int cookiedb_mysql_touch_factor( char *, char[256], int );
int cookiedb_mysql_idle_out_factors( char[255], char[256], unsigned int );
int cookiedb_mysql_rename_cookie( char *, char * );

/* Dispatch table */
struct cfs_funcs mysql_cfs = { cookiedb_mysql_init,
			       cookiedb_mysql_destroy,
			       cookiedb_mysql_validate,
			       cookiedb_mysql_logout,
			       cookiedb_mysql_read,
			       cookiedb_mysql_write_login,
			       cookiedb_mysql_register,
			       cookiedb_mysql_service_to_login,
			       cookiedb_mysql_taste_cookies,
			       cookiedb_mysql_delete,
			       cookiedb_mysql_eat_cookie,
			       cookiedb_mysql_touch,
			       cookiedb_mysql_touch_factor,
			       cookiedb_mysql_idle_out_factors,
			       cookiedb_mysql_rename_cookie };

struct cfs_funcs *cookiefs = &mysql_cfs;


static
MYSQL_STMT *prepare( const char *query, MYSQL_BIND *bind, int num_binds )
{
  MYSQL_STMT *q = NULL;

  q = mysql_stmt_init( l_sql );
  if ( q == NULL ) {
    syslog( LOG_ERR, "prepare: unable to init stmt" );
    return( NULL );
  }

  if ( mysql_stmt_prepare( q, query, strlen(query) ) ) {
    syslog( LOG_ERR, "prepare: mysql_stmt_prepare failed: %s", 
	    mysql_stmt_error( q ) );
    goto error;
  }

  /* Validate # of params */
  if ( mysql_stmt_param_count( q ) != num_binds ) {
    syslog( LOG_ERR, "prepare: param validation error" );
    goto error;
  }

  if ( mysql_stmt_bind_param( q, bind ) ) {
    syslog( LOG_ERR, "prepare: mysql_stmt_bind_param() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  return( q );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( NULL );
}


static
int record_exists_by_single_value( const char *template, const char *value )
{
  unsigned long long num_rows;
  MYSQL_STMT *q = NULL;
  unsigned long param_length;
  MYSQL_BIND bind[ 1 ];
  char param[ 256 ];

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], param, sizeof( param ), param_length );

  strncpy( param, value, sizeof( param ) );
  param_length = strlen( param );

  q = prepare( template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, "record_exists: unable to prepare" );
    return( -1 );
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "record_exists: failed to execute query: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  if ( mysql_stmt_store_result( q ) ) {
    syslog( LOG_ERR, 
	    "record_exists: mysql_stmt_store_result failed" );
    goto error;
  }
  num_rows = mysql_stmt_num_rows( q );

  mysql_stmt_close( q );
  return ( num_rows != 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

static
int record_exists_by_two_values( const char *template, const char *value1,
				 const char *value2 )
{
  unsigned long long num_rows;
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  unsigned long param1_length;
  char param1[ 256 ];
  unsigned long param2_length;
  char param2[ 256 ];

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], param1, sizeof( param1 ), param1_length );
  BIND_STRING( bind[ 1 ], param2, sizeof( param2 ), param2_length );

  strncpy( param1, value1, sizeof( param1 ) );
  param1_length = strlen( param1 );
  strncpy( param2, value2, sizeof( param2 ) );
  param2_length = strlen( param2 );

  q = prepare( template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR, "record_exists: unable to prepare" );
    return( -1 );
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "record_exists: failed to execute query: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  if ( mysql_stmt_store_result( q ) ) {
    syslog( LOG_ERR, 
	    "record_exists: mysql_stmt_store_result failed" );
    goto error;
  }
  num_rows = mysql_stmt_num_rows( q );

  mysql_stmt_close( q );
  return ( num_rows != 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

    void
cookiedb_mysql_destroy( )
{
    if ( l_initialized ) {
	if ( l_sock == l_sql ) {
	    l_sql = NULL;
	}
	if ( l_sock ) {
	    mysql_close( l_sock );
	}
	if ( l_sql ) {
	    mysql_close( l_sql );
	}
	l_initialized = 0;
    }
}

    int
cookiedb_mysql_init( char *prefix, int hashlen )
{
  my_bool		reconnect = 1;

  l_sql = mysql_init(NULL);
  if ( !l_sql) {
    syslog( LOG_ERR, "unable to mysql_init"  );
    return ( -1 );
  }

  if ( mysql_usessl ) {
    if (mysql_ssl_set( l_sql, 
		       mysql_tlskey,
		       mysql_tlscert,
		       mysql_tlsca,
		       NULL,                      // path to CA directory
		       NULL                       // list of allowed ciphers
		       ) ) {
      syslog( LOG_ERR, "Unable to configure SSL" );
      return ( -1 );
    }
  }

  /*
   * try reconnecting if the server goes away.
   *
   * we set MYSQL_OPT_RECONNECT twice, once before and once after we call
   * mysql_real_connect due to inconsistencies across revisions of the
   * mysql client libraries. See:
   *
   * http://dev.mysql.com/doc/refman/5.1/en/mysql-options.html
   */
  mysql_options( l_sql, MYSQL_OPT_RECONNECT, &reconnect );
  if (! (l_sock = mysql_real_connect( l_sql,
				      mysql_server,
				      mysql_user,
				      mysql_pass,
				      mysql_database,
				      mysql_portnum,
				      NULL,       // unix socket (NULL=default)
				      mysql_usessl ? CLIENT_SSL : 0
				      ) ) ) {
    syslog( LOG_ERR, "Unable to connect to database server" );
    return ( -1 );
  }
  mysql_options( l_sql, MYSQL_OPT_RECONNECT, &reconnect );
  l_initialized = 1;
  return( 0 );
}

/* Return 0 if a given cookie is valid. Return -1 for any failures. 
 * Also update the last-used timestamp of the record. Return 1 if the row
 * does not exist.
 */
    int
cookiedb_mysql_validate( char cookie[255], int timestamp, int state )
{
  const char *select_template = "SELECT ci_itime,ci_state FROM login_cookies "
                                "WHERE login_cookie=?";
  const char *update_template = "UPDATE login_cookies SET ci_itime=? "
                                "WHERE login_cookie=?";
  int sql_state = kLOGGED_OUT;

  MYSQL_STMT *q = NULL;
  unsigned long str_length;
  MYSQL_BIND bind[ 2 ];
  unsigned long int time_param;
  MYSQL_BIND result[ 2 ];
  unsigned long int itime_result;
  char state_result[ 100 ];
  unsigned long state_result_length;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], cookie, 255, str_length );

  str_length = strlen( cookie );

  q = prepare( select_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: unable to prepare select" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  memset( result, 0, sizeof( result ) );
  BIND_LONG  ( result[ 0 ], itime_result );
  BIND_STRING( result[ 1 ], state_result, sizeof( state_result ), state_result_length );

  if ( mysql_stmt_bind_result( q, result ) != 0 ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_validate: mysql_stmt_bind_result failed" );
    goto error;
  }

  /* Don't have to fetch the entire row set into memory; we just care about
   * the first row. */

  if ( mysql_stmt_fetch( q ) != 0 ) {
    /* No rows match, or an error occurred. Future enhancement: see if it's
     * MYSQL_NO_DATA, 1 (mysql_stmt_error() would be set), or 
     * MYSQL_DATA_TRUNCATED. */
    goto ret1;
  }

  sql_state = state_result[0] == 'l' ? kLOGGED_OUT : kACTIVE;

 /* ... if the timestamp in the cookie <  timestamp, then we need to update 
  * the record. So get the timestamp out of the query we just performed. The 
  * original query was for just timestamp, and the timestamp was at index 0,
  * so we don't have to do anything crazy to look up the proper index...
  */
 
  if ( itime_result < timestamp ) {
    mysql_stmt_close( q );
   
    memset( bind, 0, sizeof( bind ) );
    BIND_LONG  ( bind[ 0 ], time_param );
    BIND_STRING( bind[ 1 ], cookie, 255, str_length );
    
    time_param = timestamp;
    str_length = strlen( cookie );
    
    q = prepare( update_template, bind, 2 );
    if ( !q ) {
      syslog( LOG_ERR, "cookiedb_mysql_validate: failed to prepare update" );
      goto error;
    }
    
    
    if ( mysql_stmt_execute( q ) ) {
      syslog( LOG_ERR, "cookiedb_mysql_validate: "
	      "mysql_stmt_execute() failed: %s",
	      mysql_stmt_error( q ) );
      goto error;
    }
  }
  
  /* if state==0 && the cookie's record doesn't indicate 'logged out', then
     log 'em out.
  */
  if ( ( state == 0 ) && sql_state != kACTIVE) {
    return cookiedb_mysql_logout( cookie );
  }
  
  if ( q )
    mysql_stmt_close( q );
  return( 0 );
 
 ret1:
  if ( q )
    mysql_stmt_close( q );
  return( 1 );
 error:
  if ( q ) 
    mysql_stmt_close( q );
  return( -1 );
}

    int
cookiedb_mysql_logout( char cookie[255] )
{
  const char *logout_template = "UPDATE login_cookies "
    "SET ci_state='logged out' "
    "WHERE login_cookie=?";
  MYSQL_STMT *q = NULL;
  unsigned long str_length;
  MYSQL_BIND bind[ 1 ];

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiedb_mysql_logout: not initialized" );
	return( -1 );
    }

    memset( bind, 0, sizeof( bind ) );
    BIND_STRING( bind[ 0 ], cookie, 255, str_length );

    str_length = strlen( cookie );

    q = prepare( logout_template, bind, 1 );
    if ( !q ) {
      syslog( LOG_ERR, 
	      "cookiedb_mysql_logout: failed to prepare query" );
      goto error;
    }

    if ( mysql_stmt_execute( q ) ) {
      syslog( LOG_ERR, "cookiedb_mysql_logout: "
	      "mysql_stmt_execute() failed: %s",
	      mysql_stmt_error( q ) );
      goto error;
    }

    if ( q ) {
      mysql_stmt_close( q );
    }
    return( 0 );
 error:
    if ( q ) {
      mysql_stmt_close( q );
    }
    return( -1 );
}

/* return 0 for success, -1 for error, and 1 if the cookie wasn't found */
    int
cookiedb_mysql_read( char cookie[255], struct cinfo *ci )
{
  const char *read_template = "SELECT ci_itime, ci_state, ci_version, "
    "ci_ipaddr,ci_ipaddr_cur,ci_user,ci_ctime,ci_krbtkt "
    " FROM login_cookies WHERE login_cookie=?";
  const char *read_factor_template = "SELECT factor "
      "FROM factor_timeouts "
      "WHERE login_cookie=? "
      "ORDER BY id";
  int sz, left, fr, rows;
  char *p;
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 1 ];
  unsigned long str_length;
  MYSQL_BIND result[ 8 ];
  unsigned long int itime_result;
  char state_result[ 11 ]; // strlen("logged out") + 1
  unsigned long state_result_length;
  unsigned long int version_result;
  unsigned long ipaddr_result_length;
  unsigned long ipaddr_cur_result_length;
  unsigned long user_result_length;
  unsigned long ctime_result_length;
  unsigned long krbtkt_result_length;
  MYSQL_BIND factor_result[ 1 ];
  char a_factor[ 256 ];
  unsigned long factor_result_length;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_read: not initialized" );
    return( -1 );
  }
  
  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], cookie, 255, str_length );

  str_length = strlen( cookie );
  
  q = prepare( read_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_read: failed to prepare" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_read: failed to execute: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  memset( result, 0, sizeof( result ) );
  BIND_LONG  ( result[ 0 ], itime_result );
  BIND_STRING( result[ 1 ], state_result, sizeof( state_result ), state_result_length );
  BIND_LONG  ( result[ 2 ], version_result );
  BIND_STRING( result[ 3 ], ci->ci_ipaddr, sizeof( ci->ci_ipaddr ), ipaddr_result_length );
  BIND_STRING( result[ 4 ], ci->ci_ipaddr_cur, sizeof( ci->ci_ipaddr_cur ), ipaddr_cur_result_length );
  BIND_STRING( result[ 5 ], ci->ci_user, sizeof( ci->ci_user ), user_result_length );
  BIND_STRING( result[ 6 ], ci->ci_ctime, sizeof( ci->ci_ctime ), ctime_result_length );
  BIND_STRING( result[ 7 ], ci->ci_krbtkt, sizeof( ci->ci_krbtkt ), krbtkt_result_length );

  if ( mysql_stmt_bind_result( q, result ) != 0 ) {
    syslog( LOG_ERR, "cookiedb_mysql_read: mysql_stmt_bind_result failed" );
    goto error;
  }

  if ( mysql_stmt_fetch( q ) != 0 ) {
    /* This may be benign; there is no login data for that cookie. */

    /* Future enhancement: look at other possible return values, like
       truncation */

    goto ret1;
  }

  ci->ci_version = version_result;
  ci->ci_state = state_result[0] == 'l' ? kLOGGED_OUT : kACTIVE;
  ci->ci_itime = itime_result;

  /* Get all of the factors and put them into ci->ci_realm. Construct the
   * query, get the data, and then carefully construct the string. */

  mysql_stmt_close( q );

  q = prepare( read_factor_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, "cookiedb_mysql_read: unable to prepare factor query" );
    goto error;
  }

  /* Data value should still be valid from previous query */

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR,
            "cookiedb_mysql_read: failed to execute factor query: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  memset( factor_result, 0, sizeof( factor_result ) );
  BIND_STRING( factor_result[ 0 ], a_factor, sizeof( a_factor ), factor_result_length );

  if ( mysql_stmt_bind_result( q, factor_result ) != 0 ) {
      syslog( LOG_ERR, "cookiedb_mysql_read: mysql_stmt_bind_result failed" );
      goto error;
  }

  rows = 0; 
  ci->ci_realm[ 0 ] = '\0';
  left = sizeof( ci->ci_realm );
  p = ci->ci_realm;
  while (( fr = mysql_stmt_fetch( q )) == 0 ) {
      rows++;
      if ( left <= strlen( a_factor ) + 1 ) { /* +1 for space; <= for NUL */
	  syslog( LOG_ERR, 
		  "cookiedb_mysql_read: insufficient buffer space for factor list" );
	  goto error;
      }
      sz = sprintf( p, "%s ", a_factor );
      p += sz;
      left -= sz;
  }
  if ( fr != MYSQL_NO_DATA ) {
      if ( fr == MYSQL_DATA_TRUNCATED ) {
	  syslog( LOG_ERR, "cookiedb_mysql_read: mysql_stmt_fetch returned "
			   "truncated data\n" );
      } else {
	  syslog( LOG_ERR, "cookiedb_mysql_read: mysql_stmt_fetch failed: "
			   "%s\n", mysql_stmt_error( q ));
      }
      goto error;
  }
  if ( rows == 0 ) {
      syslog( LOG_ERR, "cookiedb_mysql_read: mysql_stmt_fetch: no matching "
		       "rows for read_factor query\n" );
      goto error;
  }

  /* Remove trailing space */
  if ( p != ci->ci_realm && *(p-1) == ' ' ) {
      *(p-1) = '\0';
  }
  
    if ( q ) {
      mysql_stmt_close( q );
    }
    return( 0 );
 ret1:
    if ( q ) {
      mysql_stmt_close( q );
    }
    return( 1 );
 error:
    if ( q ) {
      mysql_stmt_close( q );
    }
    return( -1 );
}

    int
cookiedb_mysql_write_login( char cookie[255], struct cinfo *ci )
{
  const char *exists_template = "SELECT ci_itime FROM login_cookies "
    "WHERE login_cookie=?";
  const char *update_template = "UPDATE login_cookies SET ci_itime=?, "
    "ci_state = 'active', ci_version=?, ci_ipaddr=?, "
    "ci_ipaddr_cur=?, ci_user=?, ci_ctime=?, "
    "ci_krbtkt=? WHERE login_cookie=?";
  const char *insert_template = "INSERT INTO login_cookies SET ci_itime=?, "
    "ci_state = 'active', ci_version=?, ci_ipaddr=?, "
    "ci_ipaddr_cur=?, ci_user=?, ci_ctime=?, "
    "ci_krbtkt=?, login_cookie=?";

  char *factor;
  const char *template;

  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 8 ];
  unsigned long int ci_itime_param;
  unsigned long int ci_version_param;
  unsigned long ci_ipaddr_length;
  unsigned long ci_ipaddr_cur_length;
  unsigned long ci_user_length;
  unsigned long ci_ctime_length;
  unsigned long ci_krbtkt_length;
  unsigned long cookie_length;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_write_login: not initialized" );
    return( -1 );
  }

  /* See if the record already exists. If it does, we'll update it. If not, 
   * we'll insert a new one. */

  switch ( record_exists_by_single_value(exists_template, cookie) ) {
  case 0:
      /* Perform an insert. */
      template = insert_template;
      break;
  case 1:
      /* Perform an update. */
      template = update_template;
      break;
  default:
      /* already syslogged an error */
      return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_LONG  ( bind[ 0 ], ci_itime_param );
  BIND_LONG  ( bind[ 1 ], ci_version_param );
  BIND_STRING( bind[ 2 ], ci->ci_ipaddr, sizeof( ci->ci_ipaddr ), ci_ipaddr_length );
  BIND_STRING( bind[ 3 ], ci->ci_ipaddr_cur, sizeof( ci->ci_ipaddr_cur ), ci_ipaddr_cur_length );
  BIND_STRING( bind[ 4 ], ci->ci_user, sizeof( ci->ci_user ), ci_user_length );
  BIND_STRING( bind[ 5 ], ci->ci_ctime, sizeof( ci->ci_ctime ),  ci_ctime_length );
  BIND_STRING( bind[ 6 ], ci->ci_krbtkt, sizeof( ci->ci_krbtkt ), ci_krbtkt_length );
  BIND_STRING( bind[ 7 ], cookie, 255, cookie_length );

  ci_itime_param = time( NULL );
  ci_version_param = ci->ci_version;
  ci_ipaddr_length = strlen( ci->ci_ipaddr );
  ci_ipaddr_cur_length = strlen( ci->ci_ipaddr_cur );
  ci_user_length = strlen( ci->ci_user );
  ci_ctime_length = strlen( ci->ci_ctime );
  ci_krbtkt_length = strlen( ci->ci_krbtkt );
  cookie_length = strlen( cookie );

  q = prepare( template, bind, 8 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_write_login: failed to prepare template" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_write_login: failed to execute" );
    goto error;
  }

  for ( factor = strtok( ci->ci_realm, " " );
	    factor != NULL;
	    factor = strtok( NULL, " " ) ) {
      if ( cookiedb_mysql_touch_factor( cookie, factor, 0 ) != 0 ) {
	  /* already syslogged an error */
	goto error;
      }
  }

  if ( q ) {
    mysql_stmt_close( q );
  }
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

    int
cookiedb_mysql_register( char lcookie[255], char scookie[255], 
			 char *factors[], int num_factors )
{
  const char *exists_template = "SELECT login_cookie FROM service_cookies "
    "WHERE service_cookie=?";
  const char *update_template = "UPDATE service_cookies SET "
    "login_cookie=? where service_cookie=?";
  const char *insert_template = "INSERT INTO service_cookies "
    "SET login_cookie=?, service_cookie=?";

  const char *template;
  int i;
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  unsigned long lcookie_length;
  unsigned long scookie_length;


  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_register: not initialized" );
    return( -1 );
  }

  switch ( record_exists_by_single_value(exists_template, scookie) ) {
  case 0:
      /* Perform an insert. */
      template = insert_template;
      break;
  case 1:
      /* Perform an update. */
      template = update_template;
      break;
  default:
      /* Already syslogged an error. */
      return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], lcookie, 255, lcookie_length );
  BIND_STRING( bind[ 1 ], scookie, 255, scookie_length );

  lcookie_length = strlen( lcookie );
  scookie_length = strlen( scookie );

  q = prepare( template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR, "cookiedb_mysql_register: unable to prepare" );
    return( -1 );
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_register: failed to execute: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  for ( i = 0; i < num_factors; i++ ) {
      if ( cookiedb_mysql_touch_factor( lcookie, factors[ i ], 0 ) != 0 ) {
	  syslog( LOG_ERR, "cookiedb_mysql_register: failed to touch factor %s\n", 
		  factors[ i ] );
	  goto error;
      }
  }

  mysql_stmt_close( q );
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return(-1);
}

    int
cookiedb_mysql_service_to_login( char cookie[255], char login[255] )
{
  const char *query_template = "SELECT login_cookie FROM "
    "service_cookies "
    "WHERE service_cookie=?";

  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 1 ];
  unsigned long cookie_length;
  MYSQL_BIND result[ 1 ];
  unsigned long login_length;
  

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_service_to_login: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], cookie, 255, cookie_length );

  cookie_length = strlen( cookie );

  q = prepare( query_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_service_to_login: failed to prepare" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_service_to_login: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  memset( result, 0, sizeof( result ) );
  BIND_STRING( result[ 0 ], login, 255, login_length );

  if ( mysql_stmt_bind_result( q, result ) != 0 ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_service_to_login: mysql_stmt_bind_result failed" );
    goto error;
  }

  if ( mysql_stmt_fetch( q ) != 0 ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_service_to_login: unable to retrieve row data" );
    goto error;
  }

  mysql_stmt_close( q );
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

    int
cookiedb_mysql_taste_cookies( void *head, struct timeval *now )
{
    /*
     * query ci_state in a numeric context to get back the index of
     * the ENUM column value, so we can avoid dealing with strings.
     *
     * ENUM column 1: 'logged out'
     * ENUM column 2: 'active'
     */
    const char		*template = "SELECT login_cookie, ci_itime, "
					"ci_state + 0 "
					"FROM login_cookies "
					"WHERE ci_itime > ? "
					"LIMIT 100000";
    MYSQL_STMT		*q = NULL;
    MYSQL_BIND		bind[ 1 ];
    MYSQL_BIND		result[ 3 ];
    char		cookie[ 255 ];
    unsigned long	itime_limit = now->tv_sec + 86400;
    unsigned long	itime = 0;
    unsigned long	state = 0;
    unsigned long	cookie_len = 0;
    int			fr, rows;
    int			login_sent = 0;
    struct connlist	*yacur;

    /* set WHERE value to min of 43200 (hard session timeout at upenn)
    and max connection list's last itime. */
    for ( yacur = (struct connlist *)head; yacur != NULL;
		yacur = yacur->cl_next ) {
	if ( yacur->cl_last_time < itime_limit ) {
	    itime_limit = yacur->cl_last_time;
	}
    }
    if ( itime_limit == 0 || itime_limit == ( now->tv_sec + 86400 )) {
	/* default to grabbing login cookies from the last 12 hours */
	itime_limit = now->tv_sec - 43200;
    }

    memset( bind, 0, sizeof( bind ));
    BIND_LONG( bind[ 0 ], itime_limit );

    if (( q = prepare( template, bind, 1 )) == NULL ) {
	syslog( LOG_ERR, "cookiedb_mysql_taste_cookies: "
			 "failed to prepare query." );
	goto error_bad_taste;
    }
    if ( mysql_stmt_execute( q ) != 0 ) {
	syslog( LOG_ERR, "cookiedb_mysql_taste_cookies: "
			 "mysql_stmt_execute: %s", mysql_stmt_error( q ));
	goto error_bad_taste;
    }

    memset( result, 0, sizeof( result ));
    BIND_STRING( result[ 0 ], cookie, sizeof( cookie ), cookie_len );
    BIND_LONG( result[ 1 ], itime );
    BIND_LONG( result[ 2 ], state );
    if ( mysql_stmt_bind_result( q, result ) != 0 ) {
	syslog( LOG_ERR, "cookiedb_mysql_taste_cookies: "
			 "mysql_stmt_bind_result: %s", mysql_stmt_error( q ));
	goto error_bad_taste;
    }

    rows = 0;
    while (( fr = mysql_stmt_fetch( q )) == 0 ) {
	rows++;

	for ( yacur = (struct connlist *)head; yacur != NULL;
		yacur = yacur->cl_next ) {
	    if ( itime > yacur->cl_last_time && yacur->cl_sn != NULL ) {
		login_sent++;
		/* state is returned as ENUM column #, beginning at index 1 */
		state = ( state > 0 ? state - 1 : -1 );
		if ( snet_writef( yacur->cl_sn, "%s %d %d\r\n",
				  cookie, itime, state ) < 0 ) {
		    syslog( LOG_ERR, "cookiedb_mysql_taste_cookies: "
				     "snet_writef failed" );
		    (void)snet_close( yacur->cl_sn );
		    yacur->cl_sn = NULL;
		    continue;
		}
	    }
	}
    }
    if ( fr != MYSQL_NO_DATA ) {
	if ( fr == MYSQL_DATA_TRUNCATED ) {
	    syslog( LOG_ERR, "cookiedb_mysql_taste_cookies: "
			     "mysql_stmt_fetch returned truncated data." );
	} else {
	    syslog( LOG_ERR, "cookiedb_mysql_taste_cookies: "
			     "mysql_stmt_fetch failed: %s.",
			     mysql_stmt_error( q ));
	}

	goto error_bad_taste;
    }

    /* emulate public monster logging in public cosign source */
    syslog( LOG_NOTICE, "STATS MONSTER: 0/%d/%d login 0/0 service",
			login_sent, rows );

    if ( q != NULL ) {
	mysql_stmt_close( q );
    }
    return( 0 );

error_bad_taste:
    if ( q != NULL ) {
	mysql_stmt_close( q );
    }

    return( -1 );
}

    int
cookiedb_mysql_delete( char cookie[255] )
{
  const char *ldelete_template = "DELETE FROM login_cookies WHERE login_cookie=?";
  const char *sdelete_template = "DELETE FROM service_cookies WHERE service_cookie=?";
  const char *template;
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 1 ];
  unsigned long cookie_length;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_delete: not initialized" );
    return( -1 );
  }

  /* determine which table we're updating */
  if ( !strncmp( cookie, "cosign=", strlen("cosign=") ) ) {
    template = ldelete_template;
  } else {
    template = sdelete_template;
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], cookie, 255, cookie_length );
  
  cookie_length = strlen( cookie );

  q = prepare( template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_delete: failed to prepare query" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_delete: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }
  
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

    int 
cookiedb_mysql_eat_cookie( char cookie[255], struct timeval *now, 
			   time_t *itime, int *state, int loggedout_cache,
			   int idle_cache, int hard_timeout )
{
    struct cinfo        ci;
    int                 rc, create = 0;
    
    /* -1 is a serious error
     * 0 means the cookie was deleted
     * 1 means still good and time was updated 
     */

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiedb_mysql_eat_cookie: not initialized" );
	return( -1 );
    }
    
    if (( rc = cookiedb_mysql_read( cookie, &ci )) < 0 ) {
	syslog( LOG_ERR, "cookiedb_mysql_eat_cookie: cookiedb_mysql_read error: %s", cookie );
	return( -1 );
    }
    
    /* login cookie gave us an ENOENT so we think it's gone */
    if ( rc == 1 ) {
	return( 0 );
    }
    
    /* logged out plus extra non-fail overtime */
    if ( !ci.ci_state && (( now->tv_sec - ci.ci_itime ) > loggedout_cache )) {
	goto delete_stuff;
    }
    
    /* idle out, plus gray window, plus non-failover */
    if (( now->tv_sec - ci.ci_itime )  > idle_cache ) {
	goto delete_stuff;
    }
    
    /* hard timeout */
    create = atoi( ci.ci_ctime );
    if (( now->tv_sec - create )  > hard_timeout ) {
	goto delete_stuff;
    }
    
    *itime = ci.ci_itime; 
    *state = ci.ci_state;
    return( 1 );
   
delete_stuff:
    
  /* remove krb5 ticket and login cookie */
    if ( *ci.ci_krbtkt != '\0' ) {
	if ( unlink( ci.ci_krbtkt ) != 0 ) {
	    syslog( LOG_ERR, "cookiedb_mysql_eat_cookie: unlink krbtgt %s: %m", ci.ci_krbtkt );
	}
    }

    return( cookiedb_mysql_delete( cookie ) );
}

    int
cookiedb_mysql_touch( char cookie[255] )
{
  const char *update_template = "UPDATE login_cookies SET ci_itime=? "
                                "WHERE login_cookie=?";
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  unsigned long cookie_length;
  unsigned long int ci_itime_param;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_touch: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_LONG  ( bind[ 0 ], ci_itime_param );
  BIND_STRING( bind[ 1 ], cookie, 255, cookie_length );
  
  ci_itime_param = time( NULL );
  cookie_length = strlen( cookie );

  q = prepare( update_template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_touch: failed to prepare query" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_touch: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  if ( q ) {
    mysql_stmt_close( q );
  }
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
  
}

    int
cookiedb_mysql_touch_factor( char *lcookie, char factor[256], int update_only )
{
  const char *update_template =
      "UPDATE factor_timeouts "
      " SET timestamp=UNIX_TIMESTAMP() "
      " WHERE factor=? AND login_cookie=?";
  const char *insert_template =
      "INSERT INTO factor_timeouts "
      " SET timestamp=UNIX_TIMESTAMP(), factor=?, login_cookie=?";
  const char *exists_template =
      "SELECT timestamp "
      " FROM factor_timeouts"
      " WHERE login_cookie=? AND factor=?";

  const char *template;

  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  unsigned long factor_length;
  unsigned long lcookie_length;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_touch_factor: not initialized" );
    return( -1 );
  }

  switch ( record_exists_by_two_values(exists_template, lcookie, factor) ) {
  case 0: 
      /* Didn't already exist. If we're update-only, return success. */
      if ( update_only ) {
	  return 0;
      }

      /* Perform an insert. */
      template = insert_template;
      break;
  case 1:
      /* Perform an update. */
      template = update_template;
      break;
  default:
      /* Already syslogged an error. */
      return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], factor, 256, factor_length );
  BIND_STRING( bind[ 1 ], lcookie, 255, lcookie_length );

  factor_length = strlen( factor );
  lcookie_length = strlen( lcookie );

  q = prepare( template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_touch_factor: failed to prepare query" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_touch_factor: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  mysql_stmt_close( q );
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

/* return 0 on success (nothing deleted), 1 on success (something deleted),
 * -1 on error */
    int
cookiedb_mysql_idle_out_factors( char lcookie[255], char factor[256],
				 unsigned int secs)
{
  int ret = 0;
  int delete_it = 0;
  const char *select_template = 
      "SELECT factor,timestamp FROM factor_timeouts "
      " WHERE factor=? AND login_cookie=?";
  const char *delete_template = 
      "DELETE FROM factor_timeouts WHERE factor=? AND login_cookie=?";
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  unsigned long factor_length;
  unsigned long lcookie_length;
  MYSQL_BIND result[ 2 ];
  unsigned long int timestamp_result;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_idle_out_factors: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  BIND_STRING( bind[ 0 ], factor, 256, factor_length );
  BIND_STRING( bind[ 1 ], lcookie, 255, lcookie_length );
  
  factor_length = strlen( factor );
  lcookie_length = strlen( lcookie );

  q = prepare( select_template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_idle_out_factors: failed to prepare query" );
    goto error;
  }

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_idle_out_factors: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }
  
  memset( result, 0, sizeof( result ) );
  BIND_STRING( result[ 0 ], factor, 255, factor_length );
  BIND_LONG  ( result[ 1 ], timestamp_result );

  if ( mysql_stmt_bind_result( q, result ) != 0 ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_idle_out_factors: mysql_stmt_bind_result failed" );
    return( -1 );
  }

  if ( mysql_stmt_fetch( q ) == 0 ) {
    if ((int)timestamp_result < (int)(time(NULL) - secs )) {
      delete_it = ret = 1;
    }
  }

  if ( delete_it ) {
    mysql_stmt_close( q );

    q = prepare( delete_template, bind, 2 );
    if ( !q ) {
      syslog( LOG_ERR,
              "cookiedb_mysql_idle_out_factors: failed to prepare query" );
      goto error;
    }

    if ( mysql_stmt_execute( q ) ) {
      syslog( LOG_ERR, "cookiedb_mysql_idle_out_factors: "
	      "mysql_stmt_execute() failed: %s",
	      mysql_stmt_error( q ) );
      goto error;
    }
  }

  if ( q ) {
    mysql_stmt_close( q );
  }
  return( ret );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );

}

    int
cookiedb_mysql_rename_cookie( char *from, char *to )
{
    MYSQL_STMT		*stmt = NULL;
    MYSQL_BIND		bind[ 2 ];
    unsigned long	from_len, to_len;
    int			rc = -1;
    const char		*rename_template = "UPDATE service_cookies "
					   "SET service_cookie=? "
					   "WHERE service_cookie=?";

    memset( bind, 0, sizeof( bind ));
    BIND_STRING( bind[ 0 ], to, strlen( to ), to_len );
    BIND_STRING( bind[ 1 ], from, strlen( from ), from_len );

    to_len = strlen( to );
    from_len = strlen( from );

    if (( stmt = prepare( rename_template, bind, 2 )) == NULL ) {
	syslog( LOG_ERR, "cookiedb_mysql_rename_cookie: "
			 "failed to prepare MySQL query." );
	return( -1 );
    }

    if ( mysql_stmt_execute( stmt ) != 0 ) {
	syslog( LOG_ERR, "cookiedb_mysql_rename_cookie: "
			 "mysql_stmt_execute failed: %s",
			 mysql_stmt_error( stmt ));
	goto cleanup;
    }

    /* update successful. */
    rc = 0;

cleanup:
    if ( stmt != NULL ) {
	mysql_stmt_close( stmt );
    }

    return( rc );
}
