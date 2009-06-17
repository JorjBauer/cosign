#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>

#include <openssl/rand.h>

#include <mysql.h>

#include "fbase64.h"
#include "mkcookie.h"
#include "srvcookiefs.h"

/* These three for COSIGN_MAXFACTORS. Shame we have to include openssl
   for that! */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "config.h"

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


enum {
  kITIME      = 0,
  kSTATE      = 1,
  kVERSION    = 2,
  kIPADDR     = 3,
  kIPADDR_CUR = 4,
  kUSER       = 5,
  kCTIME      = 6,
  kKRBTKT     = 7
};

/* These should really be in the outer project. */
enum {
  kLOGGED_OUT = 0,
  kACTIVE = 1
};

/* forward declarations */
int cookiedb_mysql_init( char *, int );
void cookiedb_mysql_destroy( );
int cookiedb_mysql_validate( char *,int, int );
int cookiedb_mysql_logout( char * );
int cookiedb_mysql_read( char *, struct cinfo * );
int cookiedb_mysql_write_login( char *, struct cinfo * );
int cookiedb_mysql_register( char *, char *, char *[], int );
int cookiedb_mysql_service_to_login( char *, char * );
int cookiedb_mysql_delete( char * );
int cookiedb_mysql_eat_cookie( char *, struct timeval *, time_t *, int *, int, int, int );
int cookiedb_mysql_touch( char * );
int cookiedb_mysql_touch_factor( char *, char *, int );
int cookiedb_mysql_idle_out_factors( char *, char *, unsigned int );

/* Dispatch table */
struct cfs_funcs mysql_cfs = { cookiedb_mysql_init,
			       cookiedb_mysql_destroy,
			       cookiedb_mysql_validate,
			       cookiedb_mysql_logout,
			       cookiedb_mysql_read,
			       cookiedb_mysql_write_login,
			       cookiedb_mysql_register,
			       cookiedb_mysql_service_to_login,
			       cookiedb_mysql_delete,
			       cookiedb_mysql_eat_cookie,
			       cookiedb_mysql_touch,
			       cookiedb_mysql_touch_factor,
			       cookiedb_mysql_idle_out_factors };

struct cfs_funcs *cookiefs = &mysql_cfs;


static
unsigned long long get_ull( MYSQL_ROW *row, int idx )
{
  unsigned long long ret = 0;
  unsigned char *p = (unsigned char *) (*row)[idx];
  while ( p && *p ) {
    ret *= 10;
    ret = ret + (*p) - '0';
    p++;
  }
  return ret;
}

static
unsigned long get_ul( MYSQL_ROW *row, int idx )
{
  unsigned long ret = 0;
  unsigned char *p = (unsigned char *) (*row)[idx];
  while ( p && *p ) {
    ret *= 10;
    ret = ret + (*p) - '0';
    p++;
  }
  return ret;
}

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
  MYSQL_RES *sql_data = NULL;
  MYSQL_STMT *q = NULL;
  unsigned long param_length;
  MYSQL_BIND bind[ 1 ];
  char param[ 256 ];

  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)param;
  bind[ 0 ].buffer_length = sizeof( param );
  bind[ 0 ].is_null = 0;
  bind[ 0 ].length = &param_length;

  q = prepare( template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, "record_exists: unable to prepare" );
    return( -1 );
  }

  strncpy( param, value, sizeof( param ) );
  param_length = strlen( param );
  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "record_exists: failed to execute query: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  sql_data = mysql_store_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, 
	    "record_exists: mysql_use_result failed" );
    goto error;
  }
  num_rows = mysql_num_rows( sql_data );
  mysql_free_result( sql_data );
  sql_data = NULL;

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
  MYSQL_RES *sql_data = NULL;
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  unsigned long param1_length;
  char param1[ 256 ];
  unsigned long param2_length;
  char param2[ 256 ];

  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)param1;
  bind[ 0 ].buffer_length = sizeof( param1 );
  bind[ 0 ].is_null = 0;
  bind[ 0 ].length = &param1_length;
  bind[ 1 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 1 ].buffer = (char *)param2;
  bind[ 1 ].buffer_length = sizeof( param2 );
  bind[ 1 ].is_null = 0;
  bind[ 1 ].length = &param2_length;

  q = prepare( template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR, "record_exists: unable to prepare" );
    return( -1 );
  }

  strncpy( param1, value1, sizeof( param1 ) );
  param1_length = strlen( param1 );
  strncpy( param2, value2, sizeof( param2 ) );
  param2_length = strlen( param2 );

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "record_exists: failed to execute query: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  sql_data = mysql_store_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, 
	    "record_exists: mysql_use_result failed" );
    goto error;
  }
  num_rows = mysql_num_rows( sql_data );
  mysql_free_result( sql_data );
  sql_data = NULL;

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
  l_initialized = 1;
  return( 0 );
}

/* Return 0 if a given cookie is valid. Return -1 for any failures. 
 * Also update the last-used timestamp of the record. Return 1 if the row
 * does not exist.
 */
    int
cookiedb_mysql_validate( char *cookie, int timestamp, int state )
{
  unsigned long record_timestamp;
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;
  const char *select_template = "SELECT ci_itime,ci_state FROM login_cookies "
                                "WHERE login_cookie=?";
  const char *update_template = "UPDATE login_cookies SET ci_itime=? "
                                "WHERE login_cookie=?";
  int sql_state = kLOGGED_OUT;

  MYSQL_STMT *q = NULL;
  unsigned long str_length;
  MYSQL_BIND bind[ 2 ];
  char cookie_param[ 256 ];
  unsigned long int time_param;


  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)cookie_param;
  bind[ 0 ].buffer_length = sizeof( cookie_param );
  bind[ 0 ].is_null = 0;
  bind[ 0 ].length = &str_length;

  q = prepare( select_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: unable to prepare select" );
    goto error;
  }

  strncpy( cookie_param, cookie, sizeof( cookie_param ) );
  str_length = strlen( cookie_param );

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiedb_mysql_validate: mysql_use_result failed" );
    goto error;
  }

  sql_row = mysql_fetch_row( sql_data );
  if ( !sql_row ) {
    mysql_free_result( sql_data );
    goto ret1;
  }

  record_timestamp = get_ul( &sql_row, kITIME );

  sql_state = sql_row[kSTATE][0] == 'l' ? kLOGGED_OUT : kACTIVE;
  mysql_free_result( sql_data );

  /* ... if the timestamp in the cookie <  timestamp, then we need to update 
   * the record. So get the timestamp out of the query we just performed. The 
   * original query was for just timestamp, and the timestamp was at index 0,
   * so we don't have to do anything crazy to look up the proper index...
  */

  if ( record_timestamp < timestamp ) {

    mysql_stmt_close( q );

    memset( bind, 0, sizeof( bind ) );
    bind[ 0 ].buffer_type = MYSQL_TYPE_LONG;
    bind[ 0 ].buffer = (char *)&time_param;
    bind[ 0 ].is_null = 0;
    bind[ 0 ].length = 0;
    bind[ 1 ].buffer_type = MYSQL_TYPE_STRING;
    bind[ 1 ].buffer = (char *)cookie_param;
    bind[ 1 ].buffer_length = sizeof( cookie_param );
    bind[ 1 ].is_null = 0;
    bind[ 1 ].length = &str_length;
    q = prepare( update_template, bind, 2 );
    if ( !q ) {
      syslog( LOG_ERR, "cookiedb_mysql_validate: failed to prepare update" );
      goto error;
    }

    strncpy( cookie_param, cookie, sizeof( cookie_param ) );
    str_length = strlen( cookie_param );
    time_param = timestamp;

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
cookiedb_mysql_logout( char *cookie )
{
  const char *logout_template = "UPDATE login_cookies "
    "SET ci_state='logged out' "
    "WHERE login_cookie=?";
  MYSQL_STMT *q = NULL;
  unsigned long str_length;
  MYSQL_BIND bind[ 1 ];
  char cookie_param[ 256 ];

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiedb_mysql_logout: not initialized" );
	return( -1 );
    }

    memset( bind, 0, sizeof( bind ) );
    bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
    bind[ 0 ].buffer = (char *)cookie_param;
    bind[ 0 ].buffer_length = sizeof( cookie_param );
    bind[ 0 ].is_null = 0;
    bind[ 0 ].length = &str_length;
    q = prepare( logout_template, bind, 1 );
    if ( !q ) {
      syslog( LOG_ERR, 
	      "cookiedb_mysql_logout: failed to prepare query" );
      goto error;
    }

    strncpy( cookie_param, cookie, sizeof( cookie_param ) );
    str_length = strlen( cookie_param );

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
cookiedb_mysql_read( char *cookie, struct cinfo *ci )
{
  const char *read_template = "SELECT ci_itime, ci_state, ci_version, "
    "ci_ipaddr,ci_ipaddr_cur,ci_user,ci_ctime,ci_krbtkt "
    " FROM login_cookies WHERE login_cookie=?";
  const char *read_factor_template = "SELECT factor "
      "FROM factor_timeouts "
      "WHERE login_cookie=?";
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;
  int sz, left;
  char *p;
  MYSQL_STMT *q = NULL;
  unsigned long str_length;
  MYSQL_BIND bind[ 1 ];
  char cookie_param[ 256 ];


  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_read: not initialized" );
    return( -1 );
  }
  
  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)cookie_param;
  bind[ 0 ].buffer_length = sizeof( cookie_param );
  bind[ 0 ].is_null = 0;
  bind[ 0 ].length = &str_length;
  q = prepare( read_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_read: failed to prepare" );
    goto error;
  }

  strncpy( cookie_param, cookie, sizeof( cookie_param ) );
  str_length = strlen( cookie_param );

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_read: failed to execute: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiedb_mysql_read: mysql_use_result failed" );
    goto error;
  }
  
  sql_row = mysql_fetch_row( sql_data );
  if ( !sql_row ) {
    /* This may be benign; there is no login data for that cookie. */
    mysql_free_result( sql_data );
    goto ret1;
  }

  ci->ci_version = get_ul( &sql_row, kVERSION );
  ci->ci_state = ( (!strcmp(sql_row[kSTATE], "logged out")) ? kLOGGED_OUT:kACTIVE );

  strncpy( ci->ci_ipaddr, sql_row[kIPADDR], sizeof(ci->ci_ipaddr) );
  strncpy( ci->ci_ipaddr_cur, sql_row[kIPADDR_CUR], sizeof(ci->ci_ipaddr_cur) );
  strncpy( ci->ci_user, sql_row[kUSER], sizeof(ci->ci_user) );
  strncpy( ci->ci_ctime, sql_row[kCTIME], sizeof(ci->ci_ctime) );
  strncpy( ci->ci_krbtkt, sql_row[kKRBTKT], sizeof(ci->ci_krbtkt) );
  ci->ci_itime = get_ull( &sql_row, kITIME );

  mysql_free_result( sql_data );
  sql_data = NULL;

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

  sql_data = mysql_use_result( l_sql ); 
  if ( !sql_data ) {
      syslog( LOG_ERR, "cookiedb_mysql_read: mysql_use_result failed" );
      goto error;
  }

  ci->ci_realm[ 0 ] = '\0';
  left = sizeof( ci->ci_realm );
  p = ci->ci_realm;
  while ( (sql_row = mysql_fetch_row( sql_data )) ) {
      if ( left <= strlen( sql_row[ 0 ] ) + 1 ) { /* +1 for space; <= for NUL */
	  syslog( LOG_ERR, 
		  "cookiedb_mysql_read: insufficient buffer space for factor list" );
	  goto error;
      }
      sz = sprintf( p, "%s ", sql_row[ 0 ] );
      p += sz;
      left -= sz;
  }
  /* Remove trailing space */
  if ( p != ci->ci_realm && *(p-1) == ' ' ) {
      *(p-1) = '\0';
  }
  mysql_free_result( sql_data );

    if ( q ) {
      mysql_stmt_close( q );
    }
    return( 0 );
 ret1:
    if ( sql_data ) {
      mysql_free_result( sql_data );
    }
    if ( q ) {
      mysql_stmt_close( q );
    }
    return( 1 );
 error:
    if ( sql_data ) {
      mysql_free_result( sql_data );
    }
    if ( q ) {
      mysql_stmt_close( q );
    }
    return( -1 );
}

    int
cookiedb_mysql_write_login( char *cookie, struct cinfo *ci )
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
  char ci_ipaddr_param[ 256 ];
  unsigned long ci_ipaddr_cur_length;
  char ci_ipaddr_cur_param[ 256 ];
  unsigned long ci_user_length;
  char ci_user_param[ 130 ];
  unsigned long ci_ctime_length;
  char ci_ctime_param[ 12 ];
  unsigned long ci_krbtkt_length;
  char ci_krbtkt_param[ 256 ];
  unsigned long cookie_length;
  char cookie_param[ 256 ];

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
  bind[ 0 ].buffer_type = MYSQL_TYPE_LONG;
  bind[ 0 ].buffer = (char *)&ci_itime_param;
  bind[ 1 ].buffer_type = MYSQL_TYPE_LONG;
  bind[ 1 ].buffer = (char *)&ci_version_param;
  bind[ 2 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 2 ].buffer = (char *)ci_ipaddr_param;
  bind[ 2 ].buffer_length = sizeof( ci_ipaddr_param );
  bind[ 2 ].length = &ci_ipaddr_length;
  bind[ 3 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 3 ].buffer = (char *)ci_ipaddr_cur_param;
  bind[ 3 ].buffer_length = sizeof( ci_ipaddr_cur_param );
  bind[ 3 ].length = &ci_ipaddr_cur_length;
  bind[ 4 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 4 ].buffer = (char *)ci_user_param;
  bind[ 4 ].buffer_length = sizeof( ci_user_param );
  bind[ 4 ].length = &ci_user_length;
  bind[ 5 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 5 ].buffer = (char *)ci_ctime_param;
  bind[ 5 ].buffer_length = sizeof( ci_ctime_param );
  bind[ 5 ].length = &ci_ctime_length;
  bind[ 6 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 6 ].buffer = (char *)ci_krbtkt_param;
  bind[ 6 ].buffer_length = sizeof( ci_krbtkt_param );
  bind[ 6 ].length = &ci_krbtkt_length;
  bind[ 7 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 7 ].buffer = (char *)cookie_param;
  bind[ 7 ].buffer_length = sizeof( cookie_param );
  bind[ 7 ].length = &cookie_length;

  q = prepare( template, bind, 8 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_write_login: failed to prepare template" );
    goto error;
  }

  ci_itime_param = time( NULL );
  ci_version_param = ci->ci_version;
  strncpy( ci_ipaddr_param, ci->ci_ipaddr, sizeof( ci_ipaddr_param ) );
  ci_ipaddr_length = strlen( ci_ipaddr_param );
  strncpy( ci_ipaddr_cur_param, ci->ci_ipaddr_cur, 
	   sizeof( ci_ipaddr_cur_param ) );
  ci_ipaddr_cur_length = strlen( ci_ipaddr_cur_param );
  strncpy( ci_user_param, ci->ci_user, sizeof( ci_user_param ) );
  ci_user_length = strlen( ci_user_param );
  strncpy( ci_ctime_param, ci->ci_ctime, sizeof( ci_ctime_param ) );
  ci_ctime_length = strlen( ci_ctime_param );
  strncpy( ci_krbtkt_param, ci->ci_krbtkt, sizeof( ci_krbtkt_param ) );
  ci_krbtkt_length = strlen( ci_krbtkt_param );
  strncpy( cookie_param, cookie, sizeof( cookie_param ) );
  cookie_length = strlen( cookie_param );

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
cookiedb_mysql_register( char *lcookie, char *scookie, char *factors[], 
			 int num_factors )
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
  char lcookie_param[ 256 ];
  unsigned long lcookie_length;
  char scookie_param[ 256 ];
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
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)lcookie_param;
  bind[ 0 ].buffer_length = sizeof( lcookie_param );
  bind[ 0 ].length = &lcookie_length;
  bind[ 1 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 1 ].buffer = (char *)scookie_param;
  bind[ 1 ].buffer_length = sizeof( scookie_param );
  bind[ 1 ].length = &scookie_length;

  q = prepare( template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR, "cookiedb_mysql_register: unable to prepare" );
    return( -1 );
  }

  strncpy( lcookie_param, lcookie, sizeof( lcookie_param ) );
  lcookie_length = strlen( lcookie_param );
  strncpy( scookie_param, scookie, sizeof( scookie_param ) );
  scookie_length = strlen( scookie_param );

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

/* Jorj: not happy that this doesn't take a length - but conforms to old use
 * of service_to_login. */
    int
cookiedb_mysql_service_to_login( char *cookie, char *login )
{
  const char *query_template = "SELECT login_cookie FROM "
    "service_cookies "
    "WHERE service_cookie=?";
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;

  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 1 ];
  char cookie_param[ 256 ];
  unsigned long cookie_length;


  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_service_to_login: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)cookie_param;
  bind[ 0 ].buffer_length = sizeof( cookie_param );
  bind[ 0 ].is_null = 0;
  bind[ 0 ].length = &cookie_length;

  q = prepare( query_template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_service_to_login: failed to prepare" );
    goto error;
  }

  strncpy( cookie_param, cookie, sizeof( cookie_param ) );
  cookie_length = strlen( cookie_param );

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_service_to_login: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiedb_mysql_service_to_login: mysql_use_result failed" );
    goto error;
  }

  sql_row = mysql_fetch_row( sql_data );
  if ( !sql_row ) {
    syslog( LOG_ERR, "cookiedb_mysql_service_to_login: unable to retrieve row data" );
    mysql_free_result( sql_data );
    goto error;
  }

  /* Not at all happy with this strcpy - but we have no buffer length due 
   * to arcane use of old method. Deal with this later. */
  strcpy( login, sql_row[0] );

  mysql_free_result( sql_data );
  return( 0 );
 error:
  if ( q ) {
    mysql_stmt_close( q );
  }
  return( -1 );
}

    int
cookiedb_mysql_delete( char *cookie )
{
  const char *ldelete_template = "DELETE FROM login_cookies WHERE login_cookie=?";
  const char *sdelete_template = "DELETE FROM service_cookies WHERE service_cookie=?";
  const char *template;
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 1 ];
  char cookie_param[ 256 ];
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
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)cookie_param;
  bind[ 0 ].buffer_length = sizeof( cookie_param );
  bind[ 0 ].is_null = 0;
  bind[ 0 ].length = &cookie_length;

  q = prepare( template, bind, 1 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_delete: failed to prepare query" );
    goto error;
  }

  strncpy( cookie_param, cookie, sizeof( cookie_param ) );
  cookie_length = strlen( cookie_param );

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
cookiedb_mysql_eat_cookie( char *cookie, struct timeval *now, time_t *itime, 
	      int *state, int loggedout_cache, int idle_cache, 
	      int hard_timeout )
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
cookiedb_mysql_touch( char *cookie )
{
  const char *update_template = "UPDATE login_cookies SET ci_itime=? "
                                "WHERE login_cookie=?";
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  char cookie_param[ 256 ];
  unsigned long cookie_length;
  unsigned long int ci_itime_param;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_touch: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_LONG;
  bind[ 0 ].buffer = (char *)&ci_itime_param;
  bind[ 1 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 1 ].buffer = (char *)cookie_param;
  bind[ 1 ].buffer_length = sizeof( cookie_param );
  bind[ 1 ].is_null = 0;
  bind[ 1 ].length = &cookie_length;

  q = prepare( update_template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_touch: failed to prepare query" );
    goto error;
  }

  strncpy( cookie_param, cookie, sizeof( cookie_param ) );
  cookie_length = strlen( cookie_param );
  ci_itime_param = time( NULL );

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
cookiedb_mysql_touch_factor( char *lcookie, char *factor, int update_only )
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
  char factor_param[ 256 ];
  unsigned long factor_length;
  char lcookie_param[ 256 ];
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
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)factor_param;
  bind[ 0 ].buffer_length = sizeof( factor_param );
  bind[ 0 ].length = &factor_length;
  bind[ 1 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 1 ].buffer = (char *)lcookie_param;
  bind[ 1 ].buffer_length = sizeof( lcookie_param );
  bind[ 1 ].length = &lcookie_length;

  q = prepare( template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_touch_factor: failed to prepare query" );
    goto error;
  }

  strncpy( factor_param, factor, sizeof( factor_param ) );
  factor_length = strlen( factor_param );
  strncpy( lcookie_param, lcookie, sizeof( lcookie_param ) );
  lcookie_length = strlen( lcookie_param );

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
cookiedb_mysql_idle_out_factors( char *lcookie, char *factor,
				 unsigned int secs)
{
  int ret = 0;
  unsigned long timestamp;
  char delete_these[ COSIGN_MAXFACTORS ] [ 256 ];
  int num_to_delete = 0;
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;
  const char *select_template = 
      "SELECT factor,timestamp FROM factor_timeouts "
      " WHERE factor=? AND login_cookie=?";
  const char *delete_template = 
      "DELETE FROM factor_timeouts WHERE factor=? AND login_cookie=?";
  MYSQL_STMT *q = NULL;
  MYSQL_BIND bind[ 2 ];
  char factor_param[ 256 ];
  unsigned long factor_length;
  char lcookie_param[ 256 ];
  unsigned long lcookie_length;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiedb_mysql_idle_out_factors: not initialized" );
    return( -1 );
  }

  memset( bind, 0, sizeof( bind ) );
  bind[ 0 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 0 ].buffer = (char *)factor_param;
  bind[ 0 ].buffer_length = sizeof( factor_param );
  bind[ 0 ].length = &factor_length;
  bind[ 1 ].buffer_type = MYSQL_TYPE_STRING;
  bind[ 1 ].buffer = (char *)lcookie_param;
  bind[ 1 ].buffer_length = sizeof( lcookie_param );
  bind[ 1 ].length = &lcookie_length;

  q = prepare( select_template, bind, 2 );
  if ( !q ) {
    syslog( LOG_ERR,
	    "cookiedb_mysql_idle_out_factors: failed to prepare query" );
    goto error;
  }

  strncpy( factor_param, factor, sizeof( factor_param ) );
  factor_length = strlen( factor_param );
  strncpy( lcookie_param, lcookie, sizeof( lcookie_param ) );
  lcookie_length = strlen( lcookie_param );

  if ( mysql_stmt_execute( q ) ) {
    syslog( LOG_ERR, "cookiedb_mysql_idle_out_factors: "
	    "mysql_stmt_execute() failed: %s",
	    mysql_stmt_error( q ) );
    goto error;
  }

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, 
	    "cookiedb_mysql_idle_out_factors: mysql_use_result failed" );
    return( -1 );
  }

  while ( (sql_row = mysql_fetch_row( sql_data )) ) {
      timestamp = get_ul( &sql_row, 1 );

      if ( timestamp < time(NULL) - secs ) {
	  ret = 1;
	  strncpy( delete_these[ num_to_delete++ ], 
		   sql_row[ 0 ], 
		   sizeof( delete_these[ 0 ] ) );
      }
  }

  mysql_free_result( sql_data );

  while ( num_to_delete ) {

    mysql_stmt_close( q );

    q = prepare( delete_template, bind, 2 );
    if ( !q ) {
      syslog( LOG_ERR,
              "cookiedb_mysql_idle_out_factors: failed to prepare query" );
      goto error;
    }

    strncpy( factor_param, 
	     delete_these[num_to_delete-1],
	     sizeof( factor_param ) );
    factor_length = strlen( factor_param );
    strncpy( lcookie_param, lcookie, sizeof( lcookie_param ) );
    lcookie_length = strlen( lcookie_param );

    if ( mysql_stmt_execute( q ) ) {
      syslog( LOG_ERR, "cookiedb_mysql_idle_out_factors: "
	      "mysql_stmt_execute() failed: %s",
	      mysql_stmt_error( q ) );
      goto error;
    }

    num_to_delete--;
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
