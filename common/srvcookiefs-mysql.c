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

enum {
  sizeUl  = 10,   /* max number of digits in a 32-bit number (%lu) */
  sizeD   = 10,   /* max in a %d */
  sizeUll = 20,   /* max number of digits in a 64-bit number (%llu) */
  sizeNul = 1
};

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
int record_exists_by_single_value( const char *template, const char *value )
{
  char *query = NULL;
  unsigned long long num_rows;
  int result;
  MYSQL_RES *sql_data = NULL;

  /* +1 for the null terminator. Theoretically there could be a "-2" for a %s,
   * but since we've abstracted up a layer, it's not clear what %-variable 
   * might have been used.
   */
  query = malloc(strlen(template) + strlen(value) + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "record_exists: unable to malloc" );
    return( -1 );
  }

  sprintf(query, template, value);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR,
	    "record_exists: failed to execute query: '%s' : %d",
	    query,
	    mysql_errno( l_sql ) );
    free( query );
    return( -1 );
  }
  free( query );
  query = NULL;

  sql_data = mysql_store_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, 
	    "record_exists: mysql_use_result failed" );
    return( -1 );
  }
  num_rows = mysql_num_rows( sql_data );
  mysql_free_result( sql_data );
  sql_data = NULL;

  return ( num_rows != 0 );
}

static
int record_exists_by_two_values( const char *template, const char *value1,
				 const char *value2 )
{
  char *query = NULL;
  unsigned long long num_rows;
  int result;
  MYSQL_RES *sql_data = NULL;

  /* +1 for the null terminator. Theoretically there could be a "-2" for a %s,
   * but since we've abstracted up a layer, it's not clear what %-variable 
   * might have been used.
   */
  query = malloc(strlen(template) + strlen(value1) + strlen(value2) + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "record_exists: unable to malloc" );
    return( -1 );
  }

  sprintf(query, template, value1, value2);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR,
	    "record_exists: failed to execute query: '%s' : %d",
	    query,
	    mysql_errno( l_sql ) );
    free( query );
    return( -1 );
  }
  free( query );
  query = NULL;

  sql_data = mysql_store_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, 
	    "record_exists: mysql_use_result failed" );
    return( -1 );
  }
  num_rows = mysql_num_rows( sql_data );
  mysql_free_result( sql_data );
  sql_data = NULL;

  return ( num_rows != 0 );
}

    void
cookiefs_destroy( )
{
  if ( l_initialized ) {
    mysql_close( l_sock );
    mysql_close( l_sql );
    l_initialized = 0;
  }
}

    int
cookiefs_init( char *prefix, int hashlen )
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
cookiefs_validate( char *cookie, int timestamp, int state )
{
  int result;
  unsigned long record_timestamp;
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;
  const char *select_template = "SELECT ci_itime,ci_state FROM login_cookies "
                                "WHERE login_cookie='%s'";
  const char *update_template = "UPDATE login_cookies SET ci_itime=%lu "
                                "WHERE login_cookie='%s'";
  char *query = NULL;
  int sql_state = kLOGGED_OUT;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_validate: not initialized" );
    return( -1 );
  }
  /* If the cookie contains an apostrophe, that's a problem. */
  if ( strstr(cookie, "'") ) {
    syslog( LOG_ERR, "cookiefs_validate: invalid cookie value" );
    return( -1 );
  }

  /* -2 for the %s, +1 for the null terminator. */
  query = malloc(strlen(select_template) + strlen(cookie) - 2 + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_validate: unable to malloc" );
    return( -1 );
  }
  sprintf(query, select_template, cookie);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR, 
	    "cookiefs_validate: failed to execute query '%s': %d", 
	    query,
	    mysql_errno( l_sql ) );
    free(query);
    return ( -1 );
  }
  free(query);
  query = NULL;

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiefs_validate: mysql_use_result failed" );
    return( -1 );
  }

  sql_row = mysql_fetch_row( sql_data );
  if ( !sql_row ) {
    mysql_free_result( sql_data );
    return( 1 );
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
    /* +10 for length of MAXINT as a string; -5 for "%lu%s"; +1 for NUL */
    query = malloc(strlen(update_template) + strlen(cookie) + sizeUl - 5 + sizeNul);
    if ( !query ) {
      syslog( LOG_ERR, "cookiefs_validate: unable to malloc" );
      return( -1 );
    }
    sprintf(query, update_template, timestamp, cookie);
    result = mysql_query( l_sql, query );
    if ( result ) {
      syslog( LOG_ERR, 
	      "cookiefs_validate: failed to execute '%s': %d", query, mysql_errno(l_sql) );
      free(query);
      return ( -1 );
    }
    free(query);
    query = NULL;
  }

  /* if state==0 && the cookie's record doesn't indicate 'logged out', then
     log 'em out.
  */
  if ( ( state == 0 ) && sql_state != kACTIVE) {
    return cookiefs_logout( cookie );
  }

  return( 0 );
}

    int
cookiefs_logout( char *cookie )
{
  char *query = NULL;
  int result;
  const char *logout_template = "UPDATE login_cookies SET ci_state='logged out' "
                                "WHERE login_cookie='%s'";

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_logout: not initialized" );
	return( -1 );
    }

    /* -2 for "%s"; +1 for NUL */
    query = malloc(strlen(logout_template) + strlen(cookie) - 2 + sizeNul);
    if ( !query ) {
      syslog( LOG_ERR, "cookiefs_logout: unable to malloc" );
      return( -1 );
    }
    sprintf(query, logout_template, cookie);
    result = mysql_query( l_sql, query );
    if ( result ) {
      syslog( LOG_ERR, 
	      "cookiefs_logout: failed to execute query '%s': %d", 
	      query,
	      mysql_errno( l_sql ) );
      free(query);
      return ( -1 );
    }
    free(query);
    query = NULL;
    return( 0 );
}

/* return 0 for success, -1 for error, and 1 if the cookie wasn't found */
    int
cookiefs_read( char *cookie, struct cinfo *ci )
{
  int result;
  char *query = NULL;
  const char *read_template = "SELECT ci_itime, ci_state, ci_version, "
    "ci_ipaddr,ci_ipaddr_cur,ci_user,ci_ctime,ci_krbtkt "
    " FROM login_cookies WHERE login_cookie='%s'";
  const char *read_factor_template = "SELECT factor "
      "FROM factor_timeouts "
      "WHERE login_cookie='%s'";
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;
  int sz, left;
  char *p;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_read: not initialized" );
    return( -1 );
  }
  
  /* -2 for "%s"; +1 for NUL */
  query = malloc(strlen(read_template) + strlen(cookie) - 2 + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_read: unable to malloc" );
    return( -1 );
  }
  sprintf(query, read_template, cookie);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR, 
	    "cookiefs_read: failed to execute '%s': %d", query, mysql_errno(l_sql) );
    free(query);
    return ( -1 );
  }
  free(query);
  query = NULL;

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiefs_read: mysql_use_result failed" );
    return( -1 );
  }
  
  sql_row = mysql_fetch_row( sql_data );
  if ( !sql_row ) {
    /* This may be benign; there is no login data for that cookie. */
    mysql_free_result( sql_data );
    /* FIXME: magic constant from the original source. Means "no such login" */
    return( 1 );
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

  /* Get all of the factors and put them into ci->ci_realm. Construct the
   * query, get the data, and then carefully construct the string. */

  /* -2 for "%s"; +1 for NUL */
  query = malloc(strlen(read_factor_template) + strlen(cookie) - 2 + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_read: unable to malloc" );
    return( -1 );
  }
  sprintf(query, read_factor_template, cookie);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR,
            "cookiefs_read: failed to execute '%s': %d", 
	    query, mysql_errno(l_sql) );
    free(query);
    return ( -1 );
  }
  free(query);
  query = NULL;

  sql_data = mysql_use_result( l_sql ); 
  if ( !sql_data ) {
      syslog( LOG_ERR, "cookiefs_read: mysql_use_result failed" );
      return( -1 );
  }

  ci->ci_realm[ 0 ] = '\0';
  left = sizeof( ci->ci_realm );
  p = ci->ci_realm;
  while ( (sql_row = mysql_fetch_row( sql_data )) ) {
      if ( left <= strlen( sql_row[ 0 ] ) + 1 ) { /* +1 for space; <= for NUL */
	  syslog( LOG_ERR, 
		  "cookiefs_read: insufficient buffer space for factor list" );
	  return( -1 );
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

  return( 0 );
}

    int
cookiefs_write_login( char *cookie, struct cinfo *ci )
{
  int result;
  char *query = NULL;
  const char *exists_template = "SELECT ci_itime FROM login_cookies "
    "WHERE login_cookie='%s'";
  const char *update_template = "UPDATE login_cookies SET ci_itime=%lu, "
    "ci_state = 'active', ci_version=%d, ci_ipaddr='%s', "
    "ci_ipaddr_cur='%s', ci_user='%s', ci_ctime='%s', "
    "ci_krbtkt='%s' WHERE login_cookie='%s'";
  const char *insert_template = "INSERT INTO login_cookies SET ci_itime=%lu, "
    "ci_state = 'active', ci_version=%d, ci_ipaddr='%s', "
    "ci_ipaddr_cur='%s', ci_user='%s', ci_ctime='%s', "
    "ci_krbtkt='%s', login_cookie='%s'";

  char *value_map[] = { cookie, ci->ci_ipaddr, ci->ci_ipaddr_cur,
			ci->ci_user, ci->ci_realm, ci->ci_ctime,
			ci->ci_krbtkt, NULL };
  char *factor;

  int vm_idx;
  const char *template;
  int content_size;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_write_login: not initialized" );
    return( -1 );
  }

  /* If any of the values we're about to insert into the database contains 
   * an apostrophe, that's a problem. This shouldn't happen. */
  vm_idx = 0;
  while (value_map[vm_idx]) {
    const char *p = value_map[vm_idx];
    if ( strstr(p, "'") ) {
      syslog( LOG_ERR, "cookiefs_write_login: invalid value" );
      return( -1 );
    }
    vm_idx++;
  }

  /* 10 for each %ul; 10 for %d; 7 * 2 for the nine %s/%d; 2 * 3 for the two %lu,+1 for NUL */
  content_size = sizeUl + sizeD + strlen(ci->ci_ipaddr) + 
    strlen(ci->ci_ipaddr_cur) + strlen(ci->ci_user) + 
    strlen(ci->ci_ctime) + 
    strlen(ci->ci_krbtkt) + sizeUl + strlen(cookie)
    - (6*2) - 3 - 2 + sizeNul; 

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

  query = malloc(strlen(template) + content_size);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_write_login: unable to malloc" );
    return( -1 );
  }
  sprintf(query, template, time(NULL), ci->ci_version, 
	  ci->ci_ipaddr, ci->ci_ipaddr_cur, ci->ci_user,
	  ci->ci_ctime, ci->ci_krbtkt, cookie );

  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR,
	    "cookiefs_write_login: failed to execute '%s': %d", query, mysql_errno(l_sql) );
    free( query );
    return( -1 );
  }
  free( query );
  query = NULL;

  for ( factor = strtok( ci->ci_realm, " " );
	    factor != NULL;
	    factor = strtok( NULL, " " ) ) {
      if ( cookiefs_touch_factor( cookie, factor, 0 ) != 0 ) {
	  /* already syslogged an error */
	  return( -1 );
      }
  }

  return( 0 );
}

    int
cookiefs_register( char *lcookie, char *scookie, char *factors[], int num_factors )
{
  char *query = NULL;
  const char *exists_template = "SELECT login_cookie FROM service_cookies "
    "WHERE service_cookie='%s'";
  const char *update_template = "UPDATE service_cookies SET "
    "login_cookie='%s' where service_cookie='%s'";
  const char *insert_template = "INSERT INTO service_cookies "
    "SET login_cookie='%s', service_cookie='%s'";

  const char *template;
  int content_size;
  int result, i;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_register: not initialized" );
    return( -1 );
  }

  if ( strstr(lcookie, "'") || strstr(scookie, "'") ) {
    syslog( LOG_ERR, "cookiefs_register: invalid cookie value" );
    return( -1 );
  }

  for (i=0; i<num_factors; i++) {
    if ( strstr( factors[ i ], "'" ) ) {
      syslog( LOG_ERR, "cookiefs_register: invalid factor name" );
      return( -1 );
    }
  }

  /* 2*2 for two %s, +1 for NUL */
  content_size = strlen(lcookie) + strlen(scookie) - (2*2) + sizeNul;
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

  query = malloc(strlen(template) + content_size);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_register: unable to malloc" );
    return( -1 );
  }

  sprintf(query, template, lcookie, scookie);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR,
	    "cookiefs_register: failed to execute '%s': %d", query, mysql_errno(l_sql) );
    free( query );
    return( -1 );
  }
  free( query );
  query = NULL;

  for ( i = 0; i < num_factors; i++ ) {
      if ( cookiefs_touch_factor( lcookie, factors[ i ], 0 ) != 0 ) {
	  syslog( LOG_ERR, "cookiefs_register: failed to touch factor %s\n", 
		  factors[ i ] );
	  return( -1 );
      }
  }

  return( 0 );
}

/* Jorj: not happy that this doesn't take a length - but conforms to old use
 * of service_to_login. */
    int
cookiefs_service_to_login( char *cookie, char *login )
{
  const char *query_template = "SELECT login_cookie FROM "
    "service_cookies "
    "WHERE service_cookie='%s'";
  char *query = NULL;
  int result;
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_service_to_login: not initialized" );
    return( -1 );
  }
 
  /* -2 for '%s', +1 for NUL */
  query = malloc(strlen(query_template) + strlen(cookie) - 2 + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_service_to_login: unable to malloc" );
    return( -1 );
  }
  sprintf(query, query_template, cookie);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR, 
	    "cookiefs_service_to_login: failed to execute '%s': %d", query, mysql_errno(l_sql) );
    free(query);
    return ( -1 );
  }
  free(query);
  query = NULL;

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiefs_service_to_login: mysql_use_result failed" );
    return( -1 );
  }

  sql_row = mysql_fetch_row( sql_data );
  if ( !sql_row ) {
    syslog( LOG_ERR, "cookiefs_service_to_login: unable to retrieve row data" );
    mysql_free_result( sql_data );
    return( -1 );
  }

  /* Not at all happy with this strcpy - but we have no buffer length due 
   * to arcane use of old method. Deal with this later. */
  strcpy( login, sql_row[0] );

  mysql_free_result( sql_data );
  return( 0 );
}

    int
cookiefs_delete( char *cookie )
{
  const char *delete_template = "DELETE FROM %s_cookies WHERE %s_cookie='%s'";
  char what[8]; /* MAX(strlen("login"), strlen("service")) + sizeNul */
  char *query = NULL;
  int result;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_delete: not initialized" );
    return( -1 );
  }

  /* determine which table we're updating */
  if ( !strncmp( cookie, "cosign=", strlen("cosign=") ) ) {
    sprintf(what, "login");
  } else {
    sprintf(what, "service");
  }

  /* -6 for 3x '%s', +1 for NUL */
  query = malloc(strlen(delete_template) + 
		 2*strlen(what) + 
		 strlen(cookie) - 6 + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_delete: unable to malloc" );
    return( -1 );
  }
  sprintf(query, delete_template, what, what, cookie);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR, 
	    "cookiefs_delete: failed to execute '%s': %d", query, mysql_errno(l_sql) );
    free(query);
    return ( -1 );
  }
  free(query);
  query = NULL;

  return( 0 );
}

    int 
cookiefs_eat_cookie( char *cookie, struct timeval *now, time_t *itime, 
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
	syslog( LOG_ERR, "cookiefs_eat_cookie: not initialized" );
	return( -1 );
    }
    
    if (( rc = cookiefs_read( cookie, &ci )) < 0 ) {
	syslog( LOG_ERR, "cookiefs_eat_cookie: cookiefs_read error: %s", cookie );
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
	    syslog( LOG_ERR, "cookiefs_eat_cookie: unlink krbtgt %s: %m", ci.ci_krbtkt );
	}
    }

    return( cookiefs_delete( cookie ) );
}

    int
cookiefs_touch( char *cookie )
{
  char *query = NULL;
  int result;
  const char *update_template = "UPDATE login_cookies SET ci_itime=%lu "
                                "WHERE login_cookie='%s'";

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_touch: not initialized" );
    return( -1 );
  }

    /* +10 for length of MAXINT as a string; -5 for "%lu%s"; +1 for NUL */
    query = malloc(strlen(update_template) + strlen(cookie) + sizeUl - 5 + sizeNul);
    if ( !query ) {
      syslog( LOG_ERR, "cookiefs_touch: unable to malloc" );
      return( -1 );
    }
    sprintf(query, update_template, time(NULL), cookie);
    result = mysql_query( l_sql, query );
    if ( result ) {
      syslog( LOG_ERR, 
	      "cookiefs_touch: failed to execute '%s': %d", query, mysql_errno(l_sql) );
      free(query);
      return ( -1 );
    }
    free(query);
    query = NULL;

  return( 0 );
}

    int
cookiefs_touch_factor( char *lcookie, char *factor, int update_only )
{
  char *query = NULL;
  int result;
  const char *update_template =
      "UPDATE factor_timeouts "
      " SET timestamp=UNIX_TIMESTAMP() "
      " WHERE factor='%s' AND login_cookie='%s'";
  const char *insert_template =
      "INSERT INTO factor_timeouts "
      " SET timestamp=UNIX_TIMESTAMP(), factor='%s', login_cookie='%s'";
  const char *exists_template =
      "SELECT timestamp "
      " FROM factor_timeouts"
      " WHERE login_cookie='%s' AND factor='%s'";

  const char *template;

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_touch_factor: not initialized" );
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
  query = malloc(strlen( template ) + 
		 strlen(lcookie) + 
		 strlen(factor) - 4 + sizeNul);
    if ( !query ) {
      syslog( LOG_ERR, "cookiefs_touch_factor: unable to malloc" );
      return( -1 );
    }

    sprintf(query, template, factor, lcookie);
    result = mysql_query( l_sql, query );
    if ( result ) {
	syslog( LOG_ERR, 
		"cookiefs_touch_factor: failed to execute '%s': %d", 
		query,
		mysql_errno( l_sql ) );
	free(query);
	return ( -1 );
    }
    free(query);
    query = NULL;

  return( 0 );
}

/* return 0 on success (nothing deleted), 1 on success (something deleted),
 * -1 on error */
    int
cookiefs_idle_out_factors( char *lcookie, char *factor, unsigned int secs)
{
  char *query = NULL;
  int ret = 0;
  int result;
  unsigned long timestamp;
  unsigned char delete_these[ COSIGN_MAXFACTORS ] [ 256 ];
  int num_to_delete = 0;
  MYSQL_RES *sql_data = NULL;
  MYSQL_ROW sql_row;
  const char *select_template = 
      "SELECT factor,timestamp FROM factor_timeouts "
      " WHERE login_cookie='%s' AND factor='%s'";
  const char *delete_template = 
      "DELETE FROM factor_timeouts WHERE factor='%s' AND login_cookie='%s'";

  if ( !l_initialized ) {
    syslog( LOG_ERR, "cookiefs_idle_out_factors: not initialized" );
    return( -1 );
  }

  /* -4 for the %s, +1 for the null terminator. */
  query = malloc(strlen(select_template) + strlen(lcookie) + strlen(factor) - 4 + sizeNul);
  if ( !query ) {
    syslog( LOG_ERR, "cookiefs_idle_out_factors: unable to malloc" );
    return( -1 );
  }
  sprintf(query, select_template, lcookie, factor);
  result = mysql_query( l_sql, query );
  if ( result ) {
    syslog( LOG_ERR, 
	    "cookiefs_idle_out_factors: failed to execute query %s: %d", 
	    query,
	    mysql_errno( l_sql ) );
    free(query);
    return ( -1 );
  }
  free(query);
  query = NULL;

  sql_data = mysql_use_result( l_sql );
  if ( !sql_data ) {
    syslog( LOG_ERR, "cookiefs_idle_out_factors: mysql_use_result failed" );
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

      /* -4 for the 2x %s, +1 for the null terminator. */
      query = malloc(strlen(delete_template) + 
		     strlen(delete_these[num_to_delete-1]) + 
		     strlen(lcookie) - 4 + sizeNul);
      if ( !query ) {
	  syslog( LOG_ERR, "cookiefs_idle_out_factors: unable to malloc" );
	  return( -1 );
      }
      sprintf(query, 
	      delete_template, 
	      delete_these[ num_to_delete - 1 ],
	      lcookie
	      );

      result = mysql_query( l_sql, query );
      if ( result ) {
	  syslog( LOG_ERR, 
		  "cookiefs_idle_out_factors: failed to execute query %s: %d", 
		  query,
		  mysql_errno( l_sql ) );
	  free(query);
	  return ( -1 );
      }
      free(query);
      query = NULL;

      num_to_delete--;
  }

  return( ret );

}
