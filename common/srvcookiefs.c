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

#include "fbase64.h"
#include "mkcookie.h"
#include "srvcookiefs.h"

static char l_prefix[ MAXPATHLEN ];
static int l_hashlen;
static int l_initialized = 0;

/* Forward declarations */
int cookiefs_init( char *, int );
void cookiefs_destroy( );
int cookiefs_validate( char *,int, int );
int cookiefs_logout( char * );
int cookiefs_read( char *, struct cinfo * );
int cookiefs_write_login( char *, struct cinfo * );
int cookiefs_register( char *, char *, char *[], int );
int cookiefs_service_to_login( char *, char * );
int cookiefs_delete( char * );
int cookiefs_eat_cookie( char *, struct timeval *, time_t *, int *, int, int, int );
int cookiefs_touch( char * );
int cookiefs_touch_factor( char *, char *, int );
int cookiefs_idle_out_factors( char *, char *, unsigned int );

/* Dispatch table */
struct cfs_funcs file_cfs = { cookiefs_init,
			      cookiefs_destroy,
			      cookiefs_validate,
			      cookiefs_logout,
			      cookiefs_read,
			      cookiefs_write_login,
			      cookiefs_register,
			      cookiefs_service_to_login,
			      cookiefs_delete,
			      cookiefs_eat_cookie,
			      cookiefs_touch,
			      cookiefs_touch_factor,
			      cookiefs_idle_out_factors };

struct cfs_funcs *cookiefs = &file_cfs;

    static int
implode_factors( char *in[], int howmany, char *out, int out_length)
{
    int i, l;

    if ( out == NULL || out_length <= 0 ) {
        return( 0 );
    }

    out[0] = '\0';

    for ( i=0; i<howmany; i++ ) {
        l = snprintf( out, out_length, "%s ", in[ i ] );
        if ( l != strlen( in[ i ] ) + 1 ) {
            return( 0 );
        }
        out += l;
        out_length -= l;
    }

    return( 1 );
}


/* mkcookiepath is an artifact of the cookiefs, and should not be used from
 * outside this code. This allows future abstraction of the storage 
 * and lookup mechanisms. */

    static int
mkcookiepath( char *prefix, int hashlen, char *cookie, char *buf, int len )
{
    char	*p;
    int		prefixlen, cookielen;

    if ( strchr( cookie, '/' ) != NULL ) {
        return( -1 );
    }

    if (( cookielen = strlen( cookie )) >= MAXCOOKIELEN ) {
        return( -1 );
    }

    if (( p = strchr( cookie, '=' )) == NULL ) {
	return( -1 );
    }
    prefixlen = p - cookie;

    if (( cookielen - prefixlen ) <= 2 ) {
	return( -1 );
    }

    if ( hashlen == 0 ) {
	if ( prefix == NULL || prefix[ 0 ] == '\0' ) {
	    if ( snprintf( buf, len, "%s", cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	} else {
	    if ( snprintf( buf, len, "%s/%s", prefix, cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	}
    }

    if ( hashlen == 1 ) {
	if ( prefix == NULL ) {
	    if ( snprintf( buf, len, "%c/%s", p[ 1 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	} else {
	    if ( snprintf( buf, len, "%s/%c/%s",
		    prefix, p[ 1 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	}
    }

    if ( hashlen == 2 ) {
	if ( prefix == NULL ) {
	    if ( snprintf( buf, len, "%c%c/%s",
		    p[ 1 ], p[ 2 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	} else {
	    if ( snprintf( buf, len, "%s/%c%c/%s",
		    prefix, p[ 1 ], p[ 2 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	}
    }
    return( -1 );
}

    static int
do_logout( char *path )
{
    if ( chmod( path, (  S_ISGID | S_IRUSR  )) < 0 ) {
	syslog( LOG_ERR, "do_logout: %s: %m", path  );
	return( -1 ) ;
    }
    utime( path, NULL );

    return( 0 );
}

/* char *login passed in should be MAXCOOKIELEN */
    static int
service_to_login( char *service, char *login )
{
    FILE	*scf;
    char	buf[ MAXCOOKIELEN + 2 ];
    char	*p;
    int		len;
    extern int	errno;

    if (( scf = fopen( service, "r" )) == NULL ) {
	if ( errno != ENOENT ) {
	    syslog( LOG_ERR, "service_to_login: %s: %m", service  );
	}
	return( -1 );
    }

    if ( fgets( buf, sizeof( buf ), scf ) == NULL ) {
	syslog( LOG_ERR, "service_to_login: fgets: %m"  );
	goto error;
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	syslog( LOG_ERR, "service_to_login: line too long" );
	goto error;
    }
    buf[ len - 1 ] = '\0';
    p = buf + 1;

    if ( *buf != 'l' ) {
	syslog( LOG_ERR,
		"service_to_login: file format error in %s", service );
	goto error;
    }

    strcpy( login, p );

    if ( fclose( scf ) != 0 ) {
	syslog( LOG_ERR, "service_to_login: %s: %m", service );
	return( -1 );
    }
    return( 0 );

error:
    if ( fclose( scf ) != 0 ) {
	syslog( LOG_ERR, "service_to_login: %s: %m", service );
    }
    return( -1 );

}

    static int
read_cookie( char *path, struct cinfo *ci )
{
    FILE		*cf;
    struct stat		st;
    char		buf[ MAXPATHLEN + 2 ];
    char		*p;
    int			len;
    extern int          errno;

    memset( ci, 0, sizeof( struct cinfo ));

    if (( cf = fopen( path, "r" )) == NULL ) {
	/* monster need this ENOENT return val */
	if ( errno == ENOENT ) {
	    return( 1 );
	}
	syslog( LOG_ERR, "read_cookie: %s: %m", path  );
	return( -1 );
    }

    if ( fstat( fileno( cf ), &st ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
	goto error;
    }

    ci->ci_itime = st.st_mtime;

    /* file ordering only matters for version and state */
    if ( fgets( buf, sizeof( ci->ci_version ), cf ) == NULL ) {
	syslog( LOG_ERR, "read_cookie: ci_version: %m"  );
	goto error;
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	syslog( LOG_ERR, "read_cookie: line too long (1)" );
	goto error;
    }
    buf[ len - 1 ] = '\0';

    if ( *buf != 'v' ) {
	syslog( LOG_ERR, "read_cookie: file format error" );
	goto error;
    }
    p = buf + 1;

    ci->ci_version = atoi( p );

    if ( ci->ci_version != 2 ) {
	syslog( LOG_ERR, "read_cookie: file version mismatch" );
	goto error;
    }

    /* legacy logout code, skip the s0/1 line */
    if ( fgets( buf, sizeof( ci->ci_state ), cf ) == NULL ) {
	syslog( LOG_ERR, "read_cookie: ci_state: %m"  );
	goto error;
    }

    /* new logout code */
    if ( st.st_mode & S_ISGID ) {
	ci->ci_state = 0;
    } else {
	ci->ci_state = 1;
    }

    /* we checked sizes when we wrote this data to a trusted file system */
    while( fgets( buf, sizeof( buf ), cf ) != NULL ) {
	len = strlen( buf );
	if ( buf[ len - 1 ] != '\n' ) {
	    syslog( LOG_ERR, "read_cookie: line too long (2)");
	    goto error;
	}
	buf[ len - 1 ] = '\0';
	p = buf + 1;

	switch( *buf ) {

	case 'i':
	    strncpy( ci->ci_ipaddr, p, sizeof(ci->ci_ipaddr) );
	    break;

	case 'j':
	    strncpy( ci->ci_ipaddr_cur, p, sizeof(ci->ci_ipaddr_cur) );
	    break;

	case 'p':
	    strncpy( ci->ci_user, p, sizeof(ci->ci_user) );
	    break;

	case 'r':
	    strncpy( ci->ci_realm, p, sizeof(ci->ci_realm) );
	    break;

	case 't':
	    strncpy( ci->ci_ctime, p, sizeof(ci->ci_ctime) );
	    break;

	case 'k':
	    strncpy( ci->ci_krbtkt, p, sizeof(ci->ci_krbtkt) );
	    break;

	default:
	    syslog( LOG_ERR, "read_cookie: unknown keyword %c", *buf );
	    goto error;
	}
    }

    if ( fclose( cf ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
	return( -1 );
    }
    return( 0 );

error:
    if ( fclose( cf ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
    }
    return( -1 );
}

/*
 * associate serivce with login
 * 0 = OK
 * -1 = unknown fatal error
 * 1 = already registered
 */
    static int
do_register( char *login, char *login_p, char *scookie_p, char *factor_list )
{
    int			fd, rc;
    char		tmppath[ MAXCOOKIELEN ];
    FILE		*tmpfile;
    struct timeval	tv;

    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "do_register: gettimeofday: %m" );
	return( -1 );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%x%x.%i",
	    (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	syslog( LOG_ERR, "do_register: tmppath too long" );
	return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "do_register: open: %s: %m", tmppath );
	return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "do_register: fdopen: %m" );
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "do_register: unlink: %m" );
	}
	return( -1 );
    }

    /* the service cookie file contains the login cookie and factors */
    fprintf( tmpfile, "l%s\n", login );
    fprintf( tmpfile, "r%s\n", factor_list );

    if ( fclose( tmpfile ) != 0 ) {
	syslog( LOG_ERR, "do_register: fclose: %m" );
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "do_register: unlink: %m" );
	}
	return( -1 );
    }

    if ( link( tmppath, scookie_p ) != 0 ) {
	if ( errno == EEXIST ) {
	    rc = 1;
	} else {
	    syslog( LOG_ERR, "do_register: link: %m" );
	    rc = -1;
	}
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "do_register: unlink: %m" );
	}
	return( rc );
    }

    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "do_register: unlink: %m" );
	return( -1 );
    }

    utime( login_p, NULL );

    return( 0 );
}

    void
cookiefs_destroy( )
{
}

    int
cookiefs_init( char *prefix, int hashlen )
{
    if ( prefix ) {
	strncpy( l_prefix, prefix, sizeof(l_prefix) );
    } else {
	l_prefix[ 0 ] = '\0';
    }
    l_hashlen = hashlen;
    l_initialized = 1;

    return( 0 );
}

    int
cookiefs_validate( char *cookie, int timestamp, int state )
{
    char path[ MAXPATHLEN ];
    struct stat st;
    struct utimbuf new_time;

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_validate: not initialized" );
	return( -1 );
    }

    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_validate: mkcookiepath error" );
	return( -1 );
    }

    if ( stat( path, &st ) < 0 ) {
      return( -1 );
    }

    if ( timestamp > st.st_mtime ) {
      new_time.modtime = timestamp;
      utime( path, &new_time );
    }

    /* This cookie should be logged out. If it's not, then make it so. */
    if (( state == 0 ) && (( st.st_mode & S_ISGID ) != 0 )) {
      if ( do_logout ( path ) < 0 ) {
	syslog( LOG_ERR, "cookiefs_validate: %s should be logged out!", path );
      }
    }

    return( 0 );
}

    int
cookiefs_logout( char *cookie )
{
    char path[ MAXPATHLEN ];

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_logout: not initialized" );
	return( -1 );
    }

    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_logout: mkcookiepath error" );
	return( -1 );
    }

    return( do_logout( path ) );
}

    int
cookiefs_read( char *cookie, struct cinfo *ci )
{
    char path[ MAXPATHLEN ];

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_read: not initialized" );
	return( -1 );
    }

    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_read: mkcookiepath error" );
	return( -1 );
    }

    return( read_cookie( path, ci ) );
}


    int
cookiefs_write_login( char *cookie, struct cinfo *ci )
{
    char tmppath[ MAXPATHLEN ], path[ MAXPATHLEN ];
    struct timeval tv;
    int fd, err;
    FILE *tmpfile;
    struct stat st;
    
    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_write_login: not initialized" );
	return( -1 );
    }
    
    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "cookiefs_write_login: gettimeofday: %m" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_write_login: mkcookiepath error" );
	return( -1 );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%x%x.%i", 
		   (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >= 
	 sizeof( tmppath )) {
	syslog( LOG_ERR, "cookiefs_write_login: tmppath too long" );
	return( -1 );
    }
    
    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "cookiefs_write_login: open: %s: %m", tmppath );
	return( -1 );
    }
    
    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	goto file_err;
    }

    fprintf( tmpfile, "v2\n" );
    fprintf( tmpfile, "s1\n" ); /* 1 is logged in, 0 is logged out */
    fprintf( tmpfile, "i%s\n", ci->ci_ipaddr );
    fprintf( tmpfile, "j%s\n", ci->ci_ipaddr_cur );
    fprintf( tmpfile, "t%s\n", ci->ci_ctime );
    fprintf( tmpfile, "p%s\n", ci->ci_user );
    fprintf( tmpfile, "r%s\n", ci->ci_realm );
    fprintf( tmpfile, "k%s\n", ci->ci_krbtkt );
    
    if ( fclose ( tmpfile ) != 0 ) {
	goto file_err;
    }
    
    if ( stat( tmppath, &st ) == 0 ) {
	if ( rename( tmppath, path ) != 0 ) { 
	    err = errno;
	    syslog( LOG_ERR,
		    "cookiefs_write_login: rename %s to %s: %m", tmppath, path );
	    if ( unlink( tmppath ) != 0 ) {
		syslog( LOG_ERR, "cookiefs_write_login: unlink %s: %m", tmppath );
	    }
	    return( err );
	}
    }
    return( 0 );
    
file_err:
    (void)fclose( tmpfile );
    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "cookiefs_write_login: unlink: %m" );
    }
    syslog( LOG_ERR, "cookiefs_write_login: bad file format" );
    return( 1 );
}

    int
cookiefs_register( char *lcookie, char *scookie, char *factors[], int num_factors )
{
    char lpath[ MAXPATHLEN ], spath[ MAXPATHLEN ];
    char imploded_factors[ 1024 ];

    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_register: not initialized" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, lcookie, lpath, sizeof(lpath) ) ) {
	syslog( LOG_ERR, "cookiefs_register: mkcookiepath error" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, scookie, spath, sizeof(spath) ) ) {
	syslog( LOG_ERR, "cookiefs_register: mkcookiepath error" );
	return( -1 );
    }

    imploded_factors[ 0 ] = '\0';
    if ( factors && implode_factors( factors, num_factors, imploded_factors, sizeof( imploded_factors ) ) == 0 ) {
	syslog( LOG_ERR, "cookiefs_register: implode_factors failed" );
	return( -1 );
    }

    return( do_register( lcookie, lpath, spath, imploded_factors ) );
}

/* Jorj: not happy that this doesn't take a length - but conforms to old use
 * of service_to_login. */
    int
cookiefs_service_to_login( char *cookie, char *login )
{
    char path[ MAXPATHLEN ];
    
    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_service_to_login: not initialized" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_service_to_login: mkcookiepath error" );
	return( -1 );
    }
    
    return( service_to_login( path, login ) );
}

    int
cookiefs_delete( char *cookie )
{
    char path[ MAXPATHLEN ];
    
    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_delete: not initialized" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_delete: mkcookiepath error" );
	return( -1 );
    }
    
    return( unlink( path ) );
}

    int 
cookiefs_eat_cookie( char *cookie, struct timeval *now, time_t *itime, 
	      int *state, int loggedout_cache, int idle_cache, 
	      int hard_timeout )
{
    char		      path[ MAXPATHLEN ];
    struct cinfo        ci;
    int                 rc, create = 0;
    extern int          errno;
    
    /* -1 is a serious error
     * 0 means the cookie was deleted
     * 1 means still good and time was updated 
     */
    
    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_eat_cookie: not initialized" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_eat_cookie: mkcookiepath error" );
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
    if ( unlink( path ) != 0 ) {
	syslog( LOG_ERR, "cookiefs_eat_cookie: unlink: %s: %m", path );
    } 
    
    return( 0 );
}

    int
cookiefs_touch( char *cookie )
{
    char path[ MAXPATHLEN ];
    
    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_touch: not initialized" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, cookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_touch: mkcookiepath error" );
	return( -1 );
    }
    
    return utime( path, NULL );
}

    int
cookiefs_touch_factor( char *lcookie, char *factor, int update_only )
{
    char path[ MAXPATHLEN ];
    struct stat st;
    
    if ( !l_initialized ) {
	syslog( LOG_ERR, "cookiefs_touch_factor: not initialized" );
	return( -1 );
    }
    
    if ( mkcookiepath( l_prefix, l_hashlen, lcookie, path, sizeof(path) ) ) {
	syslog( LOG_ERR, "cookiefs_touch_factor: mkcookiepath error" );
	return( -1 );
    }

    if ( strlen( path ) + strlen( factor ) + 2 >= MAXPATHLEN ) {
      syslog( LOG_ERR, "cookiefs_touch_factor: unable to construct path" );
      return( -1 );
    }

    /* FIXME: update_only not properly implemented here */

    strcat( path, "-" );
    strcat( path, factor );

    if ( stat( path, &st ) < 0 ) {
      fclose( fopen( path, "w" ) );
    }

    return utime( path, NULL );
}

    int
cookiefs_idle_out_factors( char *lcookie, char *factor, unsigned int secs)
{
    /* Unimplemented in this backend type. */
    syslog( LOG_ERR, "cookiefs_idle_out_factors: unable to idle out factors using the filesystem backend" );
    return( 0 );
}
