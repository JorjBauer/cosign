/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <snet.h>
#include "cgi.h"
#include "cosigncgi.h"
#include "conf.h"
#include "network.h"
#include "login.h"
#include "subfile.h"
#include "factor.h"
#include "mkcookie.h"

#define SERVICE_MENU	"/services/"
#define LOOPWINDOW      30 
#define MAXLOOPCOUNT	5        /* UPenn: reduced to 5 */
#define MAXCOOKIETIME	86400	 /* Valid life of session cookie: 24 hours */

#define kUNSATISFIED     0
#define kSATISFIED       1
#define kSUBSTITUTED_FWD 2
#define kSUBSTITUTED_REV 3

extern char	*cosign_version;
extern char	*userfactorpath;
extern char	*suffix;
extern char	*parasitic_suffix;
extern struct factorlist	*factorlist;
unsigned short	cosign_port;
char		*cosign_host = _COSIGN_HOST;
char 		*cosign_conf = _COSIGN_CONF;
char		*title = "Authentication Required";
char		*cryptofile = _COSIGN_TLS_KEY;
char		*certfile = _COSIGN_TLS_CERT;
char		*cadir = _COSIGN_TLS_CADIR;
char		*tmpldir = _COSIGN_TMPL_DIR;
char		*loop_page = _COSIGN_LOOP_URL;
int		krbtkts = 0;
SSL_CTX 	*ctx = NULL;

char			*new_factors[ COSIGN_MAXFACTORS ];
char			*script;
struct userinfo		ui;
struct subparams	sp;

struct cgi_list cl[] = {
#define CL_LOGIN	0
        { "login", CGI_TYPE_STRING, NULL },
#define CL_PASSWORD	1
        { "password", CGI_TYPE_STRING, NULL },
#define CL_REF		2
        { "ref", CGI_TYPE_STRING, NULL },
#define CL_SERVICE	3
        { "service", CGI_TYPE_STRING, NULL },
#define CL_REAUTH	4
        { "reauth", CGI_TYPE_STRING, NULL },
#define CL_RFACTOR	5
        { "required", CGI_TYPE_STRING, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
};

static struct subfile_list sl[] = {
#define SL_LOGIN	0
        { 'l', SUBF_STR_ESC, NULL },
#define SL_TITLE	1
        { 't', SUBF_STR, NULL },
#define SL_REF		2
        { 'r', SUBF_STR_ESC, NULL },
#define SL_SERVICE	3
        { 'c', SUBF_STR_ESC, NULL },
#define SL_ERROR	4
        { 'e', SUBF_STR, NULL },
#define SL_RFACTOR	5
        { 'f', SUBF_STR_ESC, NULL },
#define SL_DFACTOR	6
        { 'd', SUBF_STR_ESC, NULL },
        { '\0', 0, NULL },
};

/* 'in' is comma-separated; 'out' is space-separted. */
    static int
implode_factors( const char *in, char *out, int out_length )
{
    if ( in == NULL || out == NULL || out_length <= 0 ) {
	return( 0 );
    }

    out[0] = '\0';

    char *p = out;
    strncpy( out, in, out_length );
    while ( *p ) {
	if ( *p == ',' ) {
	    *p = ' ';
	}
	p++;
    }
    return ( strlen( out ) == strlen( in ) );
}

    static void
loop_checker( int time, int count, char *cookie )
{
    struct timeval	tv;
    char       		new_cookie[ 255 ];

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
	sl[ SL_ERROR ].sl_data = "Please try again later.";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit( 0 );
    }

    /* we're past our window, all is well */
    if (( tv.tv_sec - time ) > LOOPWINDOW ) {
	time = tv.tv_sec;
	count = 1;
	if ( snprintf( new_cookie, sizeof( new_cookie ),
		"%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
	    sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
	    sl[ SL_ERROR ].sl_data = "Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}
	printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	return;
    }

    /* too many redirects - break the loop and give an error */
    if ( count >= MAXLOOPCOUNT ) {
	time = tv.tv_sec;
	count = 1;
	if ( snprintf( new_cookie, sizeof( new_cookie ),
		"%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
	    sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
	    sl[ SL_ERROR ].sl_data = "Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}
	printf( "Location: %s\n\n", loop_page );
	exit( 0 );
    }

    /* we're still in the limit, increment and keep going */
    count++;
    if ( snprintf( new_cookie, sizeof( new_cookie ),
	    "%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
	sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
	sl[ SL_ERROR ].sl_data = "Please try again later.";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit( 0 );
    }
    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
    return;
}

    static void
kcgi_configure()
{
    char 	*val;

    if (( val = cosign_config_get( COSIGNHOSTKEY )) != NULL ) {
	cosign_host = val;
    }
    if (( val = cosign_config_get( COSIGNLOOPURLKEY )) != NULL ) {
	 loop_page = val;
    }
    if (( val = cosign_config_get( COSIGNKEYKEY )) != NULL ) {
	cryptofile = val;
    }
    if (( val = cosign_config_get( COSIGNCERTKEY )) != NULL ) {
	certfile = val;
    }
    if (( val = cosign_config_get( COSIGNCADIRKEY )) != NULL ) {
	cadir = val;
    }
    if (( val = cosign_config_get( COSIGNTMPLDIRKEY )) != NULL ) {
	tmpldir = val;
    }
    if ((( val = cosign_config_get( COSIGNX509TKTSKEY )) != NULL ) ||
	    (( val = cosign_config_get( COSIGNKRBTKTSKEY )) != NULL )) {
	if ( strcasecmp( val, "on" ) == 0 ) {
	    krbtkts = 1;
	} else if ( strcasecmp( val, "off" ) == 0 ) {
	    krbtkts = 0;
	} else {
	    fprintf( stderr, "%s: invalid setting for krbtkts:"
		    " defaulting off.\n", val );
	    krbtkts = 0;
	}
    }
    if (( val = cosign_config_get( COSIGNPORTKEY )) != NULL ) {
	cosign_port = htons( atoi( val ));
    } else {
	cosign_port = htons( 6663 );
    }
}

    static char *
smash( char *av[] )
{
    static char	smashtext[ 1024 ];
    int		i;
    
    if ( av[ 0 ] == NULL ) {
	return( NULL );
    }
    if ( strlen( av[ 0 ] ) + 1 > sizeof( smashtext )) {
	return( NULL );
    }
    strcpy( smashtext, av[ 0 ] );
    for ( i = 1; av[ i ] != NULL; i++ ) {
	if ( strlen( av[ i ] ) + 1 + 1 >
		sizeof( smashtext ) - strlen( smashtext )) {
	    return( NULL );
	}
	strcat( smashtext, "," );
	strcat( smashtext, av[ i ] );
    }
    return( smashtext );
}

/*
 * append a factor to an argv.
 *
 * factorv is expected to be the sl_factors field from the service's
 * servicelist entry. this field is always allocated with space for
 * COSIGN_MAXFACTORS elements, and the 0th element is initialized to NULL.
 *
 * return values:
 * -1: error
 *  0: factor already in list.
 *  1: factor appended
 */
    static int
factor_push( char **factorv, char *newfactor )
{
    int		i;

    for ( i = 0; factorv[ i ] != NULL; i++ ) {
	/* check if newfactor's already in factorv */
	if ( strcmp( factorv[ i ], newfactor ) == 0 ) {
	    return( 0 );
	}
    }

    /* need element at index COSIGN_MAXFACTORS - 1 to store terminating NULL */
    if ( i >= COSIGN_MAXFACTORS - 1 ) {
	fprintf( stderr, "factor_push: too many factors\n" );
	return( -1 );
    }
    if (( factorv[ i ] = strdup( newfactor )) == NULL ) {
	perror( "factor_push: strdup" );
	return( -1 );
    }
    factorv[ i + 1 ] = NULL;

    return( 1 );
}

/*
 * parse a comma-separated list of required factors, appending factors
 * to the service's required factor argv if they match the dependent
 * suffix. if a dependent factor's found, both it and its parent factor
 * are appended to the factor argv, and SL_REAUTH is set.
 */
    static int
factor_set_dependencies( struct servicelist *svc, char *reqlist,
	char *depsuffix )
{
    char	*require, *rf, *sfx;
    char	*last = NULL;
    int		rc = -1;

    if (( require = strdup( reqlist )) == NULL ) {
	perror( "factor_set_dependencies: strdup" );
	return( -1 );
    }
    for ( rf = strtok_r( require, ",", &last ); rf != NULL;
		rf = strtok_r( NULL, ",", &last )) {
	if (( sfx = strstr( rf, depsuffix )) != NULL ) {
	    /*
	     * this is a dependent factor. append it & its parent to
	     * sl_factors and set SL_REAUTH for the service.
	     */
	    *sfx = '\0';
	    if ( factor_push( svc->sl_factors, rf ) == -1 ) {
		goto cleanup;
	    }
	    *sfx = *depsuffix;
	    if ( factor_push( svc->sl_factors, rf ) == -1 ) {
		goto cleanup;
	    }
	    svc->sl_flag |= SL_REAUTH;
	}
    }
    rc = 0;

cleanup:
    free( require );

    return( rc );
}

    static int
match_factor( char *required, char *satisfied, char *suffix )
{
    char	*p;
    int		rc;

    if ( strcmp( required, satisfied ) == 0 ) {
	return( kSATISFIED );
    }
    if ( suffix != NULL ) {
	if (( p = strstr( satisfied, suffix )) != NULL ) {
	    if (( strlen( p )) == ( strlen( suffix ))) {
		*p = '\0';
		rc = strcmp( required, satisfied );
		*p = *suffix;
		if ( rc == 0 ) {
		    return( kSUBSTITUTED_FWD );
		}
	    }
	}
	if (( p = strstr( required, suffix )) != NULL ) {
	    if (( strlen( p )) == ( strlen( suffix ))) {
		*p = '\0';
		rc = strcmp( required, satisfied );
		*p = *suffix;
		if ( rc == 0 ) {
		    return( kSUBSTITUTED_REV );
		}
	    }
	}
    }
    return( kUNSATISFIED );
}

#define COSIGN_FACTOR_SATISFIED_FLAG	(1 << 0)
#define COSIGN_FACTOR_REAUTH_FLAG	(1 << 4)
#define COSIGN_FACTOR_REAUTH_REQUIRED(x) \
	(((x) & COSIGN_FACTOR_REAUTH_FLAG ))
    static int
satisfied( char		*sfactors[], char *rfactors )
{
    char		*require, *reqp, *r;
    int			i;
    int			rc = 0;

    if ( rfactors != NULL ) {
	require = strdup( rfactors );
	for ( r = strtok_r( require, ",", &reqp ); r != NULL;
		r = strtok_r( NULL, ",", &reqp )) {
	    for ( i = 0; sfactors[ i ] != NULL; i++ ) {
		if ( match_factor( r, sfactors[ i ], suffix )) {
		    break;
		}

		if ( parasitic_suffix ) {
		    switch ( match_factor( r, sfactors[ i ],
				parasitic_suffix )) {
		    case kSATISFIED:
			break;

		    case kSUBSTITUTED_REV:
			/*
			 * This is a dependent (parasitic) factor. Reauth the
			 * the factor it's dependent on.
			 */
			rc |= COSIGN_FACTOR_REAUTH_FLAG;
			break;
		    }

		    if ( COSIGN_FACTOR_REAUTH_REQUIRED( rc )) {
			break;
		    }
		}
	    }
	    if ( sfactors[ i ] == NULL || COSIGN_FACTOR_REAUTH_REQUIRED( rc )) {
		break;
	    }
	}
	free( require );
	if ( r != NULL ) {
	    return( rc );
	}
    }
    rc |= COSIGN_FACTOR_SATISFIED_FLAG;
    return( rc );
}

    static int
mkscookie( char *service_name, char *new_scookie, int len )
{
    char			tmp[ 128 ];

    if ( mkcookie( sizeof( tmp ), tmp ) != 0 ) {
	fprintf( stderr, "%s: mkscookie failed.\n", script );
	return( -1 );
    }
    if ( snprintf( new_scookie, len, "%s=%s", service_name, tmp ) >= len ) {
	fprintf( stderr, "%s: %s=%s: too long\n", script, service_name, tmp );
	return( -1 );
    }

    return( 0 );
}

    static char *
getuserfactors( char *path, char *login )
{
    struct factorlist		ufl;
    char			*msg = NULL;
    int				rc;

    ufl.fl_path = path;
    ufl.fl_flag = 0;
    ufl.fl_formfield[ 0 ] = NULL;
    ufl.fl_next = NULL;

    if ((( rc = execfactor( &ufl, NULL, login, &msg )) == COSIGN_CGI_OK ) &&
	    msg != NULL ) {
	return( msg );
    }
    return( NULL );
}

    int
main( int argc, char *argv[] )
{
    int				rc = 0, cookietime = 0, cookiecount = 0;
    int				rebasic = 0, len, server_port;
    int				reauth = 0, scheme = 2;
    int				i;
    char                	new_cookiebuf[ 128 ];
    char        		new_cookie[ 255 ];
    char			new_scookie[ 255 ];
    char			*data, *ip_addr, *tmpl = NULL, *server_name;
    char			*cookie = NULL, *method, *qs, *misc = NULL;
    char			*rfactors = NULL, *ufactors = NULL, *p;
    char			*ref = NULL, *service = NULL, *login = NULL;
    char			*remote_user = NULL;
    char			*subject_dn = NULL, *issuer_dn = NULL;
    char			*sport;
    char			*realm = NULL, *krbtkt_path = NULL;
    char			*auth_type = NULL;
    char			**ff, *msg = NULL;
    struct servicelist		*scookie = NULL;
    struct factorlist		*fl;
    struct timeval		tv;
    struct connlist		*head;
    char			matchbuf[ 1024 ];
    regmatch_t			matches[ 2 ];
    int				nmatch = 2;
    CGIHANDLE			*cgi;
    char                        imploded_factors[ 1024 ];
    char			*subst_factor = NULL;
    int				req_more_auth = 0;

    if ( argc == 2 && ( strcmp( argv[ 1 ], "-V" ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    }
    if ( argc != 1 ) {
	fprintf( stderr, "usage: %s [-V]\n", argv[ 0 ] );
	exit( 1 );
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	fprintf( stderr, "Couldn't read %s\n", cosign_conf );
	exit( 1 );
    }
    kcgi_configure();
    if ( chdir( tmpldir ) < 0 ) {
	perror( tmpldir );
	exit( 1 );
    }

    if (( script = getenv( "SCRIPT_NAME" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Unable to retrieve the script name";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit( 0 );
    }
    if (( method = getenv( "REQUEST_METHOD" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Unable to retrieve method";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit(0);
    }
    if (( ip_addr = getenv( "REMOTE_ADDR" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Unable to retrieve IP address";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit(0);
    }
    if (( server_name = getenv( "SERVER_NAME" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Unable to retrieve server name";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit(0);
    }
    if (( sport = getenv( "SERVER_PORT" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Unable to retrieve server port";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit(0);
    }
    server_port = atoi( sport);
    if (( realm = getenv( "COSIGN_DEFAULT_FACTOR" )) == NULL ) {
	realm = "basic";
    }

    subject_dn = getenv( "SSL_CLIENT_S_DN" );
    issuer_dn = getenv( "SSL_CLIENT_I_DN" );

    if ( subject_dn && issuer_dn ) {
	if ( x509_translate( subject_dn, issuer_dn, &login, &realm ) != 0 ) {
	    sl[ SL_TITLE ].sl_data = "Error: X509 failed";
	    sl[ SL_ERROR ].sl_data = "There was an x.509 mutual authentication"
		    " configuration error. Contact your administrator.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}
	remote_user = login;
    } else {
	auth_type = getenv("AUTH_TYPE");
	remote_user = getenv("REMOTE_USER");

	if ( remote_user && auth_type &&
		strcasecmp( auth_type, "Negotiate" ) == 0 ) {
	    if ( negotiate_translate( remote_user, &login, &realm ) != 0 ) {
		sl[ SL_TITLE ].sl_data = "Error: Negotiate login failed";
	 	sl[ SL_ERROR ].sl_data = "There was a problem processing your"
			" authentication data. Contact your administrator";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit ( 0 );
	    }
	    remote_user = login;
	}
    }

    if ( krbtkts ) {
	if (( krbtkt_path = getenv( "KRB5CCNAME" )) == NULL ) {
	    fprintf( stderr, "Kerberos ticket transfer is on, "
		     " but no tickets were found in the environment\n" );
	} else if ( strncmp( krbtkt_path, "FILE:", 5 ) == 0 ) {
	    krbtkt_path += 5;
	}
    }

    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) && ( *qs != '\0' )) {
	if (( p = strtok( qs, "&" )) == NULL ) {
	    sl[ SL_TITLE ].sl_data = "Error: Unrecognized Service";
	    sl[ SL_ERROR ].sl_data = "Unable to determine referring "
		    "service from query string.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 400 );
	    exit( 0 );
	}

	if ( remote_user && strcmp( p, "basic" ) == 0 ) {
	    rebasic = 1;
	    p = strtok( NULL, "&" );
	}

	if ( strcmp( p, "reauth" ) == 0 ) {
	    sp.sp_reauth = reauth = 1;
	    p = strtok( NULL, "&" );
	}

	// XXX comma separated list of required factors
	if ( p != NULL && strncmp( p, "factors=", 8 ) == 0 ) {
	    if (( rfactors = strchr( p, '=' )) == NULL ) {
		sl[ SL_TITLE ].sl_data = "Error: malformatted factors";
		sl[ SL_ERROR ].sl_data = "Unable to determine required "
			"factors from query string.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 400 );
		exit( 0 );
	    }
	    rfactors++;
	    sl[ SL_RFACTOR ].sl_data = rfactors;
	    p = strtok( NULL, "&" );
	}

	if ( p != NULL ) {
	    service = p;
	    len = strlen( service );
	    if ( service[ len - 1 ] == ';' ) {
		service[ len - 1 ] = '\0';
	    }
	    if ( strncmp( service, "cosign-", 7 ) != 0 ) {
		sl[ SL_TITLE ].sl_data = "Error: Unrecognized Service";
		sl[ SL_ERROR ].sl_data = "Bad service in query string.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 400 );
		exit( 0 );
	    }
	    sl[ SL_SERVICE ].sl_data = service;

	    /*
	     * Everything after the service to the end of the query string
	     * is the ref.
	     */
	    if (( ref = strtok( NULL, "" )) == NULL ) {
		sl[ SL_TITLE ].sl_data = "Error: malformatted referrer";
		sl[ SL_ERROR ].sl_data = "Unable to determine referring "
			"service from query string.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 400 );
		exit( 0 );
	    }
	    sl[ SL_REF ].sl_data = ref;
	}
    }

    if (( data = getenv( "HTTP_COOKIE" )) != NULL ) {
	for ( cookie = strtok( data, ";" ); cookie != NULL;
		cookie = strtok( NULL, ";" )) {
	    while ( *cookie == ' ' ) ++cookie;
	    if ( strncmp( cookie, "cosign=", 7 ) == 0 ) {
		break;
	    }
	}
    }

    if ( cookie == NULL ) {
	if (( strcmp( method, "POST" ) == 0 ) || rebasic ) {
	    sl[ SL_TITLE ].sl_data = "Error: Cookies Required";
	    sl[ SL_ERROR ].sl_data = "This service requires that "
		    "cookies be enabled.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 400 );
	    exit( 0 );
	}
	goto loginscreen;
    }

    len = strlen( cookie );
    if ( len < 120 || len > 1024 ) {
	goto loginscreen;
    }

    (void)strtok( cookie, "/" );
    if (( misc = strtok( NULL, "/" )) != NULL ) {
	cookietime = atoi( misc );

	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    sl[ SL_TITLE ].sl_data = "Error: Login Screen";
	    sl[ SL_ERROR ].sl_data = "Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	if (( tv.tv_sec - cookietime ) > MAXCOOKIETIME ) {
	    goto loginscreen;
	}
    }

    if (( misc = strtok( NULL, "/" )) != NULL ) {
	cookiecount = atoi( misc );
    }

	/* after here, we have a well-formed cookie */

    /* setup conn and ssl and hostlist */
    if (( head = connlist_setup( cosign_host, cosign_port )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server.  Please try again later.";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit( 0 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx ) != 0 ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Failed to initialise connections "
		"to the authentication server. Please try again later";
	subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	exit( 0 );
    }

    if ( service != NULL && ref != NULL ) {

	/* basic's implicit register */
	if ( rebasic && cosign_login( head, cookie, ip_addr, remote_user,
		    realm, krbtkt_path ) < 0 ) {
	    fprintf( stderr, "cosign_login: basic login failed\n" ) ;
	    sl[ SL_TITLE ].sl_data = "Error: Please try later";
	    sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		    "authentication server. Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	    if (( p = strchr( service, '=' )) == NULL ) {
	    scheme = 3;
	    scookie = service_find( service, matches, nmatch );
	} else {
	    /* legacy cosign scheme */
	    *p = '\0';
	    scookie = service_find( service, matches, nmatch );
	    *p = '=';
	}
	if ( scookie == NULL ) {
	    fprintf( stderr, "no matching service for %s\n", service );
	    sl[ SL_TITLE ].sl_data = "Error: Unknown service";
	    sl[ SL_ERROR ].sl_data = "We were unable to locate a "
		    "service matching the one provided.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	if ( match_substitute( scookie->sl_wkurl, sizeof( matchbuf ),
		matchbuf, nmatch, matches, service ) != 0 ) {
	    fprintf( stderr, "regex substitution failed: %s into %s\n",
		service, scookie->sl_wkurl );
	    sl[ SL_TITLE ].sl_data = "Error: Unknown service";
	    sl[ SL_ERROR ].sl_data = "We were unable to locate a "
		    "service matching the one provided.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	if ( scheme == 2 && !( scookie->sl_flag & SL_SCHEME_V2 )) {
	    fprintf( stderr, "requested v2 for v3 service %s\n", service );
	    sl[ SL_TITLE ].sl_data = "Error: Unknown service";
	    sl[ SL_ERROR ].sl_data = "We were unable to locate a "
		    "service matching the one provided.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	if ( cosign_check( head, cookie, &ui ) != 0 ) {
	    goto loginscreen;
	}

	if ( reauth ) {
	    scookie->sl_flag |= SL_REAUTH;
	}

	if ( !rebasic ) {
	    if ( scookie->sl_flag & SL_REAUTH ) {
		/* ui struct populated by cosign_check if good cookie */
		goto loginscreen;
	    }
	}

	if ( strcmp( ui.ui_ipaddr, ip_addr ) != 0 ) {
	    goto loginscreen;
	}

	ufactors = getuserfactors( userfactorpath, ui.ui_login );

	if ( rfactors != NULL ) {
	    if ( parasitic_suffix ) {
		if ( factor_set_dependencies( scookie,
					      sl[ SL_RFACTOR ].sl_data,
					      parasitic_suffix ) != 0 ) {
		    fprintf( stderr, "failed to set factor dependencies from "
				     "factorlist %s for service %s\n",
				     sl[ SL_RFACTOR ].sl_data,
				     scookie->sl_cookie );
		    sl[ SL_TITLE ].sl_data = "Error: Internal error";
		    sl[ SL_ERROR ].sl_data = "Failed to set factor "
					     "dependencies";
		    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		    exit( 0 );
		}
	    }
	}

	/*
	 * We don't decide exactly what factors to put in SL_RFACTOR until
	 * just before returning the login page, so it's A-OK to handle user
	 * and required factors separately.
	 */
	if ( !satisfied( ui.ui_factors, ufactors ) ||
		(!( rc = satisfied( ui.ui_factors, rfactors )) ||
		COSIGN_FACTOR_REAUTH_REQUIRED( rc ))) {
	    if ( COSIGN_FACTOR_REAUTH_REQUIRED( rc )) {
		scookie->sl_flag |= SL_REAUTH;
	    } 
	    sl[ SL_ERROR ].sl_data = "Additional authentication is required.";
	    goto loginscreen;
	}

	imploded_factors[ 0 ] = '\0';
	if ( scheme == 3 ) {
	    /* cosign3 scheme, must generate new service cookie */
	    if ( mkscookie( service, new_scookie,
			    sizeof( new_scookie )) != 0 ) {
		fprintf( stderr, "%s: mkscookie failed\n", script );
		sl[ SL_TITLE ].sl_data = "Error: Make Service Cookie Failed";
		sl[ SL_ERROR ].sl_data = "We were unable to create a service "
		    "cookie. Please try again later.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }
	    service = new_scookie;

	    /* Generate an imploded required-factor list. */
	    if ( rfactors != NULL ) {
		if ( implode_factors( rfactors, imploded_factors, sizeof(imploded_factors) ) == 0 ) {
		    fprintf( stderr, "%s: implode_factors failed\n", script );
		    sl[ SL_TITLE ].sl_data = "Error: implode_factors Failed";
		    sl[ SL_ERROR ].sl_data = "We were unable to create a service "
			"factor list. Please try again later.";
		    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		    exit( 0 );
		}
	    }
	}

	if (( rc = cosign_register( head, cookie, ip_addr, service, imploded_factors)) < 0 ) {
	    fprintf( stderr, "%s: cosign_register failed\n", script );
	    sl[ SL_TITLE ].sl_data = "Error: Register Failed";
	    sl[ SL_ERROR ].sl_data = "We were unable to contact "
		    "the authentication server.  Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	loop_checker( cookietime, cookiecount, cookie );

	if ( scheme == 3 ) {
	    printf( "Location: %s?%s&%s\n\n", matchbuf, service, ref );
	} else {
	    printf( "Location: %s\n\n", ref );
	}
	exit( 0 );
    }

    if ( strcmp( method, "POST" ) != 0 ) {
	if ( cosign_check( head, cookie, &ui ) != 0 ) {
	    if ( !rebasic ) {
		goto loginscreen;
	    }
	    if ( cosign_login( head, cookie, ip_addr, remote_user,
			realm, krbtkt_path ) < 0 ) {
		fprintf( stderr, "cosign_login: basic login failed\n" ) ;
		sl[ SL_TITLE ].sl_data = "Error: Please try later";
		sl[ SL_ERROR ].sl_data = "We were unable to contact the "
			"authentication server. Please try again later.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }
	}

	/* authentication successful, show service menu */
	if ( server_port != 443 ) {
	    printf( "Location: https://%s:%d%s\n\n", server_name,
		    server_port, SERVICE_MENU );
	} else {
	    printf( "Location: https://%s%s\n\n", server_name, SERVICE_MENU );
	}
	exit( 0 );
    }

    /* after here we want to report errors on the login screen */
    tmpl = LOGIN_ERROR_HTML;

    if (( cgi = cgi_init()) == NULL ) {
        sl[ SL_TITLE ].sl_data = "Error: Server Error";
        sl[ SL_ERROR ].sl_data = "cgi_init failed";
        subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
        exit( 0 );
    }  

    /* insert factor form fields into cl */
    for ( fl = factorlist; fl != NULL; fl = fl->fl_next ) {
	for ( ff = fl->fl_formfield; *ff != NULL; ff++ ) {
	    for ( i = 0; i < ( sizeof( cl ) / sizeof( cl[ 0 ] )) - 1; i++ ) {
		if ( cl[ i ].cl_key == NULL ) {
		    cl[ i ].cl_key = *ff;
		    cl[ i ].cl_type = CGI_TYPE_STRING;
		    break;
		}
		if ( strcmp( *ff, cl[ i ].cl_key ) == 0 ) {
		    break;
		}
	    }
	    if ( cl[ i ].cl_key == NULL ) {
		sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
		sl[ SL_ERROR ].sl_data = "Too many form fields configured.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }
	}
    }

    if ( cgi_post( cgi, cl ) != 0 ) {
	exit( 1 );
    }

    if ( cl[ CL_REF ].cl_data != NULL ) {
        ref = sp.sp_ref = sl[ SL_REF ].sl_data = cl[ CL_REF ].cl_data;
    }
    if ( cl[ CL_SERVICE ].cl_data != NULL ) {
	service = sp.sp_service =
		sl[ SL_SERVICE ].sl_data = cl[ CL_SERVICE ].cl_data;
    }
    if ( cl[ CL_RFACTOR ].cl_data != NULL ) {
	rfactors = sp.sp_factor =
		sl[ SL_RFACTOR ].sl_data = cl[ CL_RFACTOR ].cl_data;
    }
    if (( cl[ CL_REAUTH ].cl_data != NULL ) && 
	    ( strcmp( cl[ CL_REAUTH ].cl_data, "true" ) == 0 )) {
	reauth = sp.sp_reauth = 1;
    }

    if ( cosign_check( head, cookie, &ui ) == 0 ) {
	/*
	 * We're setting CL_LOGIN because we pass cl (not login) to
	 * the external factors.
	 */
	login = cl[ CL_LOGIN ].cl_data = ui.ui_login;
    } else {
	if ( cl[ CL_LOGIN ].cl_data == NULL ) {
	    sl[ SL_TITLE ].sl_data = "Authentication Required";
	    sl[ SL_ERROR ].sl_data = "Please enter your login and password.";
	    goto loginscreen;
	}
	login = sl[ SL_LOGIN ].sl_data = cl[ CL_LOGIN ].cl_data;
    }
    if ( strcmp( ui.ui_ipaddr, ip_addr ) != 0 ) {
	sp.sp_ipchanged = 1;
    }

#if defined( SQL_FRIEND ) || defined( KRB )
    if ( cl[ CL_PASSWORD ].cl_data != NULL ) {
	struct matchlist *pos = NULL;
	char *type = NULL;
	char *username = NULL;

	/* Check our login address against the passwd authenticators and 
	 * find one that is willing to handle it 
 	 */
        while ( pick_authenticator( login,
		&type, &username, &realm, &pos ) == 0 ) {
#ifdef SQL_FRIEND
            if ( strcmp( type, "mysql" ) == 0 ) {
	        if (( rc = cosign_login_mysql( head, login, username, realm, 
					cl[ CL_PASSWORD ].cl_data, ip_addr,
					cookie, &sp, &msg )) == COSIGN_CGI_OK) {
		    goto loggedin;
	        }
	    } else
# endif  /* SQL_FRIEND */
# ifdef KRB
            if ( strcmp( type, "kerberos" ) == 0 ) {
	        if (( rc = cosign_login_krb5( head, login, username, realm, 
				        cl[ CL_PASSWORD ].cl_data, ip_addr,
					cookie, &sp, &msg )) == COSIGN_CGI_OK) {
		    goto loggedin;
                }
	    } else
#endif /* KRB5 */
	    {
                rc = COSIGN_CGI_ERROR;
	        fprintf( stderr, "Unknown authentication type '%s'", type );
	    }
        }

	if ( rc == COSIGN_CGI_PASSWORD_EXPIRED ) {
	    sl[ SL_TITLE ].sl_data = "Password Expired";
	    sl[ SL_ERROR ].sl_data = msg;
            subfile( EXPIRED_ERROR_HTML, sl, 0 );
            exit( 0 ); 
        }

	sl[ SL_TITLE ].sl_data = "Authentication Required";
	if ( msg != NULL && strlen( msg ) > 0 ) {
	    sl[ SL_ERROR ].sl_data = msg;
	} else {
	    sl[ SL_ERROR ].sl_data = "Password or Account Name incorrect. "
		    "Is [caps lock] on?";
	}
	goto loginscreen;

loggedin:
	/* If we just received any new factors, and they match any of our 
	 * suffix factors, then we want to do proxy login for those creds
	 * as well. This grants "real" factors for parasitic factors... */
	for ( i=0; new_factors[ i ] != NULL; i++ ) {
	    for ( subst_factor = strtok( sl[ SL_RFACTOR ].sl_data, ",");
		      subst_factor;
		      subst_factor = strtok( NULL, "," ) ) {
		switch ( match_factor( subst_factor, 
				       new_factors[ i ],
				       parasitic_suffix ) ) {
		case kSUBSTITUTED_REV:
		    if ( cosign_login( head,
				       cookie,
				       ip_addr, 
				       login,
				       subst_factor,
				       NULL ) < 0 ) {
			sl[ SL_TITLE ].sl_data = "Error: Please try later";
			sl[ SL_ERROR ].sl_data = "We were unable to "
			    "contact the authentication server. Please "
			    "try again later.";
			subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
			exit( 0 );

		 /* We deliberately ignore kSUBSTITUTED_FWD and kSATISFIED. */
		    }
		}
	    }
	}

	(void)cosign_check( head, cookie, &ui );
    }
#endif /* SQL_FRIEND || KRB */

    /*
     * compare factor form fields with posted form fields, call
     * authenticators accordingly.
     */
    for ( fl = factorlist; fl != NULL; fl = fl->fl_next ) {
	for ( ff = fl->fl_formfield; *ff != NULL; ff++ ) {
	    for ( i = 0; cl[ i ].cl_key != NULL; i++ ) {
		if ( strcmp( *ff, cl[ i ].cl_key ) == 0 ) {
		    break;
		}
	    }
	    if ( cl[ i ].cl_key == NULL || cl[ i ].cl_data == NULL ) {
		break;
	    }
	}
	if ( *ff != NULL ) {
	    continue;
	}

	if (( fl->fl_flag == 2 ) && ( *ui.ui_login == '\0' )) {
	    sl[ SL_TITLE ].sl_data = "Authentication Required";
	    sl[ SL_ERROR ].sl_data = "Primary authentication is required"
		    " before secondary authentication.";
	    goto loginscreen;
	}
	if (( rc = execfactor( fl, cl, NULL, &msg )) != COSIGN_CGI_OK ) {
	    sl[ SL_ERROR ].sl_data = msg;
            if ( rc == COSIGN_CGI_PASSWORD_EXPIRED ) {
	        sl[ SL_TITLE ].sl_data = "Password Expired";
                subfile( EXPIRED_ERROR_HTML, sl, 0 );
                exit( 0 );
            } else {
	        sl[ SL_TITLE ].sl_data = "Authentication Required";
            }
	    goto loginscreen;
	}

	for ( i = 0; i < COSIGN_MAXFACTORS - 1; i++ ) {
	    if ( new_factors[ i ] == NULL ) {
		new_factors[ i ] = strdup( msg );
		new_factors[ i + 1 ] = NULL;
		break;
	    }
	    if ( strcmp( new_factors[ i ], msg ) == 0 ) {
		break;
	    }
	}

	/*
	 * Don't call cosign_login() if the factor in question is
	 * already satisfied.
	 */
	for ( i = 0; ui.ui_factors[ i ] != NULL; i++ ) {
	    if ( strcmp( msg, ui.ui_factors[ i ] ) == 0 ) {
		break;
	    }
	}
	if (( ui.ui_factors[ i ] == NULL ) ||
		( strcmp( ui.ui_ipaddr, ip_addr ) != 0 )) {
	    if ( cosign_login( head, cookie, ip_addr, login, msg, NULL ) < 0 ) {
		sl[ SL_TITLE ].sl_data = "Error: Please try later";
		sl[ SL_ERROR ].sl_data = "We were unable to contact the "
			"authentication server. Please try again later.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }

	    (void)cosign_check( head, cookie, &ui );
	}
    }

    if ( *ui.ui_login == '\0' ) {
	sl[ SL_TITLE ].sl_data = "Authentication Required";
	sl[ SL_ERROR ].sl_data = "Please enter your login and password.";
	goto loginscreen;
    }

    ufactors = getuserfactors( userfactorpath, ui.ui_login );

    if ( !satisfied( ui.ui_factors, ufactors ) ||
	    (!(rc = satisfied( ui.ui_factors, rfactors )) ||
	    COSIGN_FACTOR_REAUTH_REQUIRED( rc ))) {
	if ( COSIGN_FACTOR_REAUTH_REQUIRED( rc )) {
	    reauth = 1;
	}
	sl[ SL_ERROR ].sl_data = "Additional authentication is required.";
	goto loginscreen;
    }

    if ( service != NULL && ref != NULL ) {
	if (( p = strchr( service, '=' )) == NULL ) {
	    scheme = 3;
	    scookie = service_find( service, matches, nmatch );
	} else {
	    /* legacy cosign scheme */
	    *p = '\0';
	    scookie = service_find( service, matches, nmatch );
	    *p = '=';
	}
	if ( scookie == NULL ) {
	    fprintf( stderr, "no matching service for %s\n", service );
	    sl[ SL_TITLE ].sl_data = "Error: Unknown service";
	    sl[ SL_ERROR ].sl_data = "We were unable to locate a "
		    "service matching the one provided.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }

	if ( match_substitute( scookie->sl_wkurl, sizeof( matchbuf ),
		matchbuf, nmatch, matches, service ) != 0 ) {
	    fprintf( stderr, "regex substitution failed: %s into %s\n",
		service, scookie->sl_wkurl );
	    sl[ SL_TITLE ].sl_data = "Error: Unknown service";
	    sl[ SL_ERROR ].sl_data = "We were unable to locate a "
		    "service matching the one provided.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	if ( scheme == 2 && !( scookie->sl_flag & SL_SCHEME_V2 )) {
	    fprintf( stderr, "requested v2 for v3 service %s\n", service );
	    sl[ SL_TITLE ].sl_data = "Error: Unknown service";
	    sl[ SL_ERROR ].sl_data = "We were unable to locate a "
		    "service matching the one provided.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}

	if ( parasitic_suffix && cl[ CL_RFACTOR ].cl_data ) {
	    if ( factor_set_dependencies( scookie,
					  (char *)cl[ CL_RFACTOR ].cl_data,
					  parasitic_suffix ) != 0 ) {
		fprintf( stderr, "failed to set factor dependencies\n" );
		sl[ SL_TITLE ].sl_data = "Error: Factor dependencies";
		sl[ SL_ERROR ].sl_data = "Setting factor dependencies failed";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }
	}

	/*
	 * If the service requires reauth, verify that all reauth
	 * required factors have been just satisfied.
	 */
	if ( scookie->sl_flag & SL_REAUTH ) {
	    if ( scookie->sl_factors[ 0 ] == NULL &&
		    new_factors[ 0 ] == NULL ) {
		sl[ SL_ERROR ].sl_data = "Please complete any field"
			" to re-authenticate.";
		goto loginscreen;
	    }
	    if ( !satisfied( scookie->sl_factors, smash( new_factors ))) {
		sl[ SL_ERROR ].sl_data = "Please complete all required"
			" fields to re-authenticate.";
		goto loginscreen;
	    }
	}

	if ( reauth ) {
	    fprintf( stderr, "reauth requested...\n" );
	    scookie->sl_flag |= SL_REAUTH;
	}

	if ( strcmp( ui.ui_ipaddr, ip_addr ) != 0 ) {
	    goto loginscreen;
	}

	imploded_factors[ 0 ] = '\0';
	if ( scheme == 3 ) {
	    /* cosign3 scheme, must generate new service cookie */
	    if ( mkscookie( service, new_scookie,
			    sizeof( new_scookie )) != 0 ) {
		fprintf( stderr, "%s: mkscookie failed\n", script );
		sl[ SL_TITLE ].sl_data = "Error: Make Service Cookie Failed";
		sl[ SL_ERROR ].sl_data = "We were unable to create a service "
		    "cookie. Please try again later.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	    }

	    if ( sl[ SL_RFACTOR ].sl_data != NULL ) {
	      if ( implode_factors( sl[ SL_RFACTOR ].sl_data, 
				    imploded_factors,
				    sizeof(imploded_factors) ) == 0 ) {
		fprintf( stderr, 
			 "%s: implode_scookie_factors failed\n", 
			 script );
		sl[ SL_TITLE ].sl_data = "Error: Implode SCookie Factors Failed";
		sl[ SL_ERROR ].sl_data = "We were unable to create a service "
		    "factor list. Please try again later.";
		subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
		exit( 0 );
	      }
	    }
	    service = new_scookie;
	}

        if (( rc = cosign_register( head, cookie, ip_addr, service, imploded_factors )) < 0 ) {
            fprintf( stderr, "%s: implicit cosign_register failed\n", script );
            sl[ SL_TITLE ].sl_data = "Error: Implicit Register Failed";
            sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		    "authentication server.  Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
            exit( 0 );
        }

	loop_checker( cookietime, cookiecount, cookie );

	if ( scheme == 3 ) {
	    printf( "Location: %s?%s&%s\n\n", matchbuf, service, ref );
	} else {
	    printf( "Location: %s\n\n", ref );
	}
	exit( 0 );
    }

    if ( server_port != 443 ) {
	printf( "Location: https://%s:%d%s\n\n", server_name,
		server_port, SERVICE_MENU );
    } else {
	printf( "Location: https://%s%s\n\n", server_name, SERVICE_MENU );
    }
    exit( 0 );

loginscreen:
    if ( *ui.ui_login == '\0' ) {
	if ( tmpl == NULL ) {
	    tmpl = LOGIN_HTML;
	}

	if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
	    fprintf( stderr, "%s: mkcookie: failed\n", script );
	    exit( 1 );
	}
	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    sl[ SL_TITLE ].sl_data = "Error: Login Screen";
	    sl[ SL_ERROR ].sl_data = "Please try again later.";
	    subfile( ERROR_HTML, sl, SUBF_OPT_SETSTATUS, 500 );
	    exit( 0 );
	}
	snprintf( new_cookie, sizeof( new_cookie ), "cosign=%s/%lu",
		new_cookiebuf, tv.tv_sec );
	printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );

	if ( remote_user ) {
	    if ( server_port != 443 ) {
		printf( "Location: https://%s:%d%s?basic",
			server_name, server_port, script );
	    } else {
		printf( "Location: https://%s%s?basic", server_name, script );
	    }
	    if (( ref != NULL ) && ( service != NULL )) {
		printf( "&%s&%s\n\n", service, ref );
	    } else {
		fputs( "\n\n", stdout );
	    }
	    exit( 0 );
	}

    } else {
	sl[ SL_LOGIN ].sl_data = ui.ui_login;
	if (( scookie == NULL ) && ( service != NULL )) {
	    if (( p = strchr( service, '=' )) == NULL ) {
		scheme = 3;
		scookie = service_find( service, matches, nmatch );
	    } else {
		/* legacy cosign scheme */
		*p = '\0';
		scookie = service_find( service, matches, nmatch );
		*p = '=';
	    }
	}

	if ( req_more_auth ) {
	    scookie->sl_flag |= SL_REAUTH;
	}

	if ( scookie != NULL && (( scookie->sl_flag & SL_REAUTH ) || reauth )) {

	    sl[ SL_DFACTOR ].sl_data = NULL;
	    if ( scookie->sl_factors[ 0 ] != NULL ) {
		/*
		 * XXX
		 * ufactors and rfactors that haven't yet been satisfied,
		 * but aren't in sl_factors still ought to be in SL_RFACTOR.
		 */
		sl[ SL_RFACTOR ].sl_data = smash( scookie->sl_factors );
	    } else {
		/*
		 * Might be better to let the user pick a factor.
		 */
		sl[ SL_RFACTOR ].sl_data = ui.ui_factors[ 0 ];
	    }

	    sl[ SL_TITLE ].sl_data = "Re-Authentication Required";
	    if ( sl[ SL_ERROR ].sl_data == NULL ) {
		sl[ SL_ERROR ].sl_data = "Please Re-Authenticate.";
	    }
	    tmpl = REAUTH_HTML;
	} else if ( strcmp( ui.ui_ipaddr, ip_addr ) != 0 ) {
	    sl[ SL_DFACTOR ].sl_data = NULL;
	    sl[ SL_RFACTOR ].sl_data = ui.ui_factors[ 0 ];
	    sl[ SL_TITLE ].sl_data = "Re-Authentication Required";
	    if ( sl[ SL_ERROR ].sl_data == NULL ) {
		sl[ SL_ERROR ].sl_data = "Re-authenticate to confirm"
			" your new Internet address.";
	    }
	    tmpl = REAUTH_HTML;
	} else {
	    /*
	     * XXX
	     * For the sake of the user interface, we'd like SL_RFACTORS to
	     * contain ufactors and rfactors.
	     */
	    sl[ SL_DFACTOR ].sl_data = smash( ui.ui_factors );
	    sl[ SL_RFACTOR ].sl_data = rfactors;
	    tmpl = LOGIN_ERROR_HTML;
	}
    }

    subfile( tmpl, sl, SUBF_OPT_NOCACHE );
    exit( 0 );
}
