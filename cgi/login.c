/*
 * Copyright (c) 2005 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <ctype.h>

#ifdef KRB
#include <krb5.h>
#ifndef MAX_KEYTAB_NAME_LEN
#define MAX_KEYTAB_NAME_LEN 1100
#endif /* ndef MAX */
#endif /* KRB */

#include <string.h>
#include <snet.h>

#include "cosigncgi.h"
#include "login.h"
#include "config.h"
#include "network.h"
#include "subfile.h"

#if defined( KRB ) || defined( SQL_FRIEND )

#ifdef KRB
static char	*keytab_path = _KEYTAB_PATH;
static char	*ticket_path = _COSIGN_TICKET_CACHE;
#endif /* KRB */

#define LOGIN_ERROR_HTML        "../templates/login_error.html"
#define ERROR_HTML	        "../templates/error.html"

extern char	*cosign_host, *cosign_conf;

static struct subfile_list sl[] = {
#define SL_LOGIN	0
        { 'l', SUBF_STR, NULL },
#define SL_TITLE	1
        { 't', SUBF_STR, NULL },
#define SL_SERVICE	2
        { 'c', SUBF_STR_ESC, NULL },
#define SL_REF		3
        { 'r', SUBF_STR_ESC, NULL },
#define SL_ERROR	4
        { 'e', SUBF_STR, NULL },
        { '\0', 0, NULL },
};

# ifdef SQL_FRIEND
#include <crypt.h>
#include <mysql.h>

static MYSQL	friend_db;
static char	*friend_db_name = _FRIEND_MYSQL_DB;
static char	*friend_login = _FRIEND_MYSQL_LOGIN;
static char	*friend_passwd = _FRIEND_MYSQL_PASSWD;
# endif  /* SQL_FRIEND */

    static void
lcgi_configure()
{
    char        *val;

# ifdef KRB
    if (( val = cosign_config_get( COSIGNKEYTABKEY )) != NULL ) {
        keytab_path = val;
    }
    if (( val = cosign_config_get( COSIGNTICKKEY )) != NULL ) {
        ticket_path = val;
    }
# endif /* KRB */

# ifdef SQL_FRIEND
    if (( val = cosign_config_get( MYSQLDBKEY )) != NULL ) {
        friend_db_name = val;
    }
    if (( val = cosign_config_get( MYSQLUSERKEY )) != NULL ) {
        friend_login = val;
    }
    if (( val = cosign_config_get( MYSQLPASSWDKEY )) != NULL ) {
        friend_passwd = val;
    }
# endif /* SQL_FRIEND */
}

# ifdef SQL_FRIEND
    void
cosign_login_mysql( struct connlist *head, char *id, char *passwd,
	char *ip_addr, char *cookie, char *ref, char *service )
{
    MYSQL_RES		*res;
    MYSQL_ROW		row;
    char		sql[ 225 ]; /* holds sql query + email addr */
    char		*crypted, *p;
    char		*tmpl = ERROR_HTML; 

    lcgi_configure();

    if ( !mysql_real_connect( &friend_db, friend_db_name, friend_login, friend_passwd, "friend", 3306, NULL, 0 )) {
	fprintf( stderr, mysql_error( &friend_db ));
	sl[ SL_ERROR ].sl_data = "Unable to connect to guest account database.";
	sl[ SL_TITLE ].sl_data = "Database Problem";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    /* Check for sql injection prior to username query */
    for ( p = id; *p != '\0'; p++ ) {
	if (( isalpha( *p ) != 0 ) || (isdigit( *p ) != 0 )) {
	    continue;
	}

	switch ( *p ) {
	    case '@':
	    case '_':
	    case '-':
	    case '.':
	    continue;
	    default:
	    fprintf( stderr, "invalid username: %s %s\n", id, ip_addr );
	    sl[ SL_ERROR ].sl_data = "Provided login appears to be invalid";
	    sl[ SL_TITLE ].sl_data = "Invalid Input";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }
    snprintf( sql, sizeof( sql ),
"SELECT account_name, passwd FROM friends WHERE account_name = '%s'", id );

    if( mysql_real_query( &friend_db, sql, sizeof( sql ))) {
	fprintf( stderr, mysql_error( &friend_db ));
	sl[ SL_ERROR ].sl_data = "Unable to query guest account database.";
	sl[ SL_TITLE ].sl_data = "Server Problem";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( res = mysql_store_result( &friend_db )) == NULL ) {
	/* was there an error?  NULL can be okay. */
	if ( mysql_errno( &friend_db )) {
	    fprintf( stderr, mysql_error( &friend_db ));
	    sl[ SL_ERROR ].sl_data = "Problems connecting to the database.";
	    sl[ SL_TITLE ].sl_data = "Database Connection Problem";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }

    if (( row = mysql_fetch_row( res )) == NULL ) {
	sl[ SL_ERROR ].sl_data = "Password or Account Name incorrect. "
		"Is [caps lock] on?";
	sl[ SL_TITLE ].sl_data = "Authentication Required "
		"( guest account error )";
	if ( ref != NULL ) {
	    sl[ SL_REF ].sl_data = ref;
	}
	if ( service != NULL ) {
	    sl[ SL_SERVICE ].sl_data = service;
	}
	tmpl = LOGIN_ERROR_HTML;
	subfile ( tmpl, sl, 1 );
	exit( 0 );
    }

    /* crypt the user's password */
    crypted = crypt( passwd, row[ 1 ] );

    if ( strcmp( crypted, row[ 1 ] ) != 0 ) {
	mysql_free_result( res );
	mysql_close( &friend_db );

	/* this is a valid friend account but password failed */
	if ( ref != NULL ) {
	    sl[ SL_REF ].sl_data = ref;
	}
	if ( service != NULL ) {
	    sl[ SL_SERVICE ].sl_data = service;
	}
	sl[ SL_ERROR ].sl_data = "Unable to login because guest password "
	    "is incorrect.";
	sl[ SL_TITLE ].sl_data = "Authentication Required "
	    "( guest password incorrect )";
	tmpl = LOGIN_ERROR_HTML;
	subfile( tmpl, sl, 1 );
	exit( 0 );
    }

    mysql_free_result( res );
    mysql_close( &friend_db );

    if ( cosign_login( head, cookie, ip_addr, id, "friend", NULL ) < 0 ) {
	fprintf( stderr, "cosign_login_mysql: login failed\n" ) ;
	sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server. Please try again later.";
	sl[ SL_TITLE ].sl_data = "Error: Please try later";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }
    return;
}
#endif /* SQL_FRIEND */

#ifdef KRB
    void
cosign_login_krb5( struct connlist *head, char *id, char *passwd,
	char *ip_addr, char *cookie, char *ref, char *service )
{
    krb5_error_code             kerror = 0;
    krb5_context                kcontext;
    krb5_principal              kprinc;
    krb5_principal              sprinc;
    krb5_get_init_creds_opt     kopts;
    krb5_creds                  kcreds;
    krb5_ccache                 kccache;
    krb5_keytab                 keytab = 0;
    char                        *realm = "no_realm";
    char			*tmpl = ERROR_HTML; 
    char                        ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    char                        tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];

    lcgi_configure();

    if (( kerror = krb5_init_context( &kcontext ))) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Authentication Required ( kerberos error )";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( kerror = krb5_parse_name( kcontext, id, &kprinc ))) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Authentication Required ( kerberos error )";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    /* need to get realm out */
    if (( kerror = krb5_get_default_realm( kcontext, &realm )) != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Authentication Required ( krb realm error )";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	sl[ SL_ERROR ].sl_data = "An unknown error occurred.";
	sl[ SL_TITLE ].sl_data = "Authentication Required ( kerberos error )";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
	    ticket_path, tmpkrb ) >= sizeof( krbpath )) {
	sl[ SL_ERROR ].sl_data = "An unknown error occurred.";
	sl[ SL_TITLE ].sl_data = "Authentication Required ( krbpath error )";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( kerror = krb5_cc_resolve( kcontext, krbpath, &kccache )) != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Authentication Required ( kerberos error )";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, 10*60*60 );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    if (( kerror = krb5_get_init_creds_password( kcontext, &kcreds, 
	    kprinc, passwd, NULL, NULL, 0, NULL /*keytab */, &kopts ))) {

	if ( kerror == KRB5KRB_AP_ERR_BAD_INTEGRITY ) {
	    sl[ SL_ERROR ].sl_data = "Password incorrect.  Is [caps lock] on?";
	    sl[ SL_TITLE ].sl_data = "Password Incorrect";
	    tmpl = LOGIN_ERROR_HTML;
	    if ( ref != NULL ) {
		sl[ SL_REF ].sl_data = ref;
	    }
	    if ( service != NULL ) {
		sl[ SL_SERVICE ].sl_data = service;
	    }
	    subfile( tmpl, sl, 1 );
	    exit( 0 );
	} else {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "Error";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }

    /* verify no KDC spoofing */
    if ( *keytab_path == '\0' ) {
	if (( kerror = krb5_kt_default_name(
		kcontext, ktbuf, MAX_KEYTAB_NAME_LEN )) != 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "Ticket Verification Error";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    } else {
	if ( strlen( keytab_path ) > MAX_KEYTAB_NAME_LEN ) {
	    sl[ SL_ERROR ].sl_data = "server configuration error";
	    sl[ SL_TITLE ].sl_data = "Ticket Verification Error";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
	strcpy( ktbuf, keytab_path );
    }

    if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "KT Resolve Error";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( kerror = krb5_sname_to_principal( kcontext, NULL, "cosign",
	    KRB5_NT_SRV_HST, &sprinc )) != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Server Principal Error";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( kerror = krb5_verify_init_creds(
	    kcontext, &kcreds, sprinc, keytab, NULL, NULL )) != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Ticket Verify Error";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	krb5_free_principal( kcontext, sprinc );
	exit( 0 );
    }
    (void)krb5_kt_close( kcontext, keytab );
    krb5_free_principal( kcontext, sprinc );

    if (( kerror = krb5_cc_initialize( kcontext, kccache, kprinc )) != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "CC Initialize Error";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( kerror = krb5_cc_store_cred( kcontext, kccache, &kcreds ))
	    != 0 ) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "CC Storing Error";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    krb5_free_cred_contents( kcontext, &kcreds );
    krb5_free_principal( kcontext, kprinc );
    krb5_cc_close( kcontext, kccache );
    krb5_free_context( kcontext );

    /* password has been accepted, tell cosignd */
    if ( cosign_login( head, cookie, ip_addr, id, realm, krbpath ) < 0 ) {
	fprintf( stderr, "cosign_login_krb5: login failed\n") ;
	sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server. Please try again later.";
	sl[ SL_TITLE ].sl_data = "Error: Please try later";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    return;
}

#endif /* KRB */
#endif /* KRB || SQL_FRIEND */
