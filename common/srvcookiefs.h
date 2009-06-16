#include <sys/time.h>

struct cinfo {
    int         ci_version;
    int         ci_state;
    char        ci_ipaddr[ 256 ];       /* longer than necessary */
    char        ci_ipaddr_cur[ 256 ];   /* longer than necessary */
    char        ci_user[ 130 ];         /* "64@64\0" */
    char        ci_realm[ 256 ];        /* longer than necessary */
    char        ci_ctime[ 12 ];
    char        ci_krbtkt[ MAXPATHLEN ];
    time_t      ci_itime;
};

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
