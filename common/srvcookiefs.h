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

struct cfs_funcs {
  int (*f_init)(char *, int );
  void (*f_destroy)( );
  int (*f_validate)( char *, int, int );
  int (*f_logout)( char * );
  int (*f_read) ( char *, struct cinfo * );
  int (*f_write) ( char *, struct cinfo * );
  int (*f_register) (char *, char *, char *[], int );
  int (*f_service_to_login) ( char *, char * );
  int (*f_delete) ( char * );
  int (*f_eat) ( char *, struct timeval 8, time_t *, int *, int, int, int );
  int (*f_touch) ( char * );
  int (*f_touch_factor) ( char *, char *, int );
  int (*f_idle_out_factors) ( char *, char *, unsigned int );
};
