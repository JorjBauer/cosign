#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include "srvcookiefs.h"
#include "mkcookie.h"

/*
  gcc srvcookietest.c srvcookiefs.c mkcookie.c fbase64.c -lcrypto
 
  gcc -I/sw/include/mysql -L/sw/lib/mysql srvcookietest.c \
      srvcookiefs-mysql.c mkcookie.c fbase64.c -lcrypto -lmysqlclient
 */

int compare_ci ( struct cinfo *a, struct cinfo *b )
{
  if (a->ci_version != b->ci_version)
    return 0;
  if (a->ci_state != b->ci_state)
    return 0;
  if (strcmp(a->ci_ipaddr, b->ci_ipaddr))
    return 0;
  if (strcmp(a->ci_ipaddr_cur, b->ci_ipaddr_cur))
    return 0;
  if (strcmp(a->ci_user, b->ci_user))
    return 0;
  if (strcmp(a->ci_realm, b->ci_realm))
    return 0;
  if (strcmp(a->ci_ctime, b->ci_ctime))
    return 0;
  if (strcmp(a->ci_krbtkt, b->ci_krbtkt))
    return 0;
  if (a->ci_itime != b->ci_itime)
    return 0;
  return 1;
}

int main(int argc, char *argv[])
{
  int err;
  char cookiebuf[128];
  char lcookie[1024];
  char scookie[1024];
  char login_buf[1024];
  struct cinfo ci;
  struct cinfo ci2;
  struct cinfo ci3;
  time_t now;
  char now_char[1024];

  openlog("srvcookietest", LOG_NDELAY|LOG_NOWAIT|LOG_PERROR, LOG_LOCAL1);

  mkdir("/tmp/cfstest", 0777);
  printf("Initializing cookiefs\n");
  err = cookiefs_init("/tmp/cfstest/", 0);
  if (err) {
    printf("cookiefs_init returns %d\n", err);
    exit(-1);
  }

  if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
    printf("failed to mkcookie\n");
    exit(-1);
  }
  sprintf(lcookie, "cosign=%s", cookiebuf);
  if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
    printf("failed to mkcookie\n");
    exit(-1);
  }
  sprintf(scookie, "cosign-blooglemuffin=%s", cookiebuf);

  printf("creating login session\n");

  now = time(NULL);
  sprintf(now_char, "%lu", now);

  memset(&ci, 0, sizeof(ci));
  ci.ci_version = 2;
  ci.ci_state = 1; /* must start as 1. Even if it's 0, it starts at 1 on write. */
  strcpy(ci.ci_ipaddr, "127.0.0.1");
  strcpy(ci.ci_ipaddr_cur, "127.0.0.2");
  strcpy(ci.ci_user, "jorj");
  strcpy(ci.ci_realm, "TEST.NET.ISC.UPENN.EDU");
  sprintf(ci.ci_ctime, "%lu", now);
  ci.ci_itime = now; /* Ugly - re-read sets this to mtime of the disk file */
  strcpy(ci.ci_krbtkt, "/tmp/testfile1");

  printf("writing login session\n");
  err = cookiefs_write_login( lcookie, &ci );
  if (err) {
    printf("failed to cookiefs_write_login: %d\n", err);
    exit(-1);
  }

  printf("reading written login session and comparing\n");
  memset(&ci2, 0, sizeof(ci2));
  err = cookiefs_read( lcookie, &ci2 );
  if (err) {
    printf("failed to cookiefs_read: %d\n", err);
    exit(-1);
  }
  if (ci2.ci_version != 2 || ci2.ci_state != 1 ||
      strcmp(ci2.ci_ipaddr, "127.0.0.1") ||
      strcmp(ci2.ci_ipaddr_cur, "127.0.0.2") ||
      strcmp(ci2.ci_user, "jorj") ||
      strcmp(ci2.ci_realm, "TEST.NET.ISC.UPENN.EDU") ||
      atoi(ci2.ci_ctime) != now ||
      ci2.ci_itime != ci.ci_itime ||
      strcmp(ci2.ci_krbtkt, "/tmp/testfile1")) {
    printf("read returned wrong contents\n");
    printf("v: %d/%d; s: %d/%d; ip: %s/%s; ip_c: %s/%s; user: %s/%s; realm: %s/%s; ctime: %s/%s; itime: %lu/%lu; krbtkt: %s:%s\n", 
	   ci2.ci_version, 2,
	   ci2.ci_state, 1,
	   ci2.ci_ipaddr, "127.0.0.1",
	   ci2.ci_ipaddr_cur, "127.0.0.2",
	   ci2.ci_user, "jorj",
	   ci2.ci_realm, "TEST.NET.ISC.UPENN.EDU",
	   ci2.ci_ctime, now_char,
	   ci2.ci_itime, ci.ci_itime,
	   ci2.ci_krbtkt, "/tmp/testfile1");
    exit(-1);
  }

  if ( ! compare_ci( &ci, &ci2 ) ) {
    printf("ERROR: comparison failed\n");
    exit(-1);
  }

  printf("checking for non-existent service cookie\n");
  if ( cookiefs_read(scookie, &ci2) == 0 ) {
    printf("ERROR: read the cookie for %s? Haven't written it yet!\n", scookie);
    exit(-1);
  }

  printf("registering service cookie\n");
  if ( cookiefs_register( lcookie, scookie ) != 0 ) {
    printf("ERROR: unable to cookiefs_register\n");
    exit(-1);
  }

  printf("re-reading service cookie\n");
  memset(login_buf, 0, sizeof(login_buf));
  if ( cookiefs_service_to_login( scookie, login_buf ) != 0 ) {
    printf("Unable to translate from service to login\n");
    exit(-1);
  }

  if (strcmp(login_buf, lcookie)) {
    printf("ERROR: translated to wrong login cookie\n");
    exit(-1);
  }

  memset(&ci2, 0, sizeof(ci2));
  if ( cookiefs_read( login_buf, &ci2 ) ) {
    printf("ERROR: unable to re-read login cookie\n");
    exit(-1);
  }

  if ( ! compare_ci(&ci, &ci2) ) {
    printf( "ERROR: contents of service cookie read are incorrect\n" );
    exit(-1);
  }

  if ( cookiefs_validate( lcookie, (int)ci.ci_ctime, ci.ci_state ) ) {
    printf("ERROR: cookiefs_validate failed\n");
    exit(-1);
  }

  /* going to do a touch. */
  printf("preparing a touch test\n");
  sleep(2);
  now = time( NULL );
  if ( cookiefs_touch( lcookie ) != 0 ) {
    printf("ERROR: cookiefs_touch failed\n");
    exit(-1);
  }
  if ( cookiefs_read( lcookie, &ci2 ) != 0 ) {
    printf("ERROR: unable to read cookie\n");
    exit(-1);
  }

  ci.ci_itime = now; /* for later comparison */
  if (ci2.ci_itime != now ) {
    printf("ERROR: re-read time is incorrect (%lu vs %lu); might be benign if clock crossed a second boundary during the write and those values are off-by-one\n", ci2.ci_itime, now);
    exit(-1);
  }

  printf("testing logout\n");
  if ( cookiefs_logout( lcookie ) != 0 ) {
    printf("ERROR: unable to cookiefs_logout\n");
    exit(-1);
  }

  if (cookiefs_read(lcookie, &ci2 ) != 0 ) {
    printf("ERROR: unable to re-read cookie\n");
    exit(-1);
  }
  if (ci2.ci_state != 0 ) {
    printf("ERROR: cookie is not marked as logged out\n");
    exit(-1);
  }
  ci.ci_state = 0;
  if ( ! compare_ci(&ci, &ci2) ) {
    printf("ERROR: cookie no longer looks correct\n");
    exit(-1);
  }

  if ( cookiefs_delete( lcookie ) != 0 ) {
    printf("ERROR: unable to delete cookie\n");
    exit(-1);
  }

  if ( cookiefs_read(lcookie, &ci2 ) == 0 ) {
    printf("ERROR: was able to re-read cookie after a delete?\n");
    exit(-1);
  }

  /* I thought I might do this, but it turns out the legacy code allows it, so
     it's not a good test. After cookefs_delete, a fully-functioning system 
     should also delete any application tokens that related to that login 
     cookie. 

  memset(login_buf, 0, sizeof(login_buf));
  if ( cookiefs_service_to_login( scookie, login_buf ) == 0 ) {
    printf("ERROR: was able to translate service to login after a delete?\n");
    exit(-1);
  }
  */

  /*
    Did not test: 
  int cookiefs_eat_cookie( char *, struct timeval *, time_t *, int *, int, int, int );
  */

  printf("All tests passed.\n");
  return 0;
}
