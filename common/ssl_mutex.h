#include <pthread.h>

/* Global ssl_mutex for things that are not in a specific SSL context */
extern pthread_mutex_t ssl_mutex;
extern pthread_mutex_t *mutex_buf;

#define SSL_MUTEX_INIT {pthread_mutex_init(&ssl_mutex, NULL); pthread_mutex_init(&non_ssl_mutex, NULL);}
#define SSL_MUTEX_LOCK {pthread_mutex_lock(&ssl_mutex);}
#define SSL_MUTEX_UNLOCK {pthread_mutex_unlock(&ssl_mutex);}
#define NONSSL_MUTEX_LOCK {pthread_mutex_lock(&non_ssl_mutex);}
#define NONSSL_MUTEX_UNLOCK {pthread_mutex_unlock(&non_ssl_mutex);}
#define SSL_MUTEX_DESTROY {pthread_mutex_destroy(&ssl_mutex); pthread_mutex_destroy(&non_ssl_mutex);}

/* Thread-specific mutexes, designed for use with OpenSSL callbacks */
struct CRYPTO_dynlock_value
{
    pthread_mutex_t mutex;
};

#define SSL_MUTEX_INIT_BUF(m) {pthread_mutex_init(&mutex_buf[m], NULL);}
#define SSL_MUTEX_LOCK_BUF(m) {pthread_mutex_lock(&mutex_buf[m]);}
#define SSL_MUTEX_UNLOCK_BUF(m) {pthread_mutex_unlock(&mutex_buf[m]);}
#define SSL_MUTEX_DESTROY_BUF(m) {pthread_mutex_destroy(&mutex_buf[m]);}
