#include <pthread.h>
#include "ssl_mutex.h"

pthread_mutex_t non_ssl_mutex;
pthread_mutex_t ssl_mutex;
pthread_mutex_t *mutex_buf = NULL;
