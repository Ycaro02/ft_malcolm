#ifndef PTHREAD_UTILS_H
#define PTHREAD_UTILS_H

#include <pthread.h>

/* Define the data type for the thread */
typedef pthread_t Thread;
typedef pthread_mutex_t Mtx;
typedef pthread_cond_t ThreadCond;
typedef pthread_mutex_t Mtx;

/**
 * @brief Wrap pthread mutex lock
 */
static inline __attribute((always_inline)) int mtx_lock(Mtx *mtx) {
    return (pthread_mutex_lock(mtx));
}

/**
 * @brief Wrap pthread mutex unlock
 */
static inline __attribute((always_inline)) int mtx_unlock(Mtx *mtx) {
    return (pthread_mutex_unlock(mtx));
}

static inline __attribute((always_inline)) void mtx_destroy(Mtx *mtx) {
    pthread_mutex_destroy(mtx);
}

static inline __attribute((always_inline)) void mtx_init(Mtx *mtx) {
    pthread_mutex_init(mtx, NULL);
}


#endif /* PTHREAD_UTILS_H */