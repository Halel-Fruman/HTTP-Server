#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include "threadpool.h"




threadpool* create_threadpool(int num_threads_in_pool) {
    // Check input parameter
    if (num_threads_in_pool <= 0 || num_threads_in_pool > MAXT_IN_POOL) {
        fprintf(stderr, "error: Invalid number of threads in pool\n");
        return NULL;
    }

    // Allocate memory for the threadpool structure
    threadpool *pool = (threadpool *)calloc(1,sizeof(threadpool));
    if (!pool ) {
        perror("error: malloc");
        return NULL;
    }

    // Initialize the threadpool structure
    pool->num_threads = num_threads_in_pool;
    pool->threads = (pthread_t *)calloc(pool->num_threads , sizeof(pthread_t));
    if (pool->threads == NULL) {
        perror("error: calloc");
        free(pool);
        return NULL;
    }
    pool->qhead = NULL;
    pool->qtail = NULL;
    pool->qsize = 0;

    pool->shutdown = 0;
    pool->dont_accept = 0;
    if (pthread_mutex_init(&(pool->qlock), NULL)) {
        perror("error: pthread_mutex_init");
        free(pool->threads);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&(pool->q_empty), NULL)) {
        perror("error: pthread_cond_init");
        pthread_mutex_destroy(&pool->qlock);
        free(pool->threads);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&(pool->q_not_empty), NULL)) {
        perror("error: pthread_cond_init");
        pthread_mutex_destroy(&pool->qlock);
        pthread_cond_destroy(&pool->q_empty);
        free(pool->threads);
        free(pool);
        return NULL;
    }


    // Create threads
    for (int i = 0; i < num_threads_in_pool; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, do_work, pool)) {
            perror("error: pthread_create");
            pthread_mutex_destroy(&pool->qlock);
            pthread_cond_destroy(&pool->q_empty);
            pthread_cond_destroy(&pool->q_not_empty);
            free(pool->threads);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

void dispatch(threadpool* from_me, dispatch_fn dispatch_to_here, void *arg) {
    pthread_mutex_lock(&from_me->qlock);
    if (from_me->dont_accept) {
        pthread_mutex_unlock(&from_me->qlock);
        return;
    }

    // Create work_t structure and initialize it
    work_t *work = (work_t *)calloc(1, sizeof(work_t));
    if (!work) {
        perror("error: calloc");
        pthread_mutex_unlock(&from_me->qlock);
        return;
    }
    work->routine = dispatch_to_here;
    work->arg = arg;
    work->next = NULL;

    if (!from_me->qsize) {
        from_me->qhead = from_me->qtail = work;
    } else {
        from_me->qtail->next = work;
        from_me->qtail = work;
    }
    from_me->qsize++;

    pthread_cond_signal(&(from_me->q_not_empty));
    pthread_mutex_unlock(&(from_me->qlock));
}



void* do_work(void* p) {
    threadpool *pool = (threadpool *)p;
    while (1) {
        pthread_mutex_lock(&pool->qlock);

        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->qlock);
            pthread_exit(NULL); // Exit thread gracefully
        }
        while (!pool->qsize  ) {
            pthread_cond_wait(&pool->q_not_empty, &pool->qlock);
            if (pool->shutdown) {
                pthread_mutex_unlock(&pool->qlock);
                return NULL;} // Exit thread gracefully
        }
        pool->qsize--;
        work_t *work=pool->qhead;
        if (!pool->qsize)
        {
            pool->qhead = NULL;
            pool->qtail = NULL;
            //queue is empty, check again if the destructor wants to start
            if (pool->dont_accept) //signal the distructor
                pthread_cond_signal(&(pool->q_empty));
        }
        else //advance the head to the next node
            pool->qhead = pool->qhead->next;
        
        pthread_mutex_unlock(&pool->qlock);

        if (work->routine(work->arg) <0) {
            printf("failed to work");

        }
        free(work);
    }
}

void destroy_threadpool(threadpool *pool) {



    pthread_mutex_lock(&pool->qlock);
    pool->dont_accept = 1;
    while (pool->qsize) {
        pthread_cond_wait(&(pool->q_empty), &(pool->qlock));
    }
    pool->shutdown = 1;
    pthread_cond_broadcast(&(pool->q_not_empty)); // Wake up all threads

    pthread_mutex_unlock(&(pool->qlock));

    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    pthread_mutex_destroy(&(pool->qlock));
    pthread_cond_destroy(&(pool->q_not_empty));
    pthread_cond_destroy(&(pool->q_empty));
    free(pool->threads);
    free(pool);}


























