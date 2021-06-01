#include <lkl.h>
#include <lkl_host.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <poll.h>
#include <lkl_host.h>
#include <dlfcn.h>
/* Let's see if the host has semaphore.h */
#include <unistd.h>

#ifdef _POSIX_SEMAPHORES
#include <semaphore.h>
/* TODO(pscollins): We don't support fork() for now, but maybe one day
 * we will? */
#define SHARE_SEM 0
#endif /* _POSIX_SEMAPHORES */


void lkl_print(const char *str, int len)
{
	int ret __attribute__((unused));
	printf("%s\n",str);
	//ret = write(STDOUT_FILENO, str, len);
}

struct lkl_mutex {
	pthread_mutex_t mutex;
};

struct lkl_sem {
#ifdef _POSIX_SEMAPHORES
	sem_t sem;
#else
	pthread_mutex_t lock;
	int count;
	pthread_cond_t cond;
#endif /* _POSIX_SEMAPHORES */
};

struct lkl_tls_key {
	pthread_key_t key;
};

#define WARN_UNLESS(exp) do {						\
		if (exp < 0)						\
			; \
	} while (0)

static int _warn_pthread(int ret, char *str_exp)
{
	if (ret > 0)
		//lkl_printf("%s: %s\n", str_exp, strerror(ret));

	return ret;
}


/* pthread_* functions use the reverse convention */
#define WARN_PTHREAD(exp) _warn_pthread(exp, #exp)

struct lkl_sem *lkl_sem_alloc(int count)
{
	struct lkl_sem *sem;

	sem = malloc(sizeof(*sem));
	if (!sem)
		return NULL;

#ifdef _POSIX_SEMAPHORES
	if (sem_init(&sem->sem, SHARE_SEM, count) < 0) {
		//lkl_printf("sem_init: %s\n", strerror(errno));
		free(sem);
		return NULL;
	}
#else
	pthread_mutex_init(&sem->lock, NULL);
	sem->count = count;
	WARN_PTHREAD(pthread_cond_init(&sem->cond, NULL));
#endif /* _POSIX_SEMAPHORES */

	return sem;
}

void lkl_sem_free(struct lkl_sem *sem)
{
#ifdef _POSIX_SEMAPHORES
	WARN_UNLESS(sem_destroy(&sem->sem));
#else
	WARN_PTHREAD(pthread_cond_destroy(&sem->cond));
	WARN_PTHREAD(pthread_mutex_destroy(&sem->lock));
#endif /* _POSIX_SEMAPHORES */
	free(sem);
}

void lkl_sem_up(struct lkl_sem *sem)
{
#ifdef _POSIX_SEMAPHORES
	WARN_UNLESS(sem_post(&sem->sem));
#else
	WARN_PTHREAD(pthread_mutex_lock(&sem->lock));
	sem->count++;
	if (sem->count > 0)
		WARN_PTHREAD(pthread_cond_signal(&sem->cond));
	WARN_PTHREAD(pthread_mutex_unlock(&sem->lock));
#endif /* _POSIX_SEMAPHORES */

}

void lkl_sem_down(struct lkl_sem *sem)
{
#ifdef _POSIX_SEMAPHORES
	int err;

	do {
		err = sem_wait(&sem->sem);
	} while (err < 0 && errno == EINTR);
	if (err < 0 && errno != EINTR)
		; //lkl_printf("sem_wait: %s\n", strerror(errno));
#else
	WARN_PTHREAD(pthread_mutex_lock(&sem->lock));
	while (sem->count <= 0)
		WARN_PTHREAD(pthread_cond_wait(&sem->cond, &sem->lock));
	sem->count--;
	WARN_PTHREAD(pthread_mutex_unlock(&sem->lock));
#endif /* _POSIX_SEMAPHORES */
}

struct lkl_mutex *lkl_mutex_alloc(int recursive)
{
	struct lkl_mutex *_mutex = malloc(sizeof(struct lkl_mutex));
	pthread_mutex_t *mutex = NULL;
	pthread_mutexattr_t attr;

	if (!_mutex)
		return NULL;

	mutex = &_mutex->mutex;
	WARN_PTHREAD(pthread_mutexattr_init(&attr));

	/* PTHREAD_MUTEX_ERRORCHECK is *very* useful for debugging,
	 * but has some overhead, so we provide an option to turn it
	 * off. */
#ifdef DEBUG
	if (!recursive)
		WARN_PTHREAD(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
#endif /* DEBUG */

	if (recursive)
		WARN_PTHREAD(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE));

	WARN_PTHREAD(pthread_mutex_init(mutex, &attr));

	return _mutex;
}

void lkl_mutex_lock(struct lkl_mutex *mutex)
{
	WARN_PTHREAD(pthread_mutex_lock(&mutex->mutex));
}

void lkl_mutex_unlock(struct lkl_mutex *_mutex)
{
	pthread_mutex_t *mutex = &_mutex->mutex;
	WARN_PTHREAD(pthread_mutex_unlock(mutex));
}

void lkl_mutex_free(struct lkl_mutex *_mutex)
{
	pthread_mutex_t *mutex = &_mutex->mutex;
	WARN_PTHREAD(pthread_mutex_destroy(mutex));
	free(_mutex);
}

lkl_thread_t lkl_thread_create(void (*fn)(void *), void *arg)
{
	pthread_t thread;
	if (WARN_PTHREAD(pthread_create(&thread, NULL, (void* (*)(void *))fn, arg)))
		return 0;
	else
		return (lkl_thread_t) thread;
}

void lkl_thread_detach(void)
{
	WARN_PTHREAD(pthread_detach(pthread_self()));
}

void lkl_thread_exit(void)
{
	pthread_exit(NULL);
}

int lkl_thread_join(lkl_thread_t tid)
{
	if (WARN_PTHREAD(pthread_join((pthread_t)tid, NULL)))
		return -1;
	else
		return 0;
}

lkl_thread_t lkl_thread_self(void)
{
	return (lkl_thread_t)pthread_self();
}

int lkl_thread_equal(lkl_thread_t a, lkl_thread_t b)
{
	return pthread_equal((pthread_t)a, (pthread_t)b);
}

struct lkl_tls_key *lkl_tls_alloc(void (*destructor)(void *))
{
	struct lkl_tls_key *ret = malloc(sizeof(struct lkl_tls_key));

	if (WARN_PTHREAD(pthread_key_create(&ret->key, destructor))) {
		free(ret);
		return NULL;
	}
	return ret;
}

void lkl_tls_free(struct lkl_tls_key *key)
{
	WARN_PTHREAD(pthread_key_delete(key->key));
	free(key);
}

int lkl_tls_set(struct lkl_tls_key *key, void *data)
{
	if (WARN_PTHREAD(pthread_setspecific(key->key, data)))
		return -1;
	return 0;
}

void *lkl_tls_get(struct lkl_tls_key *key)
{
	return pthread_getspecific(key->key);
}

unsigned long long lkl_time_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return 1e9*ts.tv_sec + ts.tv_nsec;
}

void *lkl_timer_alloc(void (*fn)(void *), void *arg)
{
	int err;
	timer_t timer;
	struct sigevent se =  {
		.sigev_value = {
			.sival_ptr = arg,
		},
		.sigev_notify = SIGEV_THREAD,		
	};
	se.sigev_notify_function = (void (*)(union sigval))fn;

	err = timer_create(CLOCK_REALTIME, &se, &timer);
	if (err)
		return NULL;

	return (void *)(long)timer;
}

int lkl_timer_set_oneshot(void *_timer, unsigned long ns)
{
	timer_t timer = (timer_t)(long)_timer;
	struct itimerspec ts = {
		.it_value = {
			.tv_sec = ns / 1000000000,
			.tv_nsec = ns % 1000000000,
		},
	};

	return timer_settime(timer, 0, &ts, NULL);
}

void lkl_timer_free(void *_timer)
{
	timer_t timer = (timer_t)(long)_timer;

	timer_delete(timer);
}

void lkl_panic(void)
{
	assert(0);
}

long lkl__gettid(void)
{
#ifdef	__FreeBSD__
	return (long)pthread_self();
#else
	return syscall(SYS_gettid);
#endif
}

void *lkl_page_alloc(unsigned long size)
{
	void *addr;

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED)
		return NULL;

	return addr;
}

void lkl_page_free(void *addr, unsigned long size)
{
	munmap((void *)addr, size);
}

#ifdef LKL_HOST_CONFIG_VFIO_PCI
extern struct lkl_dev_pci_ops vfio_pci_ops;
#endif


struct lkl_host_operations lkl_host_ops = {
	.print = lkl_print,
	.panic = lkl_panic,
	.sem_alloc = lkl_sem_alloc,
	.sem_free = lkl_sem_free,
	.sem_up = lkl_sem_up,
	.sem_down = lkl_sem_down,
	.mutex_alloc = lkl_mutex_alloc,
	.mutex_free = lkl_mutex_free,
	.mutex_lock = lkl_mutex_lock,
	.mutex_unlock = lkl_mutex_unlock,
	.thread_create = lkl_thread_create,
	.thread_detach = lkl_thread_detach,
	.thread_exit = lkl_thread_exit,
	.thread_join = lkl_thread_join,
	.thread_self = lkl_thread_self,
	.thread_equal = lkl_thread_equal,		
	.tls_alloc = lkl_tls_alloc,
	.tls_free = lkl_tls_free,
	.tls_set = lkl_tls_set,
	.tls_get = lkl_tls_get,
	.mem_alloc = malloc,
	.mem_free = free,
	.page_alloc = lkl_page_alloc,
	.page_free = lkl_page_free,
	.time = lkl_time_ns,
	.timer_alloc = lkl_timer_alloc,
	.timer_set_oneshot = lkl_timer_set_oneshot,
	.timer_free = lkl_timer_free,			
	//.ioremap = lkl_ioremap,
	//.iomem_access = lkl_iomem_access,
	//.virtio_devices = lkl_virtio_devs,
	.gettid = lkl__gettid,
	//.jmp_buf_set = jmp_buf_set,
	//.jmp_buf_longjmp = jmp_buf_longjmp,
	.memcpy = memcpy,
#ifdef LKL_HOST_CONFIG_VFIO_PCI
	.pci_ops = &vfio_pci_ops,
#endif
};

/*
int main(){
    void * lib_handle;
    int (*fx_lkl_start_kernel)(struct lkl_host_operations *,const char *);
    int (*fx_lkl_sysctl)(const char *, const char *);
    int (*fx_lkl_sysctl_get)(const char *, char *, int);

    int (*fx_lkl_ioremap)(long, int);
    int (*fx_lkl_iomem_access)(const volatile void *, void *, int , int );
    void (*fx_jmp_buf_set)(struct lkl_jmp_buf *, void (*)(void));
    void (*fx_jmp_buf_longjmp)(struct lkl_jmp_buf *, int );
    char * lkl_virtio_devs;

    lib_handle = dlopen("./liblkl.so", RTLD_LAZY);
    fx_lkl_start_kernel =  dlsym(lib_handle, "lkl_start_kernel");
    fx_lkl_sysctl = dlsym(lib_handle, "lkl_sysctl");
    fx_lkl_sysctl_get = dlsym(lib_handle, "lkl_sysctl_get");

    fx_lkl_ioremap = dlsym(lib_handle, "lkl_ioremap");
    fx_lkl_iomem_access = dlsym(lib_handle, "lkl_iomem_access");
    fx_jmp_buf_set = dlsym(lib_handle, "jmp_buf_set");
    fx_jmp_buf_longjmp = dlsym(lib_handle, "jmp_buf_longjmp");
    lkl_virtio_devs = dlsym(lib_handle, "lkl_virtio_devs");
    
    lkl_host_ops.ioremap = fx_lkl_ioremap;
    lkl_host_ops.iomem_access = fx_lkl_iomem_access;
    lkl_host_ops.jmp_buf_set = fx_jmp_buf_set;
    lkl_host_ops.jmp_buf_longjmp = fx_jmp_buf_longjmp;
    lkl_host_ops.virtio_devices = lkl_virtio_devs; 
     
    (*fx_lkl_start_kernel)(&lkl_host_ops,"");
    (*fx_lkl_sysctl)(".net.ipv4.conf.all.forwarding","1");
    char buffer[512]; 
    memset (buffer, 0, sizeof(buffer));
    (*fx_lkl_sysctl_get)(".net.ipv4.tcp_available_congestion_control", buffer, sizeof(buffer));
    printf("%s",buffer);
    dlclose(lib_handle);
    return 0;
}*/