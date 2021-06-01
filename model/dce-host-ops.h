#include "lkl.h"
#include "lkl_host.h"

int (*fx_lkl_start_kernel)(struct lkl_host_operations *,const char *);
struct lkl_netdev * (*fx_lkl_netdev_tap_create)(const char *, int);
int (*fx_lkl_netdev_add)(struct lkl_netdev *,struct lkl_netdev_args *);
struct lkl_host_operations * lib_lkl_host_ops ; 

int (*fx_lkl_set_fd_limit)(unsigned int);
long (*fx_lkl_sys_mknod)(const char * , mode_t , dev_t);
long (*fx_lkl_sys_open)(const char* , int , int);
long (*fx_lkl_sys_dup)(unsigned int);
int (*fx_lkl_if_up)(int);

long (*fx_lkl_syscall)(long , long *);

int (*fx_lkl_sysctl)(const char *, const char *);
int (*fx_lkl_sysctl_get)(const char *, char *, int);

void (*fx_lkl_ioremap)(long, int);
int (*fx_lkl_iomem_access)(const volatile void *, void *, int , int );
void (*fx_jmp_buf_set)(struct lkl_jmp_buf *, void (*)(void));
void (*fx_jmp_buf_longjmp)(struct lkl_jmp_buf *, int );
char * char_lkl_virtio_devs;
