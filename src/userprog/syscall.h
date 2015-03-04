#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "process.h"

struct file_des {
  int fd;
  struct file* file;
  struct list_elem elem;
};

struct map_file {
  struct file_des *fd;
  uint32_t *pd;
  struct file *file;
  struct list pages;
  int map_id;
  struct list_elem elem;
};

void syscall_init (void);
int syscall_exit (int);

#endif /* userprog/syscall.h */
