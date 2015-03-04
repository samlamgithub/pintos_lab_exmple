#include "userprog/syscall.h"
#include <stdio.h>
#include "threads/malloc.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);

typedef int pid_t;

static int syscall_write (int fd, const void *buffer, unsigned size);
static int syscall_halt (void);
static int syscall_create (const char *file, unsigned initial_size);
static int syscall_open (const char *file);
static int syscall_close (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_exec (const char *cmd);
static int syscall_wait (pid_t pid);
static int syscall_filesize (int fd);
static int syscall_tell (int fd);
static int syscall_seek (int fd, unsigned pos);
static int syscall_remove (const char *file);
static int mmap (int fd, void *addr);
static int munmap (int mapping);
static bool pointer_is_safe (const void *);
static bool memory_writable (const void *);

static struct file_des* find_file(int fd);
struct lock filesys_lock;

typedef int (func_t) (uint32_t, uint32_t, uint32_t);
static void* syscall_vec[32];
static struct map_file* find_file_by_mapping (struct list *, int);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  syscall_vec[SYS_EXIT] = &syscall_exit;
  syscall_vec[SYS_HALT] = &syscall_halt;
  syscall_vec[SYS_CREATE] = &syscall_create;
  syscall_vec[SYS_OPEN] = &syscall_open;
  syscall_vec[SYS_CLOSE] = &syscall_close;
  syscall_vec[SYS_READ] = &syscall_read;
  syscall_vec[SYS_WRITE] = &syscall_write;
  syscall_vec[SYS_EXEC] = &syscall_exec;
  syscall_vec[SYS_WAIT] = &syscall_wait;
  syscall_vec[SYS_FILESIZE] = &syscall_filesize;
  syscall_vec[SYS_SEEK] = &syscall_seek;
  syscall_vec[SYS_TELL] = &syscall_tell;
  syscall_vec[SYS_REMOVE] = &syscall_remove;
  syscall_vec[SYS_MMAP] = &mmap;
  syscall_vec[SYS_MUNMAP] = &munmap;
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) {
  func_t *h;
  int *p = f->esp;
  if (!pointer_is_safe (p)){
    syscall_exit (-1);
    return;
  }
  if (*p < SYS_HALT || *p > SYS_INUMBER){
    syscall_exit (-1);
    return;
  }
  h = (func_t *) syscall_vec[*p];
  if (!pointer_is_safe (p+1) || !pointer_is_safe (p+2) || !pointer_is_safe (p+3)) {
    syscall_exit (-1);
    return;
  }
  f->eax = h (*(p+1), *(p+2), *(p+3));
}

static int
syscall_halt (void)
{
  shutdown_power_off();
  return 1;
}

int
syscall_exit (int status)
{
  struct thread *cur = thread_current();
  struct list_elem *elem;
  struct file_des *f;
  cur->ret_status = status;
  while (!list_empty (&cur->fds))
  {
    elem = list_begin (&cur->fds);
    f = list_entry (elem, struct file_des, elem);
    syscall_close (f->fd);
  }
  int i;
  if(status >= 0)    /* Normal exit. */
    for (i = 0; i < cur->next_id; i++)
      munmap (i);
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
  return 1;
}

static pid_t
syscall_exec (const char *cmd_line)
{
  int tid;
  if (!pointer_is_safe (cmd_line)) {
    syscall_exit (-1);
    return -1;
  }
  lock_acquire (&filesys_lock);
  tid = process_execute (cmd_line);
  lock_release (&filesys_lock);

  return tid;
}

static int
syscall_filesize (int fd)
{
  struct file_des *file_des = find_file(fd);
  if(file_des ==NULL) {
    syscall_exit(-1);
    return -1;
  }
  lock_acquire (&filesys_lock);
  int result = file_length(file_des->file);
  lock_release (&filesys_lock);
  return result;
}

static int
syscall_seek (int fd,unsigned position)
{
  struct file_des *file_des = find_file(fd);
  if (file_des == NULL) {
    syscall_exit(-1);
    return -1;
  }
  lock_acquire (&filesys_lock);
  file_seek(file_des->file,position);
  lock_release (&filesys_lock);
  return 1;
}

static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  int ret = -1;
  if(!pointer_is_safe(buffer) || !pointer_is_safe(buffer + size))
    syscall_exit(-1);
  else if(fd == STDOUT_FILENO)
    putbuf(buffer,size);
  else if(fd == STDIN_FILENO)
    syscall_exit (-1);
  else {
    struct file_des* file_des = find_file (fd);
    if(file_des != NULL) {
      lock_acquire (&filesys_lock);
      ret = file_write (file_des->file,buffer,size);
      lock_release (&filesys_lock);
    } else
      syscall_exit (-1);
  }
  return ret;
}

static int
syscall_tell (int fd)
{
  struct file_des *file_des = find_file(fd);
  if(file_des == NULL) {
    syscall_exit(-1);
    return -1;
  }

  lock_acquire (&filesys_lock);
  int ret = (int)file_tell(file_des->file);
  lock_release (&filesys_lock);
  return ret+1;
}

static int
syscall_read (int fd, void *buffer, unsigned size)
{
  int result = -1;
  if(!memory_writable (buffer))
    syscall_exit(-1);
  else if(fd == 1)
    syscall_exit(-1);
  else if(fd == 0)
    for (result = 0; result < (int)size; result++)
      *((char*)buffer+result) = input_getc();
  else{
    struct file_des* file_des = find_file (fd);
    if(file_des != NULL) {
      lock_acquire (&filesys_lock);
      result = file_read(file_des->file, buffer, size);
      lock_release (&filesys_lock);
    }
    else
      syscall_exit (-1);
  }
  return result;
}

static int
syscall_wait(pid_t pid)
{
  return process_wait (pid);
}

static int
syscall_create(const char *file, unsigned initial_size)
{
  if (!pointer_is_safe (file)) {
    syscall_exit(-1);
    return -1;
  }
  lock_acquire (&filesys_lock);
  int ret = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return ret;
}

static int
syscall_remove (const char *file)
{
  if(!pointer_is_safe (file)) {
    syscall_exit (-1);
    return -1;
  }
  lock_acquire (&filesys_lock);
  int ret = filesys_remove (file);
  lock_release (&filesys_lock);
  return ret;
}

static int
syscall_open (const char *file)
{
  if(!pointer_is_safe (file)) {
    syscall_exit (-1);
    return -1;
  }
  lock_acquire (&filesys_lock);
  struct file* f = filesys_open (file);
  lock_release (&filesys_lock);
  if(f == NULL)
    return -1;
  struct thread *cur = thread_current ();
  struct file_des *file_des = malloc(sizeof(file_des));
  if(file_des == NULL) {
    file_close (f);
    syscall_exit (-1);
  } else {
    file_des->fd = cur->maxfd;
    file_des->file = f;
    list_push_front (&cur->fds, &file_des->elem);
    cur->maxfd++;
    return file_des->fd;
  }
  return -1;
}

static int
syscall_close (int fd)
{
  struct file_des *file_des = find_file(fd);
  if(fd < 2 || file_des == NULL) {
    syscall_exit(-1);
    return -1;
  }
  
  lock_acquire (&filesys_lock);
  file_close(file_des->file);
  lock_release (&filesys_lock);
  list_remove(&file_des->elem);
  free(file_des);
  return 1;
}

static struct file_des*
find_file(int fd)
{
  struct list_elem* e;
  struct file_des* result;
  struct thread* t = thread_current();
  for(e = list_begin(&t->fds);e != list_end(&t->fds); e = list_next (e))
    {
      result = list_entry(e, struct file_des, elem);
      if (result->fd == fd)
        return result;
    }
  return NULL;
}

static bool
pointer_is_safe (const void *ptr)
{
  return ptr != NULL && is_user_vaddr(ptr) &&
    pagedir_get_page (thread_current ()->pagedir, ptr) != NULL;
}

/* Check if the page has write access.
   If cannot locate the page in the page table,
   ignore the test and return true.
 */
static bool
memory_writable (const void *p)
{
  if(p == NULL || !is_user_vaddr(p))
    return false;
  if(is_reserved (p))
    return false;

  void *page_addr = pg_round_down (p);
  struct sup_page page;
  page.upage = page_addr;
  struct hash_elem *elem =
    hash_find (&thread_current ()->page_table, &page.hash_elem);
  if(elem == NULL)
    return true;

  struct sup_page *page_entry = hash_entry (elem, struct sup_page, hash_elem);
  return page_entry->writable;
}

static int
mmap (int fd, void *addr)
{
  struct file_des *file_des = find_file (fd);
  struct thread *t = thread_current();
  if (file_des == NULL)
    syscall_exit (-1);
  struct file *file = file_des->file;
  uint32_t file_size = file_length (file);
  if (file_size == 0 || pg_round_down (addr) != addr ||
      addr == 0 || fd == 1 || fd == 0) 
    return -1;
  
  uint32_t page_read_bytes = PGSIZE;
  int num_pages = file_size / PGSIZE;
  if (file_size%PGSIZE != 0)
    num_pages++;

  int i;
  for (i = 0; i <= num_pages; i++) {
    struct sup_page p;
    p.upage = addr + i * PGSIZE;
    if(hash_find (&t->page_table, &p.hash_elem) != NULL)
      return -1;
  }

  struct map_file *map_file = malloc (sizeof (struct map_file));
  if(map_file == NULL)
    PANIC("Insufficient memory");

  list_init (&map_file->pages);
  map_file->fd = file_des;
  map_file->pd = t->pagedir;

  lock_acquire (&filesys_lock);
  map_file->file = file_reopen (file_des->file);
  lock_release (&filesys_lock);

  map_file->map_id = t->next_id;
  t->next_id++;

  for (i = 0; i < num_pages; i++) {
    if (i == num_pages - 1)
      page_read_bytes = file_size-PGSIZE*i;
    struct sup_page *page = malloc (sizeof (struct sup_page));
    if(page == NULL)
      PANIC("Insufficient memory");
    page->file = file_reopen(file);
    page->page_read_bytes = page_read_bytes;
    page->page_zero_bytes = PGSIZE - page_read_bytes;
    page->ofs = i*PGSIZE;
    page->writable = true;
    page->upage = pg_round_down (addr) + i*PGSIZE;
    page->kpage = frame_allocate (PAL_USER, page->upage);
    list_push_front (&map_file->pages, &page->list_elem);
    hash_insert (&t->page_table, &page->hash_elem);
  }
  list_push_front (&t->map_files, &map_file->elem);
  return map_file->map_id;
}

int
munmap (int mapping)
{
  struct thread *t = thread_current ();
  struct map_file *map_file = find_file_by_mapping (&t->map_files, mapping);
  if (map_file == NULL)
    return 0;

  struct list_elem *e;
  struct sup_page *sup_page;
  for (e = list_begin (&map_file->pages);
       e != list_end (&map_file->pages); ) { 
    sup_page = list_entry (e, struct sup_page, list_elem);
    if (pagedir_is_dirty (t->pagedir, sup_page->upage)) {
      lock_acquire (&filesys_lock);
      file_write_at (sup_page->file, sup_page->upage, sup_page->page_read_bytes, sup_page->ofs);
      lock_release (&filesys_lock);
    }
    list_remove (&sup_page->list_elem);
    hash_delete (&t->page_table, &sup_page->hash_elem);
    e = list_next (e);
    free (sup_page);
  }
  list_remove (&map_file->elem);
  free (map_file);
  return 0;
}

struct map_file*
find_file_by_mapping (struct list *map_files, int mapping)
{
  struct list_elem *e;
  struct map_file *file;
  for (e = list_begin (map_files);
       e != list_end (map_files);
       e = list_next (e)) {
    file = list_entry (e, struct map_file, elem);
    if (file->map_id == mapping)
      return file;
  }
  return NULL;
}
