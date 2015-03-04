#ifndef FRAME_H
#define FRAME_H

#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame
{
  void* kvaddr;                     /* the virtual memory address of the frame */
  void* upage;
  struct thread *owner;             /* the thread that owns the frame */
  struct list_elem list_elem;
};

void* frame_add (void*, void*);
void  frame_remove (void*);
void* frame_allocate (enum palloc_flags, void*);
void* frame_evict (void);
void  frame_init (void);

struct list frame_table;
#endif /* FRAME_H */
