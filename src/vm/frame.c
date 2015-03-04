#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include <list.h>

struct lock frame_lock;
static struct frame* find_frame_to_evict(void);

void
frame_init(void)
{
  list_init(&frame_table);
  lock_init(&frame_lock);
}

void*
frame_allocate (enum palloc_flags flags, void *upage)
{
  void *page = palloc_get_page (flags);
  if (page == NULL) {
    void *page = frame_evict ();
    if (page == NULL)
      PANIC ("CAN NOT EVICT");
  }
  else
    frame_add (page, upage);
  return page;
}

void*
frame_add (void *kvaddr, void *upage)
{
  struct frame *new_frame = malloc (sizeof(struct frame));
  if(new_frame == NULL)
    return NULL;
  lock_acquire (&frame_lock);
  new_frame->owner = thread_current ();
  new_frame->kvaddr = kvaddr;
  new_frame->upage = upage;
  list_push_front (&frame_table, &new_frame->list_elem);
  lock_release (&frame_lock);
  return new_frame->kvaddr;
}

void
frame_remove (void* kvaddr)
{
  struct list_elem *e;
  for (e = list_begin (&frame_table);
       e != list_end (&frame_table);
       e = list_next (e)) {
    struct frame *frame = list_entry (e, struct frame, list_elem);
    if (frame->kvaddr == kvaddr) {
      list_remove (e);
      palloc_free_page (kvaddr);
      free (frame);
    }
  }
}


void*
frame_evict(void)
{
  struct frame *frame = find_frame_to_evict ();
  if (frame == NULL)
    syscall_exit (-1);
  struct hash page_table = frame->owner->page_table;
  struct sup_page new_page;
  new_page.upage = frame->upage;
  struct hash_elem *e = hash_find (&page_table, &new_page.hash_elem);
  struct sup_page *sup_page = hash_entry (e, struct sup_page, hash_elem);
  page_to_sector (sup_page);
  frame_remove (frame->kvaddr);
  return frame->kvaddr;
}

static struct frame*
find_frame_to_evict(void)
{
  struct list_elem *e = list_end (&frame_table);
  return list_entry (e, struct frame, list_elem);
}


