#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

static unsigned
hash_func(const struct hash_elem *e, UNUSED void *aux)
{
  const struct sup_page *page = hash_entry (e, struct sup_page, hash_elem);
  return hash_int ((int) (page->upage));
}

static bool
hash_less(const struct hash_elem *a, const struct hash_elem *b, UNUSED void *aux)
{
  const struct sup_page *page_a = hash_entry (a, struct sup_page, hash_elem);
  const struct sup_page *page_b = hash_entry (b, struct sup_page, hash_elem);
  return page_a->upage < page_b->upage;
}

void
page_init(struct hash *page_table)
{
  hash_init(page_table, &hash_func, &hash_less, NULL);
}

bool
page_load(struct sup_page *page)
{
  struct file *file = page->file;
  off_t ofs = page->ofs;
  uint8_t *upage = page->upage;
  size_t page_read_bytes = page->page_read_bytes;
  size_t page_zero_bytes = page->page_zero_bytes;
  bool writable = page->writable;

  file_seek (file, ofs);
  /* Get a page of memory. */
  uint8_t *kpage = frame_allocate (PAL_USER, page->upage);
  if (kpage == NULL)
    return false;

  /* Load this page. */
  if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
  {
    frame_remove (kpage);
    return false; 
  }
  memset (kpage + page_read_bytes, 0, page_zero_bytes);

  /* Add the page to the process's address space. */
  if (!install_page (upage, kpage, writable)) 
  {
    frame_remove (kpage);
    return false; 
  }
  page->kpage = kpage;
  return true;
}
