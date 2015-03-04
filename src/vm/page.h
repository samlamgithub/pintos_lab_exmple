#ifndef PAGE_H
#define PAGE_H

#include "lib/kernel/hash.h"
#include "filesys/off_t.h"
#include "devices/block.h"

struct sup_page {
  void *kpage;
  size_t page_read_bytes;
  size_t page_zero_bytes;
  void *upage;
  struct file *file;
  bool writable;
  off_t ofs;
  struct hash_elem hash_elem;
  struct list_elem list_elem;
  block_sector_t sector;
  bool has_swap;
};

void page_init (struct hash*);
bool page_load (struct sup_page *);

#endif /* PAGE_H */
