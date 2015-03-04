#include "swap.h"
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <bitmap.h>
#include "page.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"

struct block *block;
struct lock swap_lock;

extern struct lock filesys_lock;

void
swap_init (void)
{ 
  lock_init (&swap_lock);
  block = block_get_role (BLOCK_SWAP);
  swap_table = bitmap_create (block_size (block) / 8);
}

void
page_to_sector (struct sup_page *page)
{
  ASSERT(swap_table != NULL);
  size_t sector =  bitmap_scan_and_flip (swap_table, 0, 1, false);
  if (sector == BITMAP_ERROR)
    PANIC ("there is no swap space avaliable");
  int i;
  void *upage = page->upage;
  for (i = 0; i < 8; i++) {
    lock_acquire (&filesys_lock);
    block_write (block, sector*8+BLOCK_SECTOR_SIZE*i, upage+BLOCK_SECTOR_SIZE*i);
    lock_release (&filesys_lock);
  }
  page->sector = sector;
  page->has_swap = true;
  page->kpage = NULL;
}

void
sector_to_page (struct sup_page *page)
{
  size_t sector = page->sector;
  void *upage = page->upage;
  int i;
  for (i = 0; i < 8; i++) {
    lock_acquire (&filesys_lock);
    block_read (block, sector*8+BLOCK_SECTOR_SIZE*i, upage+BLOCK_SECTOR_SIZE*i);
    lock_release (&filesys_lock);
  }
  bitmap_set (swap_table, sector, false);
}
