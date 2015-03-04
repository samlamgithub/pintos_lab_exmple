#include "devices/block.h"
#include <bitmap.h>
#include "page.h"

#ifndef SWAP_H
#define SWAP_H

struct page_swap
{
  void *upage;
  block_sector_t sector;
};

struct bitmap *swap_table;

void swap_init (void);
void page_to_sector (struct sup_page*);
void sector_to_page (struct sup_page*);

#endif /* SWAP_H */
