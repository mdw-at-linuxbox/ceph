#include <stdlib.h>
#include <string.h>
#include "storage_pool.h"

void *
my_s_alloc(struct s_store *store, size_t size)
{
  void *r;
  size = ((size + SALIGN) & ~SALIGN);
  if (store->s_left < size) {
    struct s_segment *next;
    size_t ns;
    ns = size + ((sizeof *next) - MINSDATA);
    if (ns < sizeof *next) ns = sizeof *next;
    ns = (ns + SALIGN2) & ~SALIGN2;
    next = (struct s_segment*)malloc(ns);
    next->s_next = store->s_first;
    store->s_first = next;
    store->s_next = next->s_data;
    store->s_left = ns - ((sizeof *next) - MINSDATA);
    next->s_size = ns;
  }
  r = store->s_next;
  store->s_left -= size;
  store->s_next += size;
  return r;
}

void
my_s_free(void *p)
{
}

void
my_s_release(struct s_store *store)
{
  struct s_segment *s, *next;
  for (s = store->s_first; s; s = next) {
    next = s->s_next;
    memset(s, 0xaa, s->s_size);
    free(s);
  }
  memset(store, 0, sizeof *store);
}

void my_s_init(struct s_store *store)
{
  memset(store, 0, sizeof *store);
}
