#define MINSDATA 3840
#define SALIGN 15
#define SALIGN2 255
struct s_segment {
  struct s_segment *s_next;
  size_t s_size;
  char s_data[MINSDATA];
};

struct s_store {
  struct s_segment *s_first;
  char *s_next;
  int s_left;
};

void *storage_pool_alloc(struct s_store *, size_t);
void storage_pool_free(void *);
void storage_pool_release(struct s_store *);
void storage_pool_init(struct s_store *);
