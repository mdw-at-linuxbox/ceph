/* "postdata" allocator */
struct postdata_bufs {
  struct postdata_bufs *next;
  char data[1024];
  int len;
};

void free_postdata(struct postdata_bufs *);
void append_postdata(struct postdata_bufs **, char *, int);
void prefix_postdata(struct postdata_bufs **, char *, int);
void append_postdata_format(struct postdata_bufs **, char *, ...);
void prefix_postdata_format(struct postdata_bufs **, char *, ...);
int compute_postdata_len(struct postdata_bufs *);
int copy_postdata_to_buf(char *, int, struct postdata_bufs *);
int copy_postdata_to_(struct postdata_bufs *, int (*)(void *,char *,int),void *);
void make_gmt_time_string(char *, int, time_t *);
