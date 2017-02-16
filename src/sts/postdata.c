#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "postdata.h"

int copy_postdata_to_( struct postdata_bufs *postdata,
  int (*func)(void *, char *, int), void *arg)
{
  struct postdata_bufs *thisp;
  int c = 0;
  int r;
  for (thisp = postdata; thisp; thisp = thisp->next) {
    r = (*func)(arg, thisp->data, thisp->len);
    if (r < 0) return r;
    c += r;
    if (!r) break;
  }
  return c;
}

struct copy_data_buf_arg {
  char *buf;
  int buflen;
};

int copy_data_to_buf(void *_a, char *data, int len)
{
  struct copy_data_buf_arg *a = _a;
  int l;
  if (!a->buflen) return 0;
  l = a->buflen;
  if (l > len) l = len;
  memcpy(a->buf, data, l);
  a->buf += l;
  a->buflen -= l;
  return l;
}

int copy_postdata_to_buf(char *buf, int buflen, struct postdata_bufs *postdata)
{
  struct copy_data_buf_arg a[1];
  a->buf = buf;
  a->buflen = buflen;
  return copy_postdata_to_(postdata, copy_data_to_buf, a);
}

void free_postdata(struct postdata_bufs *postdata)
{
  struct postdata_bufs *next;
  for (; postdata; postdata = next) {
    next = postdata->next;
    free(postdata);
  }
}

void prefix_postdata(struct postdata_bufs **postdata, char *buf, int len)
{
  struct postdata_bufs *oldp = *postdata, *thisp;

  *postdata = 0;
  append_postdata(postdata, buf, len);

  for (thisp = oldp; thisp; thisp = thisp->next)
    append_postdata(postdata, thisp->data, thisp->len);
  free_postdata(oldp);
}

void append_postdata(struct postdata_bufs **postdata, char *buf, int len)
{
  struct postdata_bufs *thisp, **nextp;
  int c;
  thisp = 0;
  for (nextp = postdata; *nextp; nextp = &thisp->next) {
    if (!*nextp) break;
    thisp = *nextp;
  }
  if (thisp && thisp->len < sizeof thisp->data) {
    c = sizeof thisp->data - thisp->len;
    if (c > len) c = len;
    memcpy(thisp->data + thisp->len, buf, c);
    thisp->len += c;
    buf += c;
    len -= c;
  }
  for (; len; buf += c, len -= c) {
    thisp = malloc(sizeof *thisp);
    memset(thisp, 0, sizeof *thisp);
    c = len;
    if (c > sizeof thisp->data) c = sizeof thisp->data;
    memcpy(thisp->data, buf, c);
    thisp->next = 0;
    thisp->len = c;
    *nextp = thisp;
    nextp = &thisp->next;
  }
}

void append_postdata_format(struct postdata_bufs **postdata, char *fmt, ...)
{
  char buf[65536];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  append_postdata(postdata, buf, strlen(buf));
}

void prefix_postdata_format(struct postdata_bufs **postdata, char *fmt, ...)
{
  char buf[65536];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  prefix_postdata(postdata, buf, strlen(buf));
}

int compute_postdata_len(struct postdata_bufs *postdata)
{
  struct postdata_bufs *thisp;
  int r;
  r = 0;
  for (thisp = postdata; thisp; thisp = thisp->next) {
    r += thisp->len;
  }
  return r;
}

void make_gmt_time_string(char *buf, int len, time_t *t)
{
  time_t x;
  if (!t) {
    x = time(0);
    t = &x;
  }
  struct tm *tm = gmtime(t);
  strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", tm);
}
