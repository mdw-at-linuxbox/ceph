#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>

#include <curl/curl.h>

/* ughugh. zxid.h needs these next 3 to make zxid_conf proper size... */
#define USE_CURL 1
#define USE_PTHREAD 1
#define USE_OPENSSL 1

#include <zx/platform.h>
#include <zx/errmac.h>
#include <zx/zx.h>
#include <zx/zxid.h>
#include <zx/zxidpriv.h>
#include <zx/zxidconf.h>
#include <zx/zxidutil.h>
#define AUTO_FLAGS 0x6ea8

#include "civetweb/civetweb.h"

#include "postdata.h"
#include "storage_pool.h"

#include "rgw_zxid.h"

// XXX needs work, should be configurable (at least)
char *zxid_confstr = "PATH=/tmp/zxid/&SSO_PAT=/test-sp/**&DEBUG=1";

int Dflag;	// XXX fixme
pthread_key_t local_store;

/* per-thread storage */
struct zxid_work {
  struct s_store store[1];
};

/* per-connection storage */
struct zxid_conn_data {
  zxid_ses *ses;
  zxid_conf cf[1];
  int foo[128]; /* paranoia */
};

int postdata_mg_write(void *a, char *buf, int len)
{
    return mg_write(a, buf, len);
}

int copy_postdata_to_mg(struct mg_connection *conn,
 struct postdata_bufs *postdata)
{
  return copy_postdata_to_(postdata, postdata_mg_write, conn);
}

// XXX this probably exists better elsewhere.
const char * make_response_code_text(int status)
{
  switch(status) {
  case 100: return "Continue";
  case 101: return "Switching Protocols";
  case 102: return "Processing";
  case 200: return "OK";
  case 201: return "Created";
  case 202: return "Accepted";
  case 203: return "Non-Authoritative Information";
  case 204: return "No Content";
  case 205: return "Reset Content";
  case 206: return "Partial Content";
  case 300: return "Multiple Choices";
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 303: return "See Other";
  case 304: return "Not Modified";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 410: return "Gone";
  case 411: return "Length Required";
  case 500: return "Internal Server Error";
  case 501: return "Not Implemented";
  default:  return "Unknown Problem or Internal Error";
  }
}

int pretty_print_expand(char *cp, int len, char *buf, int buflen)
{
  int l, r;
  char *p;
  char lp[30];
  r = len;
  for (p = cp; --len >= 0; ++p) {
    if (buflen < 1) ;
    else if (*p >= 040 && *p < 0177) --buflen, *buf++ = *p;
    else {
      sprintf (lp, "\\%040o", (unsigned char) *p);
      l = strlen(lp); if (l > (buflen-1)) l=(buflen-1);
      memcpy(buf, lp, l);
      buflen -= l; buf += l;
    }
  }
  if (buflen) *buf++ = 0;
  return r;
}

int zxid_mini_httpd_read_post(zxid_conf * cf, struct postdata_bufs *postdata, char **outp)
{
  char *cp;
  int len;

  cp = zx_alloc(cf->ctx, 1 + (len = compute_postdata_len(postdata)));
  copy_postdata_to_buf(cp, len, postdata);
  cp[len] = 0;
  *outp = cp;
  return len;
}

int zxid_mini_httpd_process_zxid_simple_outcome(zxid_conf *cf,
  struct mg_connection *conn,
  zxid_ses *ses, const char *uri_path, const char *cookie_hdr,
  char *request_data)
{
  struct postdata_bufs *output = 0, *headers = 0;
  int status;
  char *content_type = 0;
  char *p, *ep;
  int content_type_len, request_data_len;
  char timebuf[80];

  make_gmt_time_string(timebuf, sizeof timebuf, NULL);
  if (cookie_hdr && *cookie_hdr) {
    if (Dflag) fprintf(stderr,"zmhpzso: cookie_hdr: %s\n", cookie_hdr);
    append_postdata_format(&headers, "Set-Cookie: %s\r\n", cookie_hdr);
  }
  switch(*request_data) {
  case 'L':
    status = 302;
    append_postdata_format(&output, "SAML Redirect\r\n");
    request_data_len = strlen(request_data);
#if 0
    p = strchr(request_data, '\r');
    if (p) {
      request_data_len = p-request_data;
{ char *ltemp = 0;
char *savedp, *p1 = 0; int r;
savedp = p;
while (*++p) switch(*p) {
case '\r':
case '\n':
break;
default:
if (!p1) p1 = p;
}
if (p1) {
ltemp = malloc(1024);
r = pretty_print_expand(p1, p-p1, ltemp, 1024);
fprintf(stderr,"zmhpzso: Huh?  L: %d<%s>\n", r, ltemp);
}
fprintf(stderr,"zmhpzso: zero %p/%d\n", savedp, p-savedp);
memset(savedp, 'X', p-savedp);
}
    } else
      request_data_len = strlen(request_data);
if (Dflag) {
char ltemp[1024];
pretty_print_expand(request_data, request_data_len, ltemp, sizeof ltemp);
fprintf(stderr,"zmhpzso: Case L - <%s>\n", ltemp);
}
#endif
    append_postdata(&headers, request_data, request_data_len);
    break;
  case 'C':
    fprintf(stderr,"zmhpzso: request_data - case C: %s\n", request_data);
    content_type = request_data;
    request_data += 14; /* "skip Content-Type:" */
    p = strchr(request_data, '\r');
    if (!p) goto E501;
    p += 2;
    content_type_len = p - content_type;
    p += 16;    /* "skip Content-Length:" */
if (Dflag) fprintf(stderr,"zmhpzso: About to strtol: %.8s\n", p);
    request_data_len = strtol(p, &ep, 10);
    request_data = strchr(p, '\r');
    if (!request_data)
      goto E501;
    request_data += 4;  /* skip \r\n\r\n */
    append_postdata(&output, request_data, request_data_len);
    status = 200;
    break;
  case 'z':
if (Dflag) fprintf(stderr,"zmhpzso: request_data - case z: %s\n", request_data);
    goto E501;
  case 0: /* Logged in case */
    // pool2apache(cf, r, ses.at);
    status = 0;
    return status;
  default:
if (Dflag) fprintf(stderr,"zmhpzso: request_data - ?unknown?: %s\n", request_data);
  E501:
    content_type = 0;
    status = 501;
    append_postdata_format(&output, "Server Fault\r\n");
  }

  prefix_postdata_format(&headers, "HTTP/1.1 %d %s\r\n",
    status,
    make_response_code_text(status));
  if (ses->setcookie) {
    append_postdata_format(&headers, "Set-Cookie: %s\r\n", ses->setcookie);
  }
  if (ses->setptmcookie) {
    append_postdata_format(&headers, "Set-Cookie: %s\r\n", ses->setptmcookie);
  }
  append_postdata_format(&headers, "Date: %s\r\n", timebuf);
  append_postdata_format(&headers, "Content-Length: %d\r\n",
    compute_postdata_len(output));
  if (content_type) {
if (Dflag) fprintf(stderr,"zmhpzso: Custom content_type: %d<%.*s>\n",
content_type_len, content_type_len, content_type);
    append_postdata(&headers, content_type, content_type_len);
  } else {
    append_postdata_format(&headers, "Content-Type: %s\r\n",
      "text/plain");
  }
  append_postdata_format(&headers, "\r\n");
  copy_postdata_to_mg(conn, headers);
  copy_postdata_to_mg(conn, output);
  free_postdata(output);
  free_postdata(headers);
  return status;
}

int zxid_mini_httpd_step_up(zxid_conf *cf,
  struct mg_connection *conn,
  zxid_cgi *cgi, zxid_ses *ses,
  const char *uri_path, const char *cookie_hdr)
{
  char *request_data;

  if (!ses) // XXX can this happen?  should it be returned?
    ses = zxid_alloc_ses(cf);
  request_data = zxid_simple_no_ses_cf(cf, cgi, ses, 0, AUTO_FLAGS);
if (Dflag) fprintf (stderr,"zmhsu: simple_outcome\n");
  return zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
    ses, uri_path, cookie_hdr,
    request_data);
}

int zxid_mini_httpd_filter(zxid_conf * cf,
  struct mg_connection *conn,
  struct postdata_bufs *postdata,
  zxid_ses**sessp)
{
  struct mg_request_info const *req_info = mg_get_request_info(conn);
  zxid_ses *ses = zxid_alloc_ses(cf);
  zxid_cgi cgi[1];
  int len, qs_len, uri_len;
  int burl_url_len;
  char *cp;
  char *burl_url;
  const char *method = req_info->request_method;
  const char *uri_path = req_info->request_uri; // or local_url?
  const char *qs = req_info->query_string;
  char *request_data = 0;
  int request_data_len = -1;
  int r;
  const char *cookie_hdr = 0;
  int i;

  *sessp = ses;
  memset(cgi, 0, sizeof *cgi);
  for (i = 0; i < req_info->num_headers; ++i) {
    if (!strncasecmp("cookie",
        req_info->http_headers[i].name, 6))
      cookie_hdr = req_info->http_headers[i].value;
  }

  // zxid_mini_httpd_check_redirect_hack
  cgi->uri_path = (char *) uri_path;
  if (!cf->redirect_hack_zxid_qs || !*cf->redirect_hack_zxid_qs)
    cgi->qs = (char *) qs;
  else if (!*qs)
    cgi->qs = cf->redirect_hack_zxid_qs;
  else {
    qs_len = strlen(qs);
    len = strlen(cf->redirect_hack_zxid_qs);
    cp = ZX_ALLOC(cf->ctx, len + qs_len + 2);
    memcpy(cp, cf->redirect_hack_zxid_qs, len);
    cp[len] = '&';
    memcpy(cp + len + 1, qs, qs_len + 1);
    cgi->qs = cp;
    // XXX check, is qs a leak?
  }
  if (cgi->qs && *cgi->qs) {
    cp = zx_dup_cstr(cf->ctx, cgi->qs);
    zxid_parse_cgi(cf, cgi, cp);
  }
  if (cf->ses_cookie_name && *cf->ses_cookie_name && cookie_hdr) {
    zxid_get_sid_from_cookie(cf, cgi, cookie_hdr);
  }
  // zxid_mini_httpd_check_protocol_url
  for (cp = cf->burl; *cp && *cp != ':' && *cp != '/'; ++cp)
    ;
  if (*cp == ':' && cp[1] == '/' && cp[2] == '/') {
    for (cp += 3; *cp && *cp != '/'; ++cp)
      ;
  }
  burl_url = cp;
  burl_url_len = strlen(cp);
  for (cp = burl_url + burl_url_len-1; cp > burl_url; --cp)
    if (*cp == '?') break;
  if (cp == burl_url)
    cp = burl_url + burl_url_len;
  burl_url_len = cp - burl_url;
  uri_len = strlen(uri_path);
  if (uri_len == burl_url_len && !memcmp(burl_url, uri_path, uri_len)) {
if (Dflag) fprintf (stderr,"zmhf: matching zxid pseudo node\n");
    if (*method == 'P') {
      request_data_len = zxid_mini_httpd_read_post(cf, postdata,
        &request_data);
      if (cgi->op == 'S') {
        r = zxid_sp_soap_parse(cf, cgi, ses,
          request_data_len, request_data);
// XXX what is "r" for?
      } else {
        zxid_parse_cgi(cf, cgi, request_data);
      }
    }
    switch(cgi->op) {
    default:
      if (!cgi->sid || !zxid_get_ses(cf, ses, cgi->sid))
        break;
      request_data = zxid_simple_ses_active_cf(cf, cgi,
        ses, 0, AUTO_FLAGS);
      if (!request_data)
        break;
if (Dflag) fprintf (stderr,"zmhf: case #1 simple_outcome\n");
      return
zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
        ses, uri_path, cookie_hdr,
        request_data);
    case 'L':
    case 'A':
      break;
    }
    return zxid_mini_httpd_step_up(cf, conn, cgi, ses, uri_path,
      cookie_hdr);
  }
if (Dflag) fprintf (stderr,"zmhpzso: (req %s no match for pseudo %s)\n", uri_path, burl_url);
  // note: zxid_is_wsp == do zxid_mini_httpd_wsp_response
if (Dflag) fprintf (stderr,"zmhpzso: ha! got here!\n");
  if (zx_match(cf->wsp_pat, uri_path)) {
  }
  // zxid_mini_httpd_wsp
  // zxid_mini_httpd_uma
  // zxid_mini_httpd_sso
  if (zx_match(cf->sso_pat, uri_path)) {
    if (!qs || *qs != 'l') {
      cgi->op = 'E';
    }
    if (cgi->sid && cgi->sid[0] && zxid_get_ses(cf, ses, cgi->sid)) {
      request_data = zxid_simple_ses_active_cf(cf, cgi,
        ses, 0, AUTO_FLAGS);
      if (request_data) {
if (Dflag) fprintf (stderr,"zmhf: case #2 simple_outcome\n");
        return
zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
          ses, uri_path, cookie_hdr,
          request_data);
      }
    }
    return zxid_mini_httpd_step_up(cf, conn, cgi, ses, uri_path,
      cookie_hdr);
  } else {
if (Dflag) fprintf (stderr,"zmhf: sso_path=<%s> uri_path=<%s>: no match\n", cf->sso_pat, uri_path);
    return 0;
  }
}

int zxid_pool2env(zxid_conf *cf, zxid_ses *ses,
  char **envp, int maxn, char **remoteuserp)
{
  struct zxid_map *map;
  struct zxid_attr *at, *av;
  char *name, *val;
  int envn = 0;

  for (at = ses->at; at; at = at->n) {
    name = at->name;
    val = at->val;
    if (!strcmp(name, "idpnid") && val && strcmp(val, "-"))
      *remoteuserp = val;
    map = zxid_find_map(cf->outmap, at->name);
    if (map) {
      if (map->rule == ZXID_MAP_RULE_DEL) {
        continue;
      }
      at->map_val = zxid_map_val(cf, 0, 0, map, at->name, at->val);
      if (map->dst && *map->dst && map->src && map->src[0] != '*') {
        name = map->dst;
      }
      val = at->map_val->s;
    }
    if (envn >= maxn) {
    TooMany:
fprintf(stderr,"zp2e: too many envs(max=%d)\n", maxn);
      goto Done;
    }
    envp[envn++] = zx_alloc_sprintf(cf->ctx, 0, "%s%s=%s",
      cf->mod_saml_attr_prefix, name, val);
    for (av = at->nv; av; av = av->n) { /* multivalued */
      av->map_val = zxid_map_val(cf, 0, 0, map, at->name, av->val);
      if (envn >= maxn) goto TooMany;
      envp[envn++] = zx_alloc_sprintf(cf->ctx, 0, "%s%s=%s",
        cf->mod_saml_attr_prefix, name,
        map ? av->map_val->s : av->val);
    }
  }
Done:
  return envn;
}

void
read_postdata(struct postdata_bufs **outp, struct mg_connection *conn)
{
  struct mg_request_info const *req_info = mg_get_request_info(conn);
  int i;
  char const *cl = 0;
  for (i = 0; i < req_info->num_headers; ++i) {
    if (!strncasecmp("content-length",
        req_info->http_headers[i].name, 14))
      cl = req_info->http_headers[i].value;
  }
  char *ep = 0;
  int c, sofar;
#if 0
  int totlen = cl ? strtol(cl, &ep, 0) : -1;
  if (vflag && cl)
    fprintf(stdout, "reading content: %d\n", totlen);
#endif
  for (sofar = 0;;sofar += c) {
    char buf[500];
    c = mg_read(conn, buf, sizeof buf);
    if (c <= 0) break;
    append_postdata(outp,  buf, c);
  }
}

void *memory_reallocator_for_zxid(void *p, size_t n)
{
  char *r;
  int oldn;
  void *data;
  struct zxid_work *work = 0;

  data = pthread_getspecific(local_store);
  if (data) {
    work = (struct zxid_work *) data;
  }

  if (p) {
    r = p;
    r -= 16;
    oldn = *((int *)r);
  }
  n += 16;
  char *new = storage_pool_alloc(work->store, n);
  if (!new) {
    return 0;
  }
  *((int *)new) = n;
  if (p) {
    if (n > oldn) n = oldn;
    memcpy(new+16, r+16, n - 16);
  }
  return new+16;
}

void *memory_allocator_for_zxid(size_t n)
{
  return memory_reallocator_for_zxid(0, n);
}

void memory_free_for_zxid(void *p)
{
}

void discard_connection_cdata(const struct mg_connection *conn)
{
  void *p;
  struct zxid_conn_data *cdata;
  struct zx_ctx *ctx;
  p = mg_get_user_connection_data(conn);
  mg_set_user_connection_data(conn, NULL);
  cdata = (struct zxid_conn_data *) p;
  if (!cdata) return;
  curl_easy_cleanup(cdata->cf->curl);
  cdata->cf->curl = 0;
  cdata->cf->cpath = 0; /* parsed substring, not strdup */
        /* note that cpath gets alloc'd,
         * then clobbered, leak there!
         */
  if (cdata) {
    ctx = cdata->cf->ctx;
    zxid_free_conf(cdata->cf);
if (Dflag) fprintf(stderr,"free cdata: %p [%x]\n", cdata, cdata->foo[0]);
    memset(cdata, 0xaa, sizeof *cdata);
    free(cdata);
    if (ctx)
      zx_free_ctx(ctx);
  }
}

void zxid_thread_cleanup(const struct mg_connection *conn)
{
  void *data;
  struct zxid_work *work = 0;

  // eventually, don't do this.
  discard_connection_cdata(conn);
  // but need much smarter storage allocation help
  // in zxid first.

  // delete everything that zxid asked for (this thread)
  data = pthread_getspecific(local_store);
  if (data) {
    work = (struct zxid_work *) data;
    storage_pool_release(work->store);
  }
}

static void local_destroy(void *data)
{
  struct zxid_work *work = data;
  if (data) {
    storage_pool_release(work->store);
    free(data);
  }
  pthread_setspecific(local_store, NULL);
}

int rgw_initialize_zxid(void)
{
  if (!!pthread_key_create(&local_store, local_destroy)) {
    perror("pthread_key_create");
    return 1;
  }
  return 0;
}

int rgw_zxid_begin_request(const struct mg_connection *conn, zxid_results**rp)
{
  struct mg_request_info const *req_info = mg_get_request_info(conn);
  void *p;
  void *data;
  struct zxid_work *work = 0;
  int r = 0;
  struct zxid_conn_data *cdata = 0;
  struct postdata_bufs *postdata = 0;

  data = pthread_getspecific(local_store);
  if (data) {
    work = (struct zxid_work *) data;
  } else {
    work = malloc(sizeof *work);
    memset(work, 0, sizeof *work);
    if (!!pthread_setspecific(local_store, work)) {
      perror("my_begin_request");
      goto Done;  // 0 ???
    }
  }
  p = mg_get_user_connection_data(conn);
  if (p) {
    cdata = (struct zxid_conn_data *) p;
  } else {
    cdata = malloc(sizeof *cdata);
if (Dflag) fprintf(stderr,"allocate cdata: %d => %p\n", (int)(sizeof *cdata), cdata);
    memset(cdata, 0, sizeof *cdata);
    memset(cdata->foo, 0xaa, sizeof cdata->foo);
    mg_set_user_connection_data(conn, cdata);
  }
if (Dflag) fprintf(stderr,"begin-request #0: %p [%x]\n", cdata, cdata->foo[0]);

  if (!cdata->cf->ctx) {
    /* zxid_new_conf_to_cf - can't use, want
      custom memory allocator.
    */
    cdata->cf->ctx = zx_init_ctx();
    cdata->cf->ctx->malloc_func = memory_allocator_for_zxid;
    cdata->cf->ctx->realloc_func = memory_reallocator_for_zxid;
    cdata->cf->ctx->free_func = memory_free_for_zxid;
if (Dflag) fprintf(stderr,"begin-request #92: %p [%x]\n", cdata, cdata->foo[0]);
    zxid_conf_to_cf_len(cdata->cf, -1, zxid_confstr);
//NO!   cdata->cf = zxid_new_conf_to_cf(zxid_confstr);
  }
if (Dflag) fprintf(stderr,"begin-request #1: %p [%x]\n", cdata, cdata->foo[0]);

#if 0
  if (vflag) {
    fprintf (stdout, "method: %s\n", req_info->request_method);
    fprintf (stdout, "uri: %s\n", req_info->uri);
    if (req_info->query_string)
      fprintf (stdout, "qs: %s\n", req_info->query_string);
    fprintf (stdout, "user: %s\n", req_info->remote_user);
    for (i = 0; i < req_info->num_headers; ++i) {
      fprintf (stdout, "hd%d: %s=%s\n", i,
        req_info->http_headers[i].name,
        req_info->http_headers[i].value);
    }
  }
#endif
  if (!strcmp(req_info->request_method, "POST")) {
    read_postdata(&postdata, (struct mg_connection *) conn);
    if (postdata) {
      int sofar = 0;
      struct postdata_bufs *thisp;
      for (thisp = postdata; thisp; thisp = thisp->next) {
        fprintf (stdout, "dt%d-%d: %.*s\n",
          sofar, sofar+thisp->len,
          thisp->len, thisp->data);
        sofar += thisp->len;
      }
    }
  }
if (Dflag) fprintf(stderr,"begin-request #2: %p [%x]\n", cdata, cdata->foo[0]);
  r = zxid_mini_httpd_filter(cdata->cf, (struct mg_connection *) conn,
	postdata, &cdata->ses);
  if (r)
    goto Done;
Done:
  free_postdata(postdata);
if (Dflag) fprintf(stderr,"begin-request #5: %p [%x]\n", cdata, cdata->foo[0]);
  return r;
}
