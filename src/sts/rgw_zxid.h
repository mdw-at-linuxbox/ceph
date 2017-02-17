#if 0
typedef struct zxid_conf zxid_conf;
typedef struct zxid_ses zxid_ses;
int zxid_mini_httpd_filter(zxid_conf*, struct mg_connection *,
  struct postdata_bufs *, zxid_ses **);
int zxid_pool2env(zxid_conf*, zxid_ses*, char **, int, char **);
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct zxid_results zxid_results;
int rgw_zxid_begin_request(const struct mg_connection *,zxid_results**);
void discard_connection_cdata(const struct mg_connection *conn);
void zxid_thread_cleanup(const struct mg_connection *conn);
int rgw_initialize_zxid();
#ifdef __cplusplus
}
#endif
