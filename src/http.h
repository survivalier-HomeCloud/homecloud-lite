#ifndef HC_HTTP_H
#define HC_HTTP_H
#include "hc.h"
#include <sys/types.h>

typedef struct {
    int       fd;
    char      method[8];
    char      path[1024];
    char     *query;            /* raw query string or NULL */
    char     *form;             /* urlencoded POST body (<= 64 KB) or NULL */
    long long content_length;
    long long body_left;        /* bytes of body not yet consumed */
    char      token[96];
    char      peer[48];
    unsigned char *pre;         /* body bytes received together with the headers */
    size_t    pre_len, pre_off;
} req_t;

char   *req_param(req_t *r, const char *key);        /* malloc'd (query first, then form body) */
ssize_t req_body_read(req_t *r, void *buf, size_t n);
int     send_all(int fd, const void *buf, size_t n);
void    send_head(req_t *r, int status, const char *ctype, long long len, const char *extra);
void    send_json(req_t *r, int status, const char *json);
void    send_err(req_t *r, int status, const char *msg);
void    api_dispatch(req_t *r);

#endif
