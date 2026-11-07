/* Minimal threaded HTTP/1.1 server (Connection: close) + UDP LAN discovery. */
#include "http.h"
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define HDR_MAX   16384
#define FORM_MAX  65536
#define MAX_CONNS HC_MAX_CONNS

static volatile int running = 1;
static int listen_fd = -1;
static int udp_fd = -1;
static int active = 0;
static pthread_mutex_t conn_lk = PTHREAD_MUTEX_INITIALIZER;

/* ---------------- low level IO ---------------- */
int send_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static const char *status_text(int s)
{
    switch (s) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 423: return "Locked";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    case 507: return "Insufficient Storage";
    default:  return "Error";
    }
}

void send_head(req_t *r, int status, const char *ctype, long long len, const char *extra)
{
    char h[1024];
    int n = snprintf(h, sizeof h,
        "HTTP/1.1 %d %s\r\nServer: HomeCloud/" HC_VERSION "\r\nContent-Type: %s\r\n"
        "Content-Length: %lld\r\nConnection: close\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n%s\r\n",
        status, status_text(status), ctype, len, extra ? extra : "");
    send_all(r->fd, h, (size_t)n);
}

void send_json(req_t *r, int status, const char *json)
{
    send_head(r, status, "application/json; charset=utf-8", (long long)strlen(json), NULL);
    send_all(r->fd, json, strlen(json));
}

void send_err(req_t *r, int status, const char *msg)
{
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":false,\"error\":");
    sb_json(&b, msg);
    sb_add(&b, "}");
    send_json(r, status, b.p);
    sb_free(&b);
}

ssize_t req_body_read(req_t *r, void *buf, size_t n)
{
    if (r->body_left <= 0) return 0;
    if ((long long)n > r->body_left) n = (size_t)r->body_left;
    ssize_t got;
    if (r->pre_off < r->pre_len) {
        size_t avail = r->pre_len - r->pre_off;
        if (n > avail) n = avail;
        memcpy(buf, r->pre + r->pre_off, n);
        r->pre_off += n;
        got = (ssize_t)n;
    } else {
        do got = recv(r->fd, buf, n, 0); while (got < 0 && errno == EINTR);
        if (got <= 0) return -1;
    }
    r->body_left -= got;
    return got;
}

char *req_param(req_t *r, const char *key)
{
    char *v = form_get(r->query, key);
    if (!v) v = form_get(r->form, key);
    return v;
}

/* ---------------- connection handling ---------------- */
static void handle(int fd, const struct sockaddr_in *peer)
{
    req_t r;
    memset(&r, 0, sizeof r);
    r.fd = fd;
    inet_ntop(AF_INET, &peer->sin_addr, r.peer, sizeof r.peer);

    char *buf = malloc(HDR_MAX + 1);
    if (!buf) return;
    size_t len = 0;
    char *hend = NULL;
    while (!hend && len < HDR_MAX) {
        ssize_t n = recv(fd, buf + len, HDR_MAX - len, 0);
        if (n <= 0) { free(buf); return; }
        len += (size_t)n;
        buf[len] = 0;
        hend = strstr(buf, "\r\n\r\n");
    }
    if (!hend) { send_err(&r, 431, "en-têtes trop volumineux"); free(buf); return; }
    *hend = 0;
    size_t hlen = (size_t)(hend - buf) + 4;
    r.pre = (unsigned char *)buf + hlen;
    r.pre_len = len - hlen;

    /* request line */
    char *save = NULL;
    char *line = strtok_r(buf, "\r\n", &save);
    char target[1024] = "";
    if (!line || sscanf(line, "%7s %1023s", r.method, target) != 2) {
        send_err(&r, 400, "requête invalide"); free(buf); return;
    }
    char *q = strchr(target, '?');
    if (q) { *q++ = 0; r.query = strdup(q); }
    snprintf(r.path, sizeof r.path, "%s", target);

    r.content_length = 0;
    char ctype[128] = "";
    while ((line = strtok_r(NULL, "\r\n", &save))) {
        if (!strncasecmp(line, "Content-Length:", 15)) r.content_length = atoll(line + 15);
        else if (!strncasecmp(line, "Content-Type:", 13)) {
            const char *v = line + 13; while (*v == ' ') v++;
            snprintf(ctype, sizeof ctype, "%s", v);
        } else if (!strncasecmp(line, "Authorization:", 14)) {
            const char *v = line + 14; while (*v == ' ') v++;
            if (!strncasecmp(v, "Bearer ", 7)) snprintf(r.token, sizeof r.token, "%s", v + 7);
        }
    }
    if (r.content_length < 0) r.content_length = 0;
    r.body_left = r.content_length;

    /* urlencoded POST bodies are read into memory */
    if (!strcmp(r.method, "POST") && r.content_length > 0 &&
        !strncasecmp(ctype, "application/x-www-form-urlencoded", 33)) {
        if (r.content_length > FORM_MAX) { send_err(&r, 413, "corps trop volumineux"); goto out; }
        r.form = malloc((size_t)r.content_length + 1);
        size_t got = 0;
        while (r.form && got < (size_t)r.content_length) {
            ssize_t n = req_body_read(&r, r.form + got, (size_t)r.content_length - got);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (r.form) r.form[got] = 0;
    }

    api_dispatch(&r);
out:
    free(r.query);
    free(r.form);
    free(buf);
}

typedef struct { int fd; struct sockaddr_in peer; } conn_t;

static void *conn_thread(void *arg)
{
    conn_t *c = arg;
    struct timeval tv = { .tv_sec = 120 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    handle(c->fd, &c->peer);
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    free(c);
    pthread_mutex_lock(&conn_lk); active--; pthread_mutex_unlock(&conn_lk);
    return NULL;
}

void http_serve(int port)
{
    signal(SIGPIPE, SIG_IGN);
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(listen_fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(listen_fd, 64) < 0) {
        logmsg("impossible d'écouter sur le port %d : %s", port, strerror(errno));
        return;
    }
    logmsg("Home Cloud à l'écoute sur le port %d", port);

    while (running) {
        conn_t *c = calloc(1, sizeof *c);
        socklen_t sl = sizeof c->peer;
        c->fd = accept(listen_fd, (struct sockaddr *)&c->peer, &sl);
        if (c->fd < 0) { free(c); if (!running) break; if (errno == EINTR) continue; continue; }
        pthread_mutex_lock(&conn_lk);
        int busy = active >= MAX_CONNS;
        if (!busy) active++;
        pthread_mutex_unlock(&conn_lk);
        if (busy) { close(c->fd); free(c); continue; }
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &at, conn_thread, c) != 0) {
            close(c->fd); free(c);
            pthread_mutex_lock(&conn_lk); active--; pthread_mutex_unlock(&conn_lk);
        }
        pthread_attr_destroy(&at);
    }
}

void http_stop(void)
{
    running = 0;
    if (listen_fd >= 0) shutdown(listen_fd, SHUT_RDWR);
    if (udp_fd >= 0) shutdown(udp_fd, SHUT_RDWR);
}

/* ---------------- LAN discovery (UDP) ---------------- */
static void *disc_thread(void *arg)
{
    int port = (int)(intptr_t)arg;
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(HC_DISCOVERY_PORT), .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(udp_fd, (struct sockaddr *)&a, sizeof a) < 0) {
        logmsg("découverte réseau indisponible (UDP %d) : %s", HC_DISCOVERY_PORT, strerror(errno));
        return NULL;
    }
    char buf[128];
    while (running) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(udp_fd, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) { if (!running) break; continue; }
        buf[n] = 0;
        if (strncmp(buf, "HOMECLOUD_DISCOVER", 18) != 0) continue;
        char reply[256];
        int rn = snprintf(reply, sizeof reply, "HOMECLOUD_HERE|%d|%s|%s", port, g_cfg.server_name, HC_VERSION);
        sendto(udp_fd, reply, (size_t)rn, 0, (struct sockaddr *)&from, fl);
    }
    return NULL;
}

void discovery_start(int port)
{
    pthread_t t;
    if (pthread_create(&t, NULL, disc_thread, (void *)(intptr_t)port) == 0) pthread_detach(t);
}
