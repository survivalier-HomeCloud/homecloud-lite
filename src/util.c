#include "hc.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

char g_home[512];

/* $HC_HOME si défini, sinon $HOME/.homecloud (sous Termux : /data/data/com.termux/files/home/.homecloud) */
void hc_paths_init(void)
{
    const char *h = getenv("HC_HOME");
    if (h && *h) { snprintf(g_home, sizeof g_home, "%s", h); return; }
    h = getenv("HOME");
    snprintf(g_home, sizeof g_home, "%s/.homecloud", (h && *h) ? h : "/tmp");
}

/* ---------- dynamic string buffer ---------- */
void sb_init(sbuf *b) { b->p = NULL; b->len = b->cap = 0; }
void sb_free(sbuf *b) { free(b->p); sb_init(b); }

static void sb_reserve(sbuf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) return;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < b->len + extra + 1) nc *= 2;
    char *np = realloc(b->p, nc);
    if (!np) { perror("realloc"); exit(1); }
    b->p = np; b->cap = nc;
}

void sb_add(sbuf *b, const char *s)
{
    size_t n = strlen(s);
    sb_reserve(b, n);
    memcpy(b->p + b->len, s, n + 1);
    b->len += n;
}

void sb_addf(sbuf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return; }
    sb_reserve(b, (size_t)n);
    vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
}

void sb_json(sbuf *b, const char *s)
{
    sb_add(b, "\"");
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        switch (*c) {
        case '"':  sb_add(b, "\\\""); break;
        case '\\': sb_add(b, "\\\\"); break;
        case '\n': sb_add(b, "\\n");  break;
        case '\r': sb_add(b, "\\r");  break;
        case '\t': sb_add(b, "\\t");  break;
        default:
            if (*c < 0x20) sb_addf(b, "\\u%04x", *c);
            else { char t[2] = { (char)*c, 0 }; sb_add(b, t); }
        }
    }
    sb_add(b, "\"");
}

/* ---------- url / form helpers ---------- */
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void url_decode(char *s)
{
    char *o = s;
    while (*s) {
        if (*s == '+') { *o++ = ' '; s++; }
        else if (*s == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
            *o++ = (char)(hexval(s[1]) * 16 + hexval(s[2]));
            s += 3;
        } else *o++ = *s++;
    }
    *o = 0;
}

char *form_get(const char *qs, const char *key)
{
    if (!qs) return NULL;
    size_t kl = strlen(key);
    const char *p = qs;
    while (*p) {
        const char *end = strchr(p, '&');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len > kl && p[kl] == '=' && strncmp(p, key, kl) == 0) {
            char *v = strndup(p + kl + 1, len - kl - 1);
            if (v) url_decode(v);
            return v;
        }
        if (!end) break;
        p = end + 1;
    }
    return NULL;
}

/* ---------- randomness ---------- */
int random_hex(char *out, size_t nbytes)
{
    unsigned char buf[64];
    if (nbytes > sizeof buf) return -1;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < nbytes) {
        ssize_t r = read(fd, buf + got, nbytes - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    for (size_t i = 0; i < nbytes; i++) sprintf(out + 2 * i, "%02x", buf[i]);
    return 0;
}

/* ---------- processes / filesystem ---------- */
int run_cmd(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); }
        execvp(argv[0], argv);
        _exit(127);
    }
    int st;
    while (waitpid(pid, &st, 0) < 0) if (errno != EINTR) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int run_cmd_err(char *const argv[], char *err, size_t esz)
{
    int pfd[2];
    if (err && esz) err[0] = 0;
    if (!err || !esz || pipe(pfd) < 0) return run_cmd(argv);
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); }
        dup2(pfd[1], 2);
        close(pfd[0]); close(pfd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);
    size_t got = 0;
    char tmp[512];
    ssize_t n;
    while ((n = read(pfd[0], tmp, sizeof tmp)) > 0)
        for (ssize_t i = 0; i < n && got < esz - 1; i++) err[got++] = (tmp[i] == '\n' || tmp[i] == '\r') ? ' ' : tmp[i];
    err[got] = 0;
    close(pfd[0]);
    while (got && err[got - 1] == ' ') err[--got] = 0;
    int st;
    while (waitpid(pid, &st, 0) < 0) if (errno != EINTR) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int mkdir_p(const char *path, mode_t mode)
{
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

int command_exists(const char *name)
{
    const char *path = getenv("PATH");
    if (!path) path = "/usr/sbin:/usr/bin:/sbin:/bin";
    char *copy = strdup(path), *save = NULL;
    int found = 0;
    for (char *d = strtok_r(copy, ":", &save); d && !found; d = strtok_r(NULL, ":", &save)) {
        char full[1024];
        snprintf(full, sizeof full, "%s/%s", d, name);
        if (access(full, X_OK) == 0) found = 1;
    }
    free(copy);
    return found;
}

/* Normalises a user supplied path into "/a/b". Rejects "..", NUL and control chars. */
int path_clean(const char *in, char *out, size_t outsz)
{
    if (!in) in = "/";
    size_t o = 0;
    out[o++] = '/';
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *s = p;
        while (*p && *p != '/') {
            if ((unsigned char)*p < 0x20) return -1;
            p++;
        }
        size_t n = (size_t)(p - s);
        if (n == 1 && s[0] == '.') continue;
        if (n == 2 && s[0] == '.' && s[1] == '.') return -1;
        if (n > 255) return -1;
        if (o + n + 2 > outsz) return -1;
        if (o > 1) out[o++] = '/';
        memcpy(out + o, s, n);
        o += n;
    }
    out[o] = 0;
    return 0;
}

int valid_username(const char *s)
{
    size_t n = strlen(s);
    if (n < 2 || n > 32) return 0;
    for (size_t i = 0; i < n; i++)
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '-' || s[i] == '.')) return 0;
    return 1;
}

void logmsg(const char *fmt, ...)
{
    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
