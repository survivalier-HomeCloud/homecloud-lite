/* Home Cloud server - shared declarations */
#ifndef HC_H
#define HC_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <pthread.h>

#define HC_VERSION        "1.1.0-lite"
#define HC_DEFAULT_PORT   8650
#define HC_DISCOVERY_PORT 8651
#define HC_MIN_QUOTA_GB   5
#define HC_MAX_CONNS      32      /* connexions simultanées (version lite) */

#define LOCK_MIN_PASS     4

#define PERM_NONE 0
#define PERM_READ 1
#define PERM_RW   2

/* ---------- util.c ---------- */
typedef struct { char *p; size_t len, cap; } sbuf;
void sb_init(sbuf *b);
void sb_free(sbuf *b);
void sb_add(sbuf *b, const char *s);
void sb_addf(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_json(sbuf *b, const char *s);              /* adds a quoted, escaped JSON string */
void url_decode(char *s);
char *form_get(const char *qs, const char *key);   /* malloc'd or NULL */
int  random_hex(char *out, size_t nbytes);         /* out needs 2*n+1 bytes */
int  run_cmd(char *const argv[]);                  /* fork/exec, returns exit code */
int  run_cmd_err(char *const argv[], char *err, size_t esz); /* same, captures stderr */
int  mkdir_p(const char *path, mode_t mode);
int  path_clean(const char *in, char *out, size_t outsz);
int  valid_username(const char *s);
int  command_exists(const char *name);
/* dossier de travail du serveur (config, métadonnées, journal) : $HC_HOME ou $HOME/.homecloud */
extern char g_home[512];
void hc_paths_init(void);
void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ---------- ui.c (styled terminal) ---------- */
void ui_banner(void);
void ui_title(const char *t);
void ui_ok(const char *fmt, ...)   __attribute__((format(printf, 1, 2)));
void ui_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ui_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ui_err(const char *fmt, ...)  __attribute__((format(printf, 1, 2)));
void ui_kv(const char *k, const char *v);
void ui_ask(const char *label, const char *def, char *out, size_t sz);
int  ui_ask_secret(const char *label, char *out, size_t sz);
int  ui_confirm(const char *label, int def);
int  ui_choose(const char *title, const char **opts, const char **desc, int n, int def);

/* ---------- store.c (users, disks, permissions, sessions) ---------- */
typedef struct {
    char name[33], salt[33], hash[65];
    int  admin;
    char personal[17];             /* id of the personal disk */
} user_t;

typedef struct {
    char id[17], name[65], owner[33];  /* owner != "" -> personal disk */
    unsigned long long size;
    char src[512];                     /* != "" -> montage : dossier local exposé en LECTURE SEULE pour tous */
} disk_t;

typedef struct {
    char server_name[64], data_dir[512];
    int  port, default_quota_gb;
} config_t;

extern config_t g_cfg;

int  config_load(void);
int  config_save(const config_t *c);
int  store_init(void);
int  user_create(const char *name, const char *pass, int admin, unsigned quota_gb, char *err, size_t esz);
int  user_delete(const char *name, char *err, size_t esz);
int  user_verify(const char *name, const char *pass);
int  user_set_password(const char *name, const char *pass);
int  user_get(const char *name, user_t *out);
int  user_list(user_t *out, int max);
int  disk_create(const char *name, unsigned long long size, const char *owner, char *id_out, char *err, size_t esz);
int  disk_delete(const char *id, char *err, size_t esz);
int  disk_mount(const char *name, const char *path, char *id_out, char *err, size_t esz); /* monte un dossier local (lecture seule) */
int  disk_get(const char *id, disk_t *out);
int  disk_list(disk_t *out, int max);
int  perm_effective(const char *user, const char *diskid);   /* 0/1/2 */
int  perm_set(const char *diskid, const char *user, int perm);
int  perm_for_disk(const char *diskid, char users[][33], int *perms, int max);
/* file locks (password protected files) */
int  lock_get(const char *disk, const char *path, char *owner_out);            /* 1 if locked */
int  lock_check(const char *disk, const char *path, const char *pass);         /* 1 = free or right password */
int  lock_set(const char *disk, const char *path, const char *owner, const char *pass, char *err, size_t esz);
int  lock_remove(const char *disk, const char *path);
int  lock_count_under(const char *disk, const char *dir);
void lock_drop_tree(const char *disk, const char *path);
void lock_move_tree(const char *disk, const char *from, const char *to);
void store_check_disks(void);
/* sessions */
int  session_new(const char *user, char *token_out);
int  session_user(const char *token, char *user_out);
void session_drop(const char *token);

/* ---------- disk.c (dossiers simples + quota logiciel, sans root) ---------- */
void disk_dir(const char *id, char *out, size_t sz);
int  disk_make(const char *id, char *err, size_t esz);
int  disk_destroy(const char *id);
int  disk_usage(const char *id, unsigned long long *total, unsigned long long *used);  /* total = quota */
void disk_usage_forget(const char *id);                 /* invalide le cache d'occupation */
void disk_usage_adjust(const char *id, long long delta); /* corrige le cache après un envoi */
int  rm_tree(const char *path);
int  mount_inside(const disk_t *d, const char *full);   /* 1 si `full` reste dans le dossier monté (anti-symlink) */

/* ---------- http.c / api.c ---------- */
void http_serve(int port);
void http_stop(void);
void discovery_start(int port);

#endif
