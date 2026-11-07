/* REST API: auth, disks, file operations, avatars, administration. */
#include "http.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#define MAX_AVATAR (5 * 1024 * 1024)

/* ---------------- helpers ---------------- */
static int auth(req_t *r, char *user)
{
    if (session_user(r->token, user) < 0) { send_err(r, 401, "non authentifié"); return -1; }
    return 0;
}

static int need_admin(req_t *r, const char *user)
{
    user_t u;
    if (user_get(user, &u) < 0 || !u.admin) { send_err(r, 403, "réservé à l'administrateur"); return -1; }
    return 0;
}

static void ok(req_t *r) { send_json(r, 200, "{\"ok\":true}"); }

static int is_admin(const char *user)
{
    user_t u;
    return user_get(user, &u) == 0 && u.admin;
}

/* 423 + "locked":true: the client knows it has to ask for the file's password */
static void send_locked(req_t *r, const char *msg)
{
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":false,\"locked\":true,\"error\":");
    sb_json(&b, msg);
    sb_add(&b, "}");
    send_json(r, 423, b.p);
    sb_free(&b);
}

typedef struct {
    disk_t d;
    int perm;
    char mnt[640];
    char rel[1024];
    char full[1700];
} ctx_t;

/* Resolves ?disk=&path= into a safe absolute path inside the mounted disk. */
static int open_ctx(req_t *r, const char *user, int need, ctx_t *c, const char *pathkey)
{
    int rc = -1;
    char *id = req_param(r, "disk");
    char *path = req_param(r, pathkey);
    if (!id || disk_get(id, &c->d) < 0) { send_err(r, 404, "disque introuvable"); goto out; }
    c->perm = perm_effective(user, id);
    if (c->perm < need) { send_err(r, 403, c->perm ? "accès en lecture seule" : "accès refusé"); goto out; }
    if (path_clean(path ? path : "/", c->rel, sizeof c->rel) < 0) { send_err(r, 400, "chemin invalide"); goto out; }
    if (!strncmp(c->rel, "/lost+found", 11)) { send_err(r, 403, "chemin réservé"); goto out; }
    disk_dir(id, c->mnt, sizeof c->mnt);
    if (snprintf(c->full, sizeof c->full, "%s%s", c->mnt, strcmp(c->rel, "/") ? c->rel : "") >= (int)sizeof c->full) {
        send_err(r, 400, "chemin trop long"); goto out;
    }
    rc = 0;
out:
    free(id); free(path);
    return rc;
}

/* Password gate of a locked file (?lockpass=). Administrators are exempt.
 * Returns 0 when access is allowed, otherwise the error has been sent. */
static int lock_gate(req_t *r, const char *user, const ctx_t *c)
{
    if (!lock_get(c->d.id, c->rel, NULL) || is_admin(user)) return 0;
    char *p = req_param(r, "lockpass");
    int good = p && p[0] && lock_check(c->d.id, c->rel, p);
    int given = p && p[0];
    free(p);
    if (good) return 0;
    if (given) {
        logmsg("mot de passe de fichier incorrect pour '%s' (%s%s) depuis %s", user, c->d.name, c->rel, r->peer);
        sleep(1);
    }
    send_locked(r, given ? "mot de passe du fichier incorrect" : "fichier verrouillé : mot de passe requis");
    return -1;
}

/* A non-admin may not touch a folder that contains locked files (delete / rename). */
static int tree_gate(req_t *r, const char *user, const ctx_t *c)
{
    int n = lock_count_under(c->d.id, c->rel);
    if (!n || is_admin(user)) return 0;
    char msg[200];
    snprintf(msg, sizeof msg, "ce dossier contient %d fichier(s) verrouillé(s) : déverrouillez-les d'abord", n);
    send_locked(r, msg);
    return -1;
}

static void user_json(sbuf *b, const user_t *u)
{
    sb_add(b, "{\"name\":"); sb_json(b, u->name);
    sb_addf(b, ",\"admin\":%s,\"personal\":\"%s\"}", u->admin ? "true" : "false", u->personal);
}

/* ---------------- public ---------------- */
static void h_ping(req_t *r)
{
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":true,\"app\":\"HomeCloud\",\"name\":");
    sb_json(&b, g_cfg.server_name);
    sb_addf(&b, ",\"version\":\"%s\"}", HC_VERSION);
    send_json(r, 200, b.p);
    sb_free(&b);
}

static void h_login(req_t *r)
{
    char *u = req_param(r, "user"), *p = req_param(r, "pass");
    if (!u || !p) { send_err(r, 400, "identifiants manquants"); goto out; }
    if (!user_verify(u, p)) {
        logmsg("échec de connexion pour '%s' depuis %s", u, r->peer);
        sleep(1);
        send_err(r, 401, "identifiant ou mot de passe incorrect");
        goto out;
    }
    char tok[65];
    user_t ud;
    if (session_new(u, tok) < 0 || user_get(u, &ud) < 0) { send_err(r, 500, "erreur interne"); goto out; }
    logmsg("connexion de '%s' depuis %s", u, r->peer);
    sbuf b; sb_init(&b);
    sb_addf(&b, "{\"ok\":true,\"token\":\"%s\",\"user\":", tok);
    user_json(&b, &ud);
    sb_add(&b, "}");
    send_json(r, 200, b.p);
    sb_free(&b);
out:
    free(u); free(p);
}

/* ---------------- account ---------------- */
static void h_logout(req_t *r) { session_drop(r->token); ok(r); }

static void h_me(req_t *r)
{
    char me[33]; user_t u;
    if (auth(r, me) || user_get(me, &u) < 0) return;
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":true,\"user\":");
    user_json(&b, &u);
    sb_add(&b, "}");
    send_json(r, 200, b.p);
    sb_free(&b);
}

static void h_password(req_t *r)
{
    char me[33];
    if (auth(r, me)) return;
    char *o = req_param(r, "old"), *n = req_param(r, "new");
    if (!o || !n) send_err(r, 400, "paramètres manquants");
    else if (!user_verify(me, o)) send_err(r, 403, "ancien mot de passe incorrect");
    else if (strlen(n) < 8) send_err(r, 400, "nouveau mot de passe trop court (8 minimum)");
    else if (user_set_password(me, n) < 0) send_err(r, 500, "erreur interne");
    else ok(r);
    free(o); free(n);
}

static void h_avatar_set(req_t *r)
{
    char me[33];
    if (auth(r, me)) return;
    if (r->content_length <= 0 || r->content_length > MAX_AVATAR) { send_err(r, 413, "image invalide ou trop grande (5 Mo max)"); return; }
    unsigned char *img = malloc((size_t)r->content_length);
    size_t got = 0;
    while (img && got < (size_t)r->content_length) {
        ssize_t n = req_body_read(r, img + got, (size_t)r->content_length - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    int png = got > 4 && !memcmp(img, "\x89PNG", 4);
    int jpg = got > 3 && img[0] == 0xFF && img[1] == 0xD8 && img[2] == 0xFF;
    if (!img || got != (size_t)r->content_length || !(png || jpg)) { free(img); send_err(r, 400, "format d'image non supporté (PNG ou JPEG)"); return; }
    char path[700], tmp[720];
    snprintf(path, sizeof path, "%s/meta/avatars/%s.img", g_home, me);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    int good = f && fwrite(img, 1, got, f) == got;
    if (f) fclose(f);
    free(img);
    if (good && rename(tmp, path) == 0) ok(r); else { unlink(tmp); send_err(r, 500, "écriture impossible"); }
}

static void h_avatar_get(req_t *r)
{
    char me[33];
    if (auth(r, me)) return;
    char *who = req_param(r, "user");
    if (!who || !valid_username(who)) { free(who); send_err(r, 400, "utilisateur invalide"); return; }
    char path[700];
    snprintf(path, sizeof path, "%s/meta/avatars/%s.img", g_home, who);
    free(who);
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0) { if (fd >= 0) close(fd); send_err(r, 404, "pas d'avatar"); return; }
    unsigned char *buf = malloc((size_t)st.st_size);
    ssize_t n = buf ? read(fd, buf, (size_t)st.st_size) : -1;
    close(fd);
    if (n != st.st_size) { free(buf); send_err(r, 500, "lecture impossible"); return; }
    send_head(r, 200, buf[0] == 0xFF ? "image/jpeg" : "image/png", st.st_size, NULL);
    send_all(r->fd, buf, (size_t)n);
    free(buf);
}

/* ---------------- disks ---------------- */
static void disk_json(sbuf *b, const disk_t *d, int perm)
{
    unsigned long long total = 0, used = 0;
    disk_usage(d->id, &total, &used);
    sb_addf(b, "{\"id\":\"%s\",\"name\":", d->id);
    sb_json(b, d->name);
    sb_addf(b, ",\"size\":%llu,\"used\":%llu,\"personal\":%s,\"owner\":", d->size, used, d->owner[0] ? "true" : "false");
    sb_json(b, d->owner);
    sb_addf(b, ",\"perm\":\"%s\"}", perm >= PERM_RW ? "rw" : "r");
}

static void h_disks(req_t *r)
{
    char me[33];
    if (auth(r, me)) return;
    static __thread disk_t all[512];
    int n = disk_list(all, 512), first = 1;
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":true,\"disks\":[");
    for (int pass = 0; pass < 2; pass++)          /* own personal disk first */
        for (int i = 0; i < n; i++) {
            int mine = !strcmp(all[i].owner, me);
            if ((pass == 0) != mine) continue;
            int p = perm_effective(me, all[i].id);
            if (!p) continue;
            if (!first) sb_add(&b, ",");
            first = 0;
            disk_json(&b, &all[i], p);
        }
    sb_add(&b, "]}");
    send_json(r, 200, b.p);
    sb_free(&b);
}

/* ---------------- files ---------------- */
static void h_list(req_t *r)
{
    char me[33]; ctx_t c;
    if (auth(r, me) || open_ctx(r, me, PERM_READ, &c, "path")) return;
    DIR *d = opendir(c.full);
    if (!d) { send_err(r, 404, "dossier introuvable"); return; }
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":true,\"path\":"); sb_json(&b, c.rel);
    sb_add(&b, ",\"entries\":[");
    struct dirent *e;
    int first = 1;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!strcmp(c.rel, "/") && !strcmp(e->d_name, "lost+found")) continue;
        if (!strncmp(e->d_name, ".hc_upload_", 11)) continue;
        char child[2100];
        if (snprintf(child, sizeof child, "%s/%s", c.full, e->d_name) >= (int)sizeof child) continue;
        struct stat st;
        if (lstat(child, &st) < 0 || !(S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))) continue;
        if (!first) sb_add(&b, ",");
        first = 0;
        sb_add(&b, "{\"name\":"); sb_json(&b, e->d_name);
        sb_addf(&b, ",\"dir\":%s,\"size\":%lld,\"mtime\":%lld", S_ISDIR(st.st_mode) ? "true" : "false",
                (long long)(S_ISDIR(st.st_mode) ? 0 : st.st_size), (long long)st.st_mtime);
        if (S_ISREG(st.st_mode)) {
            char crel[1400];
            snprintf(crel, sizeof crel, "%s%s%s", c.rel, strcmp(c.rel, "/") ? "/" : "", e->d_name);
            if (lock_get(c.d.id, crel, NULL)) sb_add(&b, ",\"locked\":true");
        }
        sb_add(&b, "}");
    }
    closedir(d);
    sb_add(&b, "]}");
    send_json(r, 200, b.p);
    sb_free(&b);
}

static void h_info(req_t *r)
{
    char me[33]; ctx_t c; struct stat st;
    if (auth(r, me) || open_ctx(r, me, PERM_READ, &c, "path")) return;
    if (lstat(c.full, &st) < 0) { send_err(r, 404, "introuvable"); return; }
    sbuf b; sb_init(&b);
    const char *base = strrchr(c.rel, '/');
    base = (base && base[1]) ? base + 1 : "/";
    sb_add(&b, "{\"ok\":true,\"name\":"); sb_json(&b, base);
    sb_add(&b, ",\"path\":"); sb_json(&b, c.rel);
    sb_addf(&b, ",\"dir\":%s,\"size\":%lld,\"mtime\":%lld,\"ctime\":%lld", S_ISDIR(st.st_mode) ? "true" : "false",
            (long long)st.st_size, (long long)st.st_mtime, (long long)st.st_ctime);
    char lowner[33];
    if (lock_get(c.d.id, c.rel, lowner)) { sb_add(&b, ",\"locked\":true,\"lock_owner\":"); sb_json(&b, lowner); }
    sb_add(&b, "}");
    send_json(r, 200, b.p);
    sb_free(&b);
}

static void h_download(req_t *r)
{
    char me[33]; ctx_t c; struct stat st;
    if (auth(r, me) || open_ctx(r, me, PERM_READ, &c, "path") || lock_gate(r, me, &c)) return;
    int fd = open(c.full, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);
        send_err(r, 404, "fichier introuvable"); return;
    }
    char fname[300] = "";
    const char *base = strrchr(c.rel, '/') + 1;
    for (size_t i = 0; base[i] && i < sizeof fname - 2; i++)
        fname[i] = (base[i] == '"' || base[i] == '\\' || (unsigned char)base[i] < 0x20) ? '_' : base[i];
    char extra[400];
    snprintf(extra, sizeof extra, "Content-Disposition: attachment; filename=\"%s\"\r\n", fname);
    send_head(r, 200, "application/octet-stream", st.st_size, extra);
    char *buf = malloc(65536);
    ssize_t n;
    while (buf && (n = read(fd, buf, 65536)) > 0)
        if (send_all(r->fd, buf, (size_t)n) < 0) break;
    free(buf);
    close(fd);
}

static void h_upload(req_t *r)
{
    char me[33]; ctx_t c; struct stat st;
    if (auth(r, me) || open_ctx(r, me, PERM_RW, &c, "path")) return;
    if (!strcmp(c.rel, "/")) { send_err(r, 400, "nom de fichier manquant"); return; }
    if (lock_gate(r, me, &c)) return;                 /* overwriting a locked file needs its password */
    if (r->content_length < 0) { send_err(r, 411, "Content-Length requis"); return; }

    char tmpl[1700];
    snprintf(tmpl, sizeof tmpl, "%s", c.full);
    char *dir = dirname(tmpl);
    if (stat(dir, &st) < 0 || !S_ISDIR(st.st_mode)) { send_err(r, 404, "dossier parent introuvable"); return; }
    struct statvfs sv;
    if (statvfs(dir, &sv) == 0 && (unsigned long long)sv.f_bavail * sv.f_frsize < (unsigned long long)r->content_length + 4096) {
        send_err(r, 507, "espace insuffisant sur l'appareil"); return;
    }
    /* quota logiciel du disque : l'éventuel fichier remplacé est déduit */
    unsigned long long quota = 0, used = 0, old = 0;
    struct stat ost;
    disk_usage(c.d.id, &quota, &used);
    if (lstat(c.full, &ost) == 0 && S_ISREG(ost.st_mode)) old = (unsigned long long)ost.st_size;
    if (used - (old < used ? old : used) + (unsigned long long)r->content_length > quota) {
        send_err(r, 507, "quota du disque dépassé"); return;
    }
    char rnd[17], tmp[1800];
    random_hex(rnd, 8);
    snprintf(tmp, sizeof tmp, "%s/.hc_upload_%s", dir, rnd);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) { send_err(r, 500, "création impossible"); return; }

    char *buf = malloc(65536);
    int good = buf != NULL;
    while (good && r->body_left > 0) {
        ssize_t n = req_body_read(r, buf, 65536);
        if (n <= 0) { good = 0; break; }
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(fd, p, (size_t)n);
            if (w <= 0) { good = 0; break; }
            p += w; n -= w;
        }
        if (n > 0) good = 0;
    }
    free(buf);
    close(fd);
    if (!good) { unlink(tmp); send_err(r, errno == ENOSPC ? 507 : 400, "transfert interrompu"); return; }
    if (lstat(c.full, &st) == 0 && S_ISDIR(st.st_mode)) { unlink(tmp); send_err(r, 409, "un dossier porte déjà ce nom"); return; }
    if (rename(tmp, c.full) < 0) { unlink(tmp); send_err(r, 500, "finalisation impossible"); return; }
    disk_usage_adjust(c.d.id, (long long)r->content_length - (long long)old);
    logmsg("upload '%s' -> %s%s (%lld o)", me, c.d.name, c.rel, r->content_length);
    ok(r);
}

static void h_mkdir(req_t *r)
{
    char me[33]; ctx_t c;
    if (auth(r, me) || open_ctx(r, me, PERM_RW, &c, "path")) return;
    if (!strcmp(c.rel, "/")) { send_err(r, 400, "nom manquant"); return; }
    if (mkdir(c.full, 0755) < 0) { send_err(r, errno == EEXIST ? 409 : 400, errno == EEXIST ? "existe déjà" : "création impossible"); return; }
    ok(r);
}

static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(p);
}

static void h_delete(req_t *r)
{
    char me[33]; ctx_t c; struct stat st;
    if (auth(r, me) || open_ctx(r, me, PERM_RW, &c, "path")) return;
    if (!strcmp(c.rel, "/")) { send_err(r, 400, "impossible de supprimer la racine"); return; }
    if (lstat(c.full, &st) < 0) { send_err(r, 404, "introuvable"); return; }
    if (S_ISDIR(st.st_mode) ? tree_gate(r, me, &c) : lock_gate(r, me, &c)) return;
    int rc = S_ISDIR(st.st_mode) ? nftw(c.full, rm_cb, 32, FTW_DEPTH | FTW_PHYS) : unlink(c.full);
    if (rc < 0) { send_err(r, 500, "suppression impossible"); return; }
    lock_drop_tree(c.d.id, c.rel);
    disk_usage_forget(c.d.id);
    logmsg("suppression '%s' : %s%s", me, c.d.name, c.rel);
    ok(r);
}

static void h_rename(req_t *r)
{
    char me[33]; ctx_t c, t; struct stat st, st2;
    if (auth(r, me) || open_ctx(r, me, PERM_RW, &c, "path")) return;
    if (open_ctx(r, me, PERM_RW, &t, "to")) return;
    if (strcmp(c.d.id, t.d.id)) { send_err(r, 400, "déplacement entre disques non supporté"); return; }
    if (!strcmp(c.rel, "/") || !strcmp(t.rel, "/")) { send_err(r, 400, "chemin invalide"); return; }
    if (lstat(c.full, &st) < 0) { send_err(r, 404, "introuvable"); return; }
    if (lstat(t.full, &st2) == 0) { send_err(r, 409, "la destination existe déjà"); return; }
    if (S_ISDIR(st.st_mode) ? tree_gate(r, me, &c) : lock_gate(r, me, &c)) return;
    if (rename(c.full, t.full) < 0) { send_err(r, 500, "renommage impossible"); return; }
    lock_drop_tree(t.d.id, t.rel);                    /* leftovers at the destination, if any */
    lock_move_tree(c.d.id, c.rel, t.rel);
    ok(r);
}

/* ---------------- file locks ---------------- */
static void h_lock(req_t *r)
{
    char me[33], err[200] = ""; ctx_t c; struct stat st;
    if (auth(r, me) || open_ctx(r, me, PERM_RW, &c, "path")) return;
    char *pass = req_param(r, "pass");
    if (!strcmp(c.rel, "/") || lstat(c.full, &st) < 0) send_err(r, 404, "fichier introuvable");
    else if (!S_ISREG(st.st_mode)) send_err(r, 400, "seuls les fichiers peuvent être verrouillés");
    else if (!pass || !pass[0]) send_err(r, 400, "mot de passe manquant");
    else if (lock_set(c.d.id, c.rel, me, pass, err, sizeof err) < 0) send_err(r, 400, err);
    else { logmsg("verrouillage '%s' : %s%s", me, c.d.name, c.rel); ok(r); }
    free(pass);
}

/* Removes a lock: file password required, except for administrators. */
static void h_unlock(req_t *r)
{
    char me[33]; ctx_t c;
    if (auth(r, me) || open_ctx(r, me, PERM_RW, &c, "path")) return;
    if (!lock_get(c.d.id, c.rel, NULL)) { send_err(r, 400, "ce fichier n'est pas verrouillé"); return; }
    char *pass = req_param(r, "pass");
    if (!is_admin(me) && !(pass && pass[0] && lock_check(c.d.id, c.rel, pass))) {
        if (pass && pass[0]) { logmsg("déverrouillage refusé pour '%s' (%s%s) depuis %s", me, c.d.name, c.rel, r->peer); sleep(1); }
        send_locked(r, pass && pass[0] ? "mot de passe du fichier incorrect" : "mot de passe requis");
    } else if (lock_remove(c.d.id, c.rel) < 0) send_err(r, 500, "erreur interne");
    else { logmsg("déverrouillage '%s' : %s%s", me, c.d.name, c.rel); ok(r); }
    free(pass);
}

/* Lets the client validate a password before opening / downloading / editing (?lockpass=). */
static void h_lock_check(req_t *r)
{
    char me[33]; ctx_t c;
    if (auth(r, me) || open_ctx(r, me, PERM_READ, &c, "path") || lock_gate(r, me, &c)) return;
    ok(r);
}

/* ---------------- administration ---------------- */
static void h_admin_users(req_t *r)
{
    char me[33];
    if (auth(r, me) || need_admin(r, me)) return;
    static __thread user_t us[256];
    int n = user_list(us, 256);
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":true,\"users\":[");
    for (int i = 0; i < n; i++) {
        disk_t d; unsigned long long quota = 0;
        if (disk_get(us[i].personal, &d) == 0) quota = d.size;
        if (i) sb_add(&b, ",");
        sb_add(&b, "{\"name\":"); sb_json(&b, us[i].name);
        sb_addf(&b, ",\"admin\":%s,\"personal\":\"%s\",\"quota\":%llu}", us[i].admin ? "true" : "false", us[i].personal, quota);
    }
    sb_add(&b, "]}");
    send_json(r, 200, b.p);
    sb_free(&b);
}

static void h_admin_user_create(req_t *r)
{
    char me[33], err[400] = "";
    if (auth(r, me) || need_admin(r, me)) return;
    char *name = req_param(r, "name"), *pass = req_param(r, "pass");
    char *q = req_param(r, "quota_gb"), *adm = req_param(r, "admin");
    if (!name || !pass) send_err(r, 400, "paramètres manquants");
    else if (user_create(name, pass, adm && !strcmp(adm, "1"), q ? (unsigned)atoi(q) : (unsigned)g_cfg.default_quota_gb, err, sizeof err) < 0)
        send_err(r, 400, err);
    else { logmsg("utilisateur créé : %s", name); ok(r); }
    free(name); free(pass); free(q); free(adm);
}

static void h_admin_user_delete(req_t *r)
{
    char me[33], err[160] = "";
    if (auth(r, me) || need_admin(r, me)) return;
    char *name = req_param(r, "name");
    if (!name) send_err(r, 400, "paramètres manquants");
    else if (!strcmp(name, me)) send_err(r, 400, "vous ne pouvez pas vous supprimer vous-même");
    else if (user_delete(name, err, sizeof err) < 0) send_err(r, 400, err);
    else { logmsg("utilisateur supprimé : %s", name); ok(r); }
    free(name);
}

static void h_admin_disk_create(req_t *r)
{
    char me[33], err[400] = "", id[17];
    if (auth(r, me) || need_admin(r, me)) return;
    char *name = req_param(r, "name"), *sz = req_param(r, "size_gb");
    long gb = sz ? atol(sz) : 0;
    if (!name || gb < 1 || gb > 100000) send_err(r, 400, "nom ou taille invalide (1 à 100000 Go)");
    else if (disk_create(name, (unsigned long long)gb << 30, "", id, err, sizeof err) < 0) send_err(r, 400, err);
    else {
        logmsg("disque créé : %s (%ld Go)", name, gb);
        sbuf b; sb_init(&b);
        sb_addf(&b, "{\"ok\":true,\"id\":\"%s\"}", id);
        send_json(r, 200, b.p);
        sb_free(&b);
    }
    free(name); free(sz);
}

static void h_admin_disk_delete(req_t *r)
{
    char me[33], err[160] = "";
    disk_t d;
    if (auth(r, me) || need_admin(r, me)) return;
    char *id = req_param(r, "disk");
    if (!id || disk_get(id, &d) < 0) send_err(r, 404, "disque introuvable");
    else if (d.owner[0]) send_err(r, 400, "un espace personnel se supprime avec son utilisateur");
    else if (disk_delete(id, err, sizeof err) < 0) send_err(r, 400, err);
    else { logmsg("disque supprimé : %s", d.name); ok(r); }
    free(id);
}

static void h_admin_perms(req_t *r)
{
    char me[33];
    if (auth(r, me) || need_admin(r, me)) return;
    char *id = req_param(r, "disk");
    if (!id) { send_err(r, 400, "paramètres manquants"); return; }
    static __thread char names[256][33];
    int pm[256];
    int n = perm_for_disk(id, names, pm, 256);
    free(id);
    sbuf b; sb_init(&b);
    sb_add(&b, "{\"ok\":true,\"perms\":[");
    for (int i = 0; i < n; i++) {
        if (i) sb_add(&b, ",");
        sb_add(&b, "{\"user\":"); sb_json(&b, names[i]);
        sb_addf(&b, ",\"perm\":\"%s\"}", pm[i] >= PERM_RW ? "rw" : "r");
    }
    sb_add(&b, "]}");
    send_json(r, 200, b.p);
    sb_free(&b);
}

static void h_admin_perm_set(req_t *r)
{
    char me[33];
    if (auth(r, me) || need_admin(r, me)) return;
    char *id = req_param(r, "disk"), *u = req_param(r, "user"), *p = req_param(r, "perm");
    int perm = !p ? -1 : !strcmp(p, "rw") ? PERM_RW : !strcmp(p, "r") ? PERM_READ : !strcmp(p, "none") ? PERM_NONE : -1;
    if (!id || !u || perm < 0) send_err(r, 400, "paramètres invalides");
    else if (perm_set(id, u, perm) < 0) send_err(r, 400, "disque/utilisateur introuvable ou espace personnel");
    else ok(r);
    free(id); free(u); free(p);
}

/* ---------------- routing ---------------- */
typedef struct { const char *method, *path; void (*fn)(req_t *); } route_t;

static const route_t routes[] = {
    { "GET",  "/api/ping",              h_ping },
    { "POST", "/api/login",             h_login },
    { "POST", "/api/logout",            h_logout },
    { "GET",  "/api/me",                h_me },
    { "POST", "/api/password",          h_password },
    { "POST", "/api/avatar",            h_avatar_set },
    { "GET",  "/api/avatar",            h_avatar_get },
    { "GET",  "/api/disks",             h_disks },
    { "GET",  "/api/list",              h_list },
    { "GET",  "/api/info",              h_info },
    { "GET",  "/api/download",          h_download },
    { "POST", "/api/upload",            h_upload },
    { "POST", "/api/mkdir",             h_mkdir },
    { "POST", "/api/delete",            h_delete },
    { "POST", "/api/rename",            h_rename },
    { "POST", "/api/lock",              h_lock },
    { "POST", "/api/unlock",            h_unlock },
    { "POST", "/api/lock_check",        h_lock_check },
    { "GET",  "/api/admin/users",       h_admin_users },
    { "POST", "/api/admin/user_create", h_admin_user_create },
    { "POST", "/api/admin/user_delete", h_admin_user_delete },
    { "POST", "/api/admin/disk_create", h_admin_disk_create },
    { "POST", "/api/admin/disk_delete", h_admin_disk_delete },
    { "GET",  "/api/admin/perms",       h_admin_perms },
    { "POST", "/api/admin/perm_set",    h_admin_perm_set },
};

void api_dispatch(req_t *r)
{
    int path_seen = 0;
    for (size_t i = 0; i < sizeof routes / sizeof *routes; i++) {
        if (strcmp(r->path, routes[i].path)) continue;
        path_seen = 1;                                   /* same path may exist with several methods (GET|POST /api/avatar) */
        if (!strcmp(r->method, routes[i].method)) { routes[i].fn(r); return; }
    }
    if (path_seen) send_err(r, 400, "méthode non supportée");
    else send_err(r, 404, "route inconnue");
}
