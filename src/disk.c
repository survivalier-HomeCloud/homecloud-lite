/*
 * Disques « lite » : sans root, sans LUKS, sans montage.
 *
 * Chaque espace est un simple dossier <données>/disks/<id>/. La taille indiquée à la
 * création est un QUOTA LOGICIEL : le serveur refuse un envoi qui le dépasserait.
 * L'occupation est calculée en parcourant le dossier (résultat gardé en cache quelques
 * secondes pour ne pas reparcourir l'arborescence à chaque requête).
 */
#include "hc.h"
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#define UCACHE_MAX 512
#define UCACHE_TTL 15            /* secondes */

typedef struct { char id[17]; unsigned long long used; time_t when; } ucache_t;
static ucache_t ucache[UCACHE_MAX];
static pthread_mutex_t ulk = PTHREAD_MUTEX_INITIALIZER;

static void default_dir(const char *id, char *out, size_t sz)
{
    snprintf(out, sz, "%s/disks/%s", g_cfg.data_dir, id);
}

/* dossier réel d'un disque : le dossier source pour un montage, sinon <données>/disks/<id> */
void disk_dir(const char *id, char *out, size_t sz)
{
    disk_t d;
    if (disk_get(id, &d) == 0 && d.src[0]) snprintf(out, sz, "%s", d.src);
    else default_dir(id, out, sz);
}

/* Un lien symbolique placé dans le dossier monté ne doit pas permettre d'en sortir. */
int mount_inside(const disk_t *d, const char *full)
{
    if (!d->src[0]) return 1;
    char real[PATH_MAX];
    if (!realpath(full, real)) return errno == ENOENT || errno == ENOTDIR;   /* inexistant : les handlers répondent 404 */
    size_t n = strlen(d->src);
    return !strncmp(real, d->src, n) && (real[n] == 0 || real[n] == '/');
}

int disk_make(const char *id, char *err, size_t esz)
{
    char d[640];
    disk_dir(id, d, sizeof d);
    if (mkdir(d, 0700) < 0) {
        if (err) snprintf(err, esz, "impossible de créer le dossier du disque (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

/* ---------- suppression récursive ---------- */
static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(p);
}

int rm_tree(const char *path)
{
    return nftw(path, rm_cb, 32, FTW_DEPTH | FTW_PHYS);
}

/* Ne supprime JAMAIS qu'un dossier de <données>/disks : un dossier monté n'est donc jamais touché. */
int disk_destroy(const char *id)
{
    char d[640];
    default_dir(id, d, sizeof d);
    disk_usage_forget(id);
    rm_tree(d);
    return 0;
}

/* ---------- occupation ---------- */
static __thread unsigned long long walk_total;

static int sum_cb(const char *p, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)p; (void)ftw;
    if (flag == FTW_F) walk_total += (unsigned long long)sb->st_size;
    return 0;
}

static unsigned long long walk_used(const char *id)
{
    char d[640];
    disk_dir(id, d, sizeof d);
    walk_total = 0;
    nftw(d, sum_cb, 16, FTW_PHYS);
    return walk_total;
}

static ucache_t *cache_slot(const char *id, int create)
{
    ucache_t *free_slot = NULL, *oldest = &ucache[0];
    for (int i = 0; i < UCACHE_MAX; i++) {
        if (!strcmp(ucache[i].id, id)) return &ucache[i];
        if (!ucache[i].id[0] && !free_slot) free_slot = &ucache[i];
        if (ucache[i].when < oldest->when) oldest = &ucache[i];
    }
    if (!create) return NULL;
    ucache_t *s = free_slot ? free_slot : oldest;
    memset(s, 0, sizeof *s);
    snprintf(s->id, sizeof s->id, "%s", id);
    return s;
}

int disk_usage(const char *id, unsigned long long *total, unsigned long long *used)
{
    disk_t d;
    if (disk_get(id, &d) < 0) return -1;
    if (d.src[0]) {                                  /* montage : occupation du volume source, sans parcours */
        struct statvfs sv;
        if (statvfs(d.src, &sv) < 0) return -1;
        *total = (unsigned long long)sv.f_blocks * sv.f_frsize;
        *used  = (unsigned long long)(sv.f_blocks - sv.f_bfree) * sv.f_frsize;
        return 0;
    }
    time_t now = time(NULL);
    unsigned long long u = 0;
    int fresh = 0;

    pthread_mutex_lock(&ulk);
    ucache_t *c = cache_slot(id, 0);
    if (c && c->when && now - c->when < UCACHE_TTL) { u = c->used; fresh = 1; }
    pthread_mutex_unlock(&ulk);

    if (!fresh) {                                   /* parcours hors verrou */
        u = walk_used(id);
        pthread_mutex_lock(&ulk);
        c = cache_slot(id, 1);
        c->used = u;
        c->when = now;
        pthread_mutex_unlock(&ulk);
    }
    *total = d.size;
    *used = u;
    return 0;
}

void disk_usage_forget(const char *id)
{
    pthread_mutex_lock(&ulk);
    ucache_t *c = cache_slot(id, 0);
    if (c) memset(c, 0, sizeof *c);
    pthread_mutex_unlock(&ulk);
}

void disk_usage_adjust(const char *id, long long delta)
{
    pthread_mutex_lock(&ulk);
    ucache_t *c = cache_slot(id, 0);
    if (c) {
        if (delta < 0 && (unsigned long long)(-delta) > c->used) c->used = 0;
        else c->used = (unsigned long long)((long long)c->used + delta);
    }
    pthread_mutex_unlock(&ulk);
}
