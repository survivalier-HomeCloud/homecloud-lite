/* Configuration, users, disks, permissions and sessions. Flat TSV files, one global lock. */
#include "hc.h"
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define MAXU 256
#define MAXD 512
#define MAXP 4096
#define MAXS 256
#define MAXL 4096
#define SESSION_TTL (12 * 3600)

typedef struct { char disk[17]; char user[33]; int perm; } perm_t;
typedef struct { char token[65]; char user[33]; time_t expiry; } session_t;
/* file lock: path is the clean path inside the disk ("/dir/file.txt") */
typedef struct { char disk[17]; char path[1024]; char owner[33]; char salt[33]; char hash[65]; } lock_t;

config_t g_cfg;
static pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
static user_t    users[MAXU];   static int nusers;
static disk_t    disks[MAXD];   static int ndisks;
static perm_t    perms[MAXP];   static int nperms;
static lock_t    locks[MAXL];   static int nlocks;
static session_t sess[MAXS];

/* ================= configuration ================= */
int config_load(void)
{
    snprintf(g_cfg.server_name, sizeof g_cfg.server_name, "HomeCloud");
    snprintf(g_cfg.data_dir, sizeof g_cfg.data_dir, "%.500s/data", g_home);
    g_cfg.port = HC_DEFAULT_PORT;
    g_cfg.default_quota_gb = HC_MIN_QUOTA_GB;

    char conf[640];
    snprintf(conf, sizeof conf, "%s/homecloud.conf", g_home);
    FILE *f = fopen(conf, "r");
    if (!f) return -1;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
        if (line[0] == '#' || !line[0]) continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char *k = line, *v = eq + 1;
        if      (!strcmp(k, "server_name"))      snprintf(g_cfg.server_name, sizeof g_cfg.server_name, "%s", v);
        else if (!strcmp(k, "data_dir"))         snprintf(g_cfg.data_dir, sizeof g_cfg.data_dir, "%s", v);
        else if (!strcmp(k, "port"))             g_cfg.port = atoi(v);
        else if (!strcmp(k, "default_quota_gb")) g_cfg.default_quota_gb = atoi(v);
    }
    fclose(f);
    if (g_cfg.default_quota_gb < HC_MIN_QUOTA_GB) g_cfg.default_quota_gb = HC_MIN_QUOTA_GB;
    if (g_cfg.port < 1 || g_cfg.port > 65535) g_cfg.port = HC_DEFAULT_PORT;
    return 0;
}

int config_save(const config_t *c)
{
    char conf[640];
    snprintf(conf, sizeof conf, "%s/homecloud.conf", g_home);
    mkdir_p(g_home, 0700);
    FILE *f = fopen(conf, "w");
    if (!f) return -1;
    fprintf(f, "# Home Cloud server configuration\n");
    fprintf(f, "server_name=%s\ndata_dir=%s\nport=%d\ndefault_quota_gb=%d\n",
            c->server_name, c->data_dir, c->port, c->default_quota_gb);
    fclose(f);
    chmod(conf, 0600);
    return 0;
}

/* ================= persistence ================= */
static void meta_path(char *out, size_t sz, const char *name)
{
    snprintf(out, sz, "%s/meta/%s", g_home, name);   /* toujours dans le dossier privé de Termux */
}

static int split_tab(char *line, char **f, int max)
{
    int n = 0;
    char *p = line;
    while (n < max && p) f[n++] = strsep(&p, "\t");
    return n;
}

static void load_all(void)
{
    char path[640], line[1024], *f[6];
    FILE *fp;

    meta_path(path, sizeof path, "users.tsv");
    if ((fp = fopen(path, "r"))) {
        while (nusers < MAXU && fgets(line, sizeof line, fp)) {
            line[strcspn(line, "\r\n")] = 0;
            if (split_tab(line, f, 5) < 5) continue;
            user_t *u = &users[nusers++];
            snprintf(u->name, sizeof u->name, "%s", f[0]);
            snprintf(u->salt, sizeof u->salt, "%s", f[1]);
            snprintf(u->hash, sizeof u->hash, "%s", f[2]);
            u->admin = atoi(f[3]);
            snprintf(u->personal, sizeof u->personal, "%s", f[4]);
        }
        fclose(fp);
    }
    meta_path(path, sizeof path, "disks.tsv");
    if ((fp = fopen(path, "r"))) {
        while (ndisks < MAXD && fgets(line, sizeof line, fp)) {
            line[strcspn(line, "\r\n")] = 0;
            int nf = split_tab(line, f, 5);
            if (nf < 4) continue;
            disk_t *d = &disks[ndisks++];
            memset(d, 0, sizeof *d);
            snprintf(d->id, sizeof d->id, "%s", f[0]);
            snprintf(d->name, sizeof d->name, "%s", f[1]);
            d->size = strtoull(f[2], NULL, 10);
            snprintf(d->owner, sizeof d->owner, "%s", f[3]);
            if (nf >= 5) snprintf(d->src, sizeof d->src, "%s", f[4]);
        }
        fclose(fp);
    }
    meta_path(path, sizeof path, "perms.tsv");
    if ((fp = fopen(path, "r"))) {
        while (nperms < MAXP && fgets(line, sizeof line, fp)) {
            line[strcspn(line, "\r\n")] = 0;
            if (split_tab(line, f, 3) < 3) continue;
            perm_t *p = &perms[nperms++];
            snprintf(p->disk, sizeof p->disk, "%s", f[0]);
            snprintf(p->user, sizeof p->user, "%s", f[1]);
            p->perm = atoi(f[2]);
        }
        fclose(fp);
    }
    meta_path(path, sizeof path, "locks.tsv");
    if ((fp = fopen(path, "r"))) {
        char big[2400], *lf[6];
        while (nlocks < MAXL && fgets(big, sizeof big, fp)) {
            big[strcspn(big, "\r\n")] = 0;
            if (split_tab(big, lf, 5) < 5) continue;
            lock_t *l = &locks[nlocks++];
            snprintf(l->disk, sizeof l->disk, "%s", lf[0]);
            snprintf(l->path, sizeof l->path, "%s", lf[1]);
            snprintf(l->owner, sizeof l->owner, "%s", lf[2]);
            snprintf(l->salt, sizeof l->salt, "%s", lf[3]);
            snprintf(l->hash, sizeof l->hash, "%s", lf[4]);
        }
        fclose(fp);
    }
}

/* writes one file atomically (tmp + rename) */
static void save_file(const char *name, void (*writer)(FILE *))
{
    char path[640], tmp[660];
    meta_path(path, sizeof path, name);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) { logmsg("sauvegarde %s impossible: %s", name, strerror(errno)); return; }
    writer(f);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    chmod(tmp, 0600);
    rename(tmp, path);
}

static void w_users(FILE *f) { for (int i = 0; i < nusers; i++) fprintf(f, "%s\t%s\t%s\t%d\t%s\n", users[i].name, users[i].salt, users[i].hash, users[i].admin, users[i].personal); }
static void w_disks(FILE *f) { for (int i = 0; i < ndisks; i++) fprintf(f, "%s\t%s\t%llu\t%s\t%s\n", disks[i].id, disks[i].name, disks[i].size, disks[i].owner, disks[i].src); }
static void w_perms(FILE *f) { for (int i = 0; i < nperms; i++) fprintf(f, "%s\t%s\t%d\n", perms[i].disk, perms[i].user, perms[i].perm); }

static void w_locks(FILE *f) { for (int i = 0; i < nlocks; i++) fprintf(f, "%s\t%s\t%s\t%s\t%s\n", locks[i].disk, locks[i].path, locks[i].owner, locks[i].salt, locks[i].hash); }

static void save_locked(void)
{
    save_file("users.tsv", w_users);
    save_file("disks.tsv", w_disks);
    save_file("perms.tsv", w_perms);
    save_file("locks.tsv", w_locks);
}

int store_init(void)
{
    char p[640];
    const char *sub[] = { "", "/disks" };
    for (size_t i = 0; i < sizeof sub / sizeof *sub; i++) {
        snprintf(p, sizeof p, "%s%s", g_cfg.data_dir, sub[i]);
        if (mkdir_p(p, 0700) < 0) return -1;
    }
    snprintf(p, sizeof p, "%s/meta/avatars", g_home);   /* mots de passe, verrous, avatars : jamais sur le stockage partagé */
    if (mkdir_p(p, 0700) < 0) return -1;
    pthread_mutex_lock(&lk);
    nusers = ndisks = nperms = nlocks = 0;
    load_all();
    pthread_mutex_unlock(&lk);
    return 0;
}

/* ================= passwords ================= */
static void hash_pw(const char *pw, const char *salt, char out[65])
{
    unsigned char dk[32];
    PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), (const unsigned char *)salt, (int)strlen(salt),
                      200000, EVP_sha256(), 32, dk);
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", dk[i]);
}

/* ================= lookups (lock must be held) ================= */
static user_t *find_user(const char *name)
{
    for (int i = 0; i < nusers; i++) if (!strcmp(users[i].name, name)) return &users[i];
    return NULL;
}
static disk_t *find_disk(const char *id)
{
    for (int i = 0; i < ndisks; i++) if (!strcmp(disks[i].id, id)) return &disks[i];
    return NULL;
}

/* ================= users ================= */
int user_get(const char *name, user_t *out)
{
    pthread_mutex_lock(&lk);
    user_t *u = find_user(name);
    if (u) *out = *u;
    pthread_mutex_unlock(&lk);
    return u ? 0 : -1;
}

int user_list(user_t *out, int max)
{
    pthread_mutex_lock(&lk);
    int n = nusers < max ? nusers : max;
    memcpy(out, users, (size_t)n * sizeof(user_t));
    pthread_mutex_unlock(&lk);
    return n;
}

int user_verify(const char *name, const char *pass)
{
    user_t u;
    char h[65];
    int exists = user_get(name, &u) == 0;
    if (!exists) { snprintf(u.salt, sizeof u.salt, "00000000000000000000000000000000"); snprintf(u.hash, sizeof u.hash, "x"); }
    hash_pw(pass, u.salt, h);                      /* always hash: constant-ish timing */
    return exists && CRYPTO_memcmp(h, u.hash, 64) == 0;
}

int user_set_password(const char *name, const char *pass)
{
    char salt[33], h[65];
    if (random_hex(salt, 16) < 0) return -1;
    hash_pw(pass, salt, h);
    pthread_mutex_lock(&lk);
    user_t *u = find_user(name);
    if (u) {
        snprintf(u->salt, sizeof u->salt, "%s", salt);
        snprintf(u->hash, sizeof u->hash, "%s", h);
        save_locked();
    }
    pthread_mutex_unlock(&lk);
    return u ? 0 : -1;
}

int user_create(const char *name, const char *pass, int admin, unsigned quota_gb, char *err, size_t esz)
{
    if (!valid_username(name)) { snprintf(err, esz, "nom d'utilisateur invalide (2-32 car. : lettres, chiffres, . _ -)"); return -1; }
    if (strlen(pass) < 8)      { snprintf(err, esz, "mot de passe trop court (8 caractères minimum)"); return -1; }
    if (quota_gb < HC_MIN_QUOTA_GB) { snprintf(err, esz, "quota minimum : %d Go", HC_MIN_QUOTA_GB); return -1; }

    pthread_mutex_lock(&lk);
    int bad = find_user(name) != NULL || nusers >= MAXU;
    pthread_mutex_unlock(&lk);
    if (bad) { snprintf(err, esz, "utilisateur existant ou limite atteinte"); return -1; }

    char id[17];
    char dname[65];
    snprintf(dname, sizeof dname, "Espace de %s", name);
    if (disk_create(dname, (unsigned long long)quota_gb << 30, name, id, err, esz) < 0) return -1;

    char salt[33], h[65];
    random_hex(salt, 16);
    hash_pw(pass, salt, h);

    pthread_mutex_lock(&lk);
    if (find_user(name) || nusers >= MAXU) {
        pthread_mutex_unlock(&lk);
        disk_delete(id, err, esz);
        snprintf(err, esz, "utilisateur existant");
        return -1;
    }
    user_t *u = &users[nusers++];
    memset(u, 0, sizeof *u);
    snprintf(u->name, sizeof u->name, "%s", name);
    snprintf(u->salt, sizeof u->salt, "%s", salt);
    snprintf(u->hash, sizeof u->hash, "%s", h);
    u->admin = admin ? 1 : 0;
    snprintf(u->personal, sizeof u->personal, "%s", id);
    save_locked();
    pthread_mutex_unlock(&lk);
    return 0;
}

static void remove_disk_locked(const char *id)
{
    for (int i = 0; i < ndisks; i++)
        if (!strcmp(disks[i].id, id)) { disks[i] = disks[--ndisks]; break; }
    for (int i = 0; i < nperms; ) {
        if (!strcmp(perms[i].disk, id)) perms[i] = perms[--nperms]; else i++;
    }
    for (int i = 0; i < nlocks; ) {
        if (!strcmp(locks[i].disk, id)) locks[i] = locks[--nlocks]; else i++;
    }
}

int user_delete(const char *name, char *err, size_t esz)
{
    pthread_mutex_lock(&lk);
    user_t *u = find_user(name);
    if (!u) { pthread_mutex_unlock(&lk); snprintf(err, esz, "utilisateur introuvable"); return -1; }
    if (u->admin) {
        int admins = 0;
        for (int i = 0; i < nusers; i++) admins += users[i].admin;
        if (admins <= 1) { pthread_mutex_unlock(&lk); snprintf(err, esz, "impossible de supprimer le dernier administrateur"); return -1; }
    }
    char pid[17];
    snprintf(pid, sizeof pid, "%s", u->personal);
    *u = users[--nusers];
    remove_disk_locked(pid);
    for (int i = 0; i < nperms; ) {
        if (!strcmp(perms[i].user, name)) perms[i] = perms[--nperms]; else i++;
    }
    save_locked();
    pthread_mutex_unlock(&lk);

    disk_destroy(pid);
    char ap[700];
    snprintf(ap, sizeof ap, "%s/meta/avatars/%s.img", g_home, name);
    unlink(ap);
    return 0;
}

/* ================= disks ================= */
int disk_get(const char *id, disk_t *out)
{
    pthread_mutex_lock(&lk);
    disk_t *d = find_disk(id);
    if (d) *out = *d;
    pthread_mutex_unlock(&lk);
    return d ? 0 : -1;
}

int disk_list(disk_t *out, int max)
{
    pthread_mutex_lock(&lk);
    int n = ndisks < max ? ndisks : max;
    memcpy(out, disks, (size_t)n * sizeof(disk_t));
    pthread_mutex_unlock(&lk);
    return n;
}

int disk_create(const char *name, unsigned long long size, const char *owner, char *id_out, char *err, size_t esz)
{
    if (!*name || strlen(name) > 64) { snprintf(err, esz, "nom de disque invalide (1-64 caractères)"); return -1; }
    if (size < (1ULL << 30))         { snprintf(err, esz, "taille minimale : 1 Go"); return -1; }
    pthread_mutex_lock(&lk);
    int full = ndisks >= MAXD;
    pthread_mutex_unlock(&lk);
    if (full) { snprintf(err, esz, "nombre maximal de disques atteint"); return -1; }

    char id[17];
    if (random_hex(id, 8) < 0) { snprintf(err, esz, "aléa indisponible"); return -1; }
    if (disk_make(id, err, esz) < 0) return -1;

    pthread_mutex_lock(&lk);
    disk_t *d = &disks[ndisks++];
    memset(d, 0, sizeof *d);
    snprintf(d->id, sizeof d->id, "%s", id);
    for (const char *s = name; *s && strlen(d->name) < sizeof d->name - 1; s++) {
        char c[2] = { (*s == '\t' || *s == '\n' || *s == '\r') ? ' ' : *s, 0 };
        strcat(d->name, c);
    }
    snprintf(d->owner, sizeof d->owner, "%s", owner ? owner : "");
    d->size = size;
    save_locked();
    pthread_mutex_unlock(&lk);
    if (id_out) snprintf(id_out, 17, "%s", id);
    return 0;
}

int disk_delete(const char *id, char *err, size_t esz)
{
    pthread_mutex_lock(&lk);
    disk_t *d = find_disk(id);
    if (!d) { pthread_mutex_unlock(&lk); snprintf(err, esz, "disque introuvable"); return -1; }
    int mounted = d->src[0] != 0;
    remove_disk_locked(id);
    save_locked();
    pthread_mutex_unlock(&lk);
    if (mounted) disk_usage_forget(id);               /* démontage : le dossier source reste intact */
    else disk_destroy(id);
    return 0;
}

/* dir == p, ou p se trouve sous dir */
static int path_within(const char *dir, const char *p)
{
    size_t n = strlen(dir);
    if (n == 1 && dir[0] == '/') return p[0] == '/';
    return !strncmp(p, dir, n) && (p[n] == 0 || p[n] == '/');
}

/* Monte un dossier local comme disque en lecture seule, visible par tous les utilisateurs. */
int disk_mount(const char *name, const char *path, char *id_out, char *err, size_t esz)
{
    char real[PATH_MAX], other[PATH_MAX];
    struct stat st;
    if (!path || !*path) { snprintf(err, esz, "chemin manquant"); return -1; }
    if (strpbrk(path, "\t\r\n")) { snprintf(err, esz, "chemin non supporté (caractère de contrôle)"); return -1; }
    if (!realpath(path, real)) { snprintf(err, esz, "dossier introuvable (%s)", strerror(errno)); return -1; }
    if (stat(real, &st) < 0 || !S_ISDIR(st.st_mode)) { snprintf(err, esz, "ce n'est pas un dossier"); return -1; }
    if (access(real, R_OK | X_OK) < 0) { snprintf(err, esz, "dossier non lisible (%s)", strerror(errno)); return -1; }
    if (strlen(real) >= sizeof ((disk_t *)0)->src) { snprintf(err, esz, "chemin trop long"); return -1; }

    /* jamais le dossier privé (mots de passe, verrous) ni les espaces des utilisateurs, ni un de leurs parents */
    if ((realpath(g_home, other) && (path_within(real, other) || path_within(other, real))) ||
        (realpath(g_cfg.data_dir, other) && (path_within(real, other) || path_within(other, real)))) {
        snprintf(err, esz, "ce dossier contient (ou se trouve dans) les données de Home Cloud : choisissez-en un autre");
        return -1;
    }

    char label[65] = "";
    const char *src_name = (name && *name) ? name : strrchr(real, '/') + 1;
    for (const char *s = src_name; *s && strlen(label) < sizeof label - 1; s++) {
        char c[2] = { (*s == '\t' || *s == '\n' || *s == '\r') ? ' ' : *s, 0 };
        strcat(label, c);
    }
    if (!label[0]) { snprintf(err, esz, "nom de disque invalide (1-64 caractères)"); return -1; }

    char id[17];
    if (random_hex(id, 8) < 0) { snprintf(err, esz, "aléa indisponible"); return -1; }

    pthread_mutex_lock(&lk);
    int rc = -1;
    if (ndisks >= MAXD) snprintf(err, esz, "nombre maximal de disques atteint");
    else {
        for (int i = 0; i < ndisks; i++) {
            if (!strcmp(disks[i].src, real)) { snprintf(err, esz, "ce dossier est déjà monté (« %s »)", disks[i].name); goto done; }
            if (!strcmp(disks[i].name, label)) { snprintf(err, esz, "un disque porte déjà le nom « %s »", label); goto done; }
        }
        disk_t *d = &disks[ndisks++];
        memset(d, 0, sizeof *d);
        snprintf(d->id, sizeof d->id, "%s", id);
        snprintf(d->name, sizeof d->name, "%s", label);
        snprintf(d->src, sizeof d->src, "%s", real);
        save_locked();
        if (id_out) snprintf(id_out, 17, "%s", id);
        rc = 0;
    }
done:
    pthread_mutex_unlock(&lk);
    return rc;
}

/* ================= permissions ================= */
int perm_effective(const char *user, const char *diskid)
{
    int r = PERM_NONE;
    pthread_mutex_lock(&lk);
    user_t *u = find_user(user);
    disk_t *d = find_disk(diskid);
    if (u && d) {
        if (d->src[0]) r = PERM_READ;               /* montage : lecture seule pour tout le monde, administrateurs compris */
        else if (u->admin) r = PERM_RW;
        else if (d->owner[0]) r = strcmp(d->owner, user) == 0 ? PERM_RW : PERM_NONE;
        else for (int i = 0; i < nperms; i++)
            if (!strcmp(perms[i].disk, diskid) && !strcmp(perms[i].user, user)) { r = perms[i].perm; break; }
    }
    pthread_mutex_unlock(&lk);
    return r;
}

int perm_set(const char *diskid, const char *user, int perm)
{
    int rc = -1;
    pthread_mutex_lock(&lk);
    disk_t *d = find_disk(diskid);
    user_t *u = find_user(user);
    if (d && u && !d->owner[0] && !d->src[0] && perm >= 0 && perm <= 2) {
        for (int i = 0; i < nperms; i++)
            if (!strcmp(perms[i].disk, diskid) && !strcmp(perms[i].user, user)) {
                if (perm == PERM_NONE) perms[i] = perms[--nperms]; else perms[i].perm = perm;
                rc = 0; goto done;
            }
        if (perm != PERM_NONE && nperms < MAXP) {
            perm_t *p = &perms[nperms++];
            snprintf(p->disk, sizeof p->disk, "%s", diskid);
            snprintf(p->user, sizeof p->user, "%s", user);
            p->perm = perm;
        }
        rc = 0;
    }
done:
    if (rc == 0) save_locked();
    pthread_mutex_unlock(&lk);
    return rc;
}

int perm_for_disk(const char *diskid, char users_out[][33], int *perms_out, int max)
{
    int n = 0;
    pthread_mutex_lock(&lk);
    for (int i = 0; i < nperms && n < max; i++)
        if (!strcmp(perms[i].disk, diskid)) {
            snprintf(users_out[n], 33, "%s", perms[i].user);
            perms_out[n++] = perms[i].perm;
        }
    pthread_mutex_unlock(&lk);
    return n;
}

/* ================= file locks =================
 * A locked file asks for its own password to be opened, downloaded, modified, renamed or deleted
 * (administrators are exempt: the API layer skips the check for them). */
static lock_t *find_lock(const char *disk, const char *path)
{
    for (int i = 0; i < nlocks; i++)
        if (!strcmp(locks[i].disk, disk) && !strcmp(locks[i].path, path)) return &locks[i];
    return NULL;
}

/* does `path` lie strictly inside directory `dir` ? */
static int is_under(const char *dir, const char *path)
{
    size_t n = strlen(dir);
    if (n == 1 && dir[0] == '/') return path[0] == '/' && path[1];
    return !strncmp(path, dir, n) && path[n] == '/';
}

int lock_get(const char *disk, const char *path, char *owner_out)
{
    pthread_mutex_lock(&lk);
    lock_t *l = find_lock(disk, path);
    if (l && owner_out) snprintf(owner_out, 33, "%s", l->owner);
    int r = l != NULL;
    pthread_mutex_unlock(&lk);
    return r;
}

/* 1 = not locked or password correct, 0 = wrong password. The slow hash runs outside the global lock. */
int lock_check(const char *disk, const char *path, const char *pass)
{
    char salt[33], want[65], h[65];
    pthread_mutex_lock(&lk);
    lock_t *l = find_lock(disk, path);
    if (l) { snprintf(salt, sizeof salt, "%s", l->salt); snprintf(want, sizeof want, "%s", l->hash); }
    pthread_mutex_unlock(&lk);
    if (!l) return 1;
    if (!pass) return 0;
    hash_pw(pass, salt, h);
    return CRYPTO_memcmp(h, want, 64) == 0;
}

int lock_set(const char *disk, const char *path, const char *owner, const char *pass, char *err, size_t esz)
{
    if (strlen(pass) < LOCK_MIN_PASS) { snprintf(err, esz, "mot de passe trop court (%d caractères minimum)", LOCK_MIN_PASS); return -1; }
    if (strpbrk(path, "\t\r\n")) { snprintf(err, esz, "nom de fichier non supporté pour le verrouillage"); return -1; }
    char salt[33], h[65];
    if (random_hex(salt, 16) < 0) { snprintf(err, esz, "erreur interne"); return -1; }
    hash_pw(pass, salt, h);
    pthread_mutex_lock(&lk);
    int rc = -1;
    if (find_lock(disk, path)) snprintf(err, esz, "ce fichier est déjà verrouillé");
    else if (nlocks >= MAXL) snprintf(err, esz, "nombre maximal de fichiers verrouillés atteint");
    else {
        lock_t *l = &locks[nlocks++];
        memset(l, 0, sizeof *l);
        snprintf(l->disk, sizeof l->disk, "%s", disk);
        snprintf(l->path, sizeof l->path, "%s", path);
        snprintf(l->owner, sizeof l->owner, "%s", owner);
        snprintf(l->salt, sizeof l->salt, "%s", salt);
        snprintf(l->hash, sizeof l->hash, "%s", h);
        save_locked();
        rc = 0;
    }
    pthread_mutex_unlock(&lk);
    return rc;
}

int lock_remove(const char *disk, const char *path)
{
    pthread_mutex_lock(&lk);
    lock_t *l = find_lock(disk, path);
    if (l) { *l = locks[--nlocks]; save_locked(); }
    pthread_mutex_unlock(&lk);
    return l ? 0 : -1;
}

int lock_count_under(const char *disk, const char *dir)
{
    int n = 0;
    pthread_mutex_lock(&lk);
    for (int i = 0; i < nlocks; i++)
        if (!strcmp(locks[i].disk, disk) && is_under(dir, locks[i].path)) n++;
    pthread_mutex_unlock(&lk);
    return n;
}

/* removes the lock of `path` and of everything below it (after a deletion) */
void lock_drop_tree(const char *disk, const char *path)
{
    int changed = 0;
    pthread_mutex_lock(&lk);
    for (int i = 0; i < nlocks; ) {
        if (!strcmp(locks[i].disk, disk) && (!strcmp(locks[i].path, path) || is_under(path, locks[i].path))) {
            locks[i] = locks[--nlocks]; changed = 1;
        } else i++;
    }
    if (changed) save_locked();
    pthread_mutex_unlock(&lk);
}

/* a file or folder was renamed: locks follow it */
void lock_move_tree(const char *disk, const char *from, const char *to)
{
    int changed = 0;
    size_t fl = strlen(from);
    pthread_mutex_lock(&lk);
    for (int i = 0; i < nlocks; i++) {
        if (strcmp(locks[i].disk, disk)) continue;
        if (strcmp(locks[i].path, from) && !is_under(from, locks[i].path)) continue;
        char np[1024];
        if (snprintf(np, sizeof np, "%s%s", to, locks[i].path + fl) >= (int)sizeof np) continue;
        snprintf(locks[i].path, sizeof locks[i].path, "%s", np);
        changed = 1;
    }
    if (changed) save_locked();
    pthread_mutex_unlock(&lk);
}

/* au démarrage : s'assure que le dossier de chaque disque existe */
void store_check_disks(void)
{
    static disk_t tmp[MAXD];
    int n = disk_list(tmp, MAXD);
    for (int i = 0; i < n; i++) {
        char d[640];
        disk_dir(tmp[i].id, d, sizeof d);
        if (tmp[i].src[0]) {                           /* montage : on ne crée rien, on vérifie seulement */
            struct stat st;
            if (stat(d, &st) == 0 && S_ISDIR(st.st_mode)) logmsg("montage en lecture seule prêt : %s (%s)", tmp[i].name, tmp[i].id);
            else logmsg("ATTENTION : dossier monté introuvable pour %s (%s)", tmp[i].name, tmp[i].id);
            continue;
        }
        if (mkdir_p(d, 0700) == 0) logmsg("disque prêt : %s (%s)", tmp[i].name, tmp[i].id);
        else logmsg("ERREUR : dossier introuvable pour %s (%s)", tmp[i].name, tmp[i].id);
    }
}

/* ================= sessions ================= */
int session_new(const char *user, char *token_out)
{
    char tok[65];
    if (random_hex(tok, 32) < 0) return -1;
    time_t now = time(NULL);
    pthread_mutex_lock(&lk);
    int slot = 0;
    for (int i = 0; i < MAXS; i++) {
        if (!sess[i].token[0] || sess[i].expiry < now) { slot = i; break; }
        if (sess[i].expiry < sess[slot].expiry) slot = i;
    }
    snprintf(sess[slot].token, sizeof sess[slot].token, "%s", tok);
    snprintf(sess[slot].user, sizeof sess[slot].user, "%s", user);
    sess[slot].expiry = now + SESSION_TTL;
    pthread_mutex_unlock(&lk);
    snprintf(token_out, 65, "%s", tok);
    return 0;
}

int session_user(const char *token, char *user_out)
{
    if (!token || strlen(token) != 64) return -1;
    time_t now = time(NULL);
    int rc = -1;
    pthread_mutex_lock(&lk);
    for (int i = 0; i < MAXS; i++) {
        if (sess[i].token[0] && CRYPTO_memcmp(sess[i].token, token, 64) == 0) {
            if (sess[i].expiry >= now && find_user(sess[i].user)) {
                sess[i].expiry = now + SESSION_TTL;
                snprintf(user_out, 33, "%s", sess[i].user);
                rc = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&lk);
    return rc;
}

void session_drop(const char *token)
{
    pthread_mutex_lock(&lk);
    for (int i = 0; i < MAXS; i++)
        if (sess[i].token[0] && strcmp(sess[i].token, token) == 0) memset(&sess[i], 0, sizeof sess[i]);
    pthread_mutex_unlock(&lk);
}
