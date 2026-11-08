/* Home Cloud server (édition lite / Termux) : installeur + démon, sans root. */
#include "hc.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>

static void on_signal(int sig) { (void)sig; http_stop(); }

/* ---------------- fichiers de service ---------------- */
static void pid_path(char *o, size_t n) { snprintf(o, n, "%s/homecloud.pid", g_home); }
static void log_path(char *o, size_t n) { snprintf(o, n, "%s/homecloud.log", g_home); }

/* pid du démon s'il tourne, sinon 0 */
static pid_t running_pid(void)
{
    char p[640];
    pid_path(p, sizeof p);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    int pid = 0;
    if (fscanf(f, "%d", &pid) != 1) pid = 0;
    fclose(f);
    if (pid <= 0 || kill(pid, 0) != 0) return 0;
    char cl[64], buf[256] = "";                      /* évite un pid recyclé par un autre programme */
    snprintf(cl, sizeof cl, "/proc/%d/cmdline", pid);
    FILE *c = fopen(cl, "r");
    if (c) {
        size_t n = fread(buf, 1, sizeof buf - 1, c);
        buf[n] = 0;
        fclose(c);
        if (n && !strstr(buf, "homecloud")) return 0;
    }
    return pid;
}

static int load_or_die(int need_store)
{
    if (config_load() < 0) {
        fprintf(stderr, "Home Cloud n'est pas installé. Lancez : homecloud-server install\n");
        return -1;
    }
    if (need_store && store_init() < 0) {
        fprintf(stderr, "dossier de données inaccessible : %s\n", g_cfg.data_dir);
        return -1;
    }
    return 0;
}

/* ---------------- adresses ---------------- */
static int print_addresses(int port)
{
    int shown = 0;
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) == 0) {
        for (p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET || (p->ifa_flags & IFF_LOOPBACK)) continue;
            char ip[INET_ADDRSTRLEN], line[128];
            inet_ntop(AF_INET, &((struct sockaddr_in *)p->ifa_addr)->sin_addr, ip, sizeof ip);
            snprintf(line, sizeof line, "%s:%d", ip, port);
            ui_kv(p->ifa_name, line);
            shown++;
        }
        freeifaddrs(ifa);
    }
    if (shown) return shown;

    /* Android récent : getifaddrs() est bridé pour les applis. On demande au noyau quelle
     * adresse il utiliserait pour sortir (aucun paquet n'est envoyé). */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(53) }, me;
        socklen_t ml = sizeof me;
        inet_pton(AF_INET, "192.0.2.1", &to.sin_addr);
        if (connect(s, (struct sockaddr *)&to, sizeof to) == 0 && getsockname(s, (struct sockaddr *)&me, &ml) == 0) {
            char ip[INET_ADDRSTRLEN], line[128];
            inet_ntop(AF_INET, &me.sin_addr, ip, sizeof ip);
            snprintf(line, sizeof line, "%s:%d", ip, port);
            ui_kv("réseau", line);
            shown++;
        }
        close(s);
    }
    if (!shown) ui_warn("Adresse IP introuvable : essayez « ifconfig » ou « termux-wifi-connectioninfo ».");
    return shown;
}

/* ---------------- saisie ---------------- */
static int ask_number(const char *label, int def, int min, int max)
{
    for (;;) {
        char d[16], buf[32];
        snprintf(d, sizeof d, "%d", def);
        ui_ask(label, d, buf, sizeof buf);
        int v = atoi(buf);
        if (v >= min && v <= max) return v;
        ui_err("Valeur attendue entre %d et %d.", min, max);
    }
}

static void ask_admin_credentials(char *user, size_t usz, char *pass, size_t psz)
{
    for (;;) {
        ui_ask("Nom d'utilisateur administrateur", "admin", user, usz);
        if (valid_username(user)) break;
        ui_err("Nom invalide (2-32 caractères : lettres, chiffres, . _ -).");
    }
    for (;;) {
        char again[128];
        ui_ask_secret("Mot de passe administrateur (8 car. min.)", pass, psz);
        if (strlen(pass) < 8) { ui_err("Mot de passe trop court."); continue; }
        ui_ask_secret("Confirmez le mot de passe", again, sizeof again);
        if (strcmp(pass, again)) { ui_err("Les mots de passe ne correspondent pas."); continue; }
        break;
    }
}

/* « ~/x » -> « $HOME/x » */
static void expand_home(const char *in, char *out, size_t sz)
{
    const char *h = getenv("HOME");
    if (in[0] == '~' && (in[1] == '/' || !in[1]) && h) snprintf(out, sz, "%s%s", h, in + 1);
    else snprintf(out, sz, "%s", in);
}

/* script Termux:Boot : démarrage automatique au lancement du téléphone */
static int install_boot_script(void)
{
    const char *h = getenv("HOME");
    const char *prefix = getenv("PREFIX");
    char dir[640], file[700];
    if (!h) return -1;
    snprintf(dir, sizeof dir, "%s/.termux/boot", h);
    if (mkdir_p(dir, 0700) < 0) return -1;
    snprintf(file, sizeof file, "%s/homecloud-server", dir);
    FILE *f = fopen(file, "w");
    if (!f) return -1;
    fprintf(f, "#!%s/bin/sh\ntermux-wake-lock\nhomecloud-server start\n",
            prefix && *prefix ? prefix : "/data/data/com.termux/files/usr");
    fclose(f);
    chmod(file, 0700);
    return 0;
}

/* ---------------- démon ---------------- */
static void run_daemon_core(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    logmsg("Home Cloud %s - serveur « %s »", HC_VERSION, g_cfg.server_name);
    store_check_disks();
    discovery_start(g_cfg.port);
    http_serve(g_cfg.port);
    logmsg("arrêt du serveur");
}

static void cmd_run(void)
{
    if (load_or_die(1) < 0) exit(1);
    pid_t other = running_pid();
    if (other && other != getpid()) {
        fprintf(stderr, "Home Cloud tourne déjà (pid %d). Arrêtez-le avec : homecloud-server stop\n", (int)other);
        exit(1);
    }
    run_daemon_core();
}

static int cmd_start(int quiet)
{
    if (load_or_die(1) < 0) return -1;
    pid_t pid = running_pid();
    if (pid) {
        if (!quiet) ui_warn("Home Cloud tourne déjà (pid %d).", (int)pid);
        return 0;
    }
    char lp[640], pp[640];
    log_path(lp, sizeof lp);
    pid_path(pp, sizeof pp);

    if (command_exists("termux-wake-lock")) {          /* empêche Android d'endormir le CPU */
        char *wl[] = { "termux-wake-lock", NULL };
        run_cmd(wl);
    }

    fflush(NULL);
    pid = fork();
    if (pid < 0) { ui_err("fork impossible : %s", strerror(errno)); return -1; }
    if (pid == 0) {
        setsid();
        int dn = open("/dev/null", O_RDONLY);
        int lg = open(lp, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (dn >= 0) dup2(dn, 0);
        if (lg >= 0) { dup2(lg, 1); dup2(lg, 2); }
        FILE *f = fopen(pp, "w");
        if (f) { fprintf(f, "%d\n", (int)getpid()); fclose(f); }
        run_daemon_core();
        unlink(pp);
        _exit(0);
    }
    usleep(800000);                                    /* le démon s'est-il bien lancé ? (bind du port, etc.) */
    int st;
    if (waitpid(pid, &st, WNOHANG) == pid) {
        ui_err("Le serveur s'est arrêté au démarrage. Consultez le journal : tail %s", lp);
        return -1;
    }
    if (!quiet) {
        ui_ok("Home Cloud démarré en arrière-plan (pid %d)", (int)pid);
        ui_info("Journal : %s", lp);
    }
    return 0;
}

static int cmd_stop(void)
{
    pid_t pid = running_pid();
    if (!pid) { ui_warn("Home Cloud n'est pas démarré."); return 0; }
    kill(pid, SIGTERM);
    for (int i = 0; i < 50 && kill(pid, 0) == 0; i++) usleep(100000);
    if (kill(pid, 0) == 0) { kill(pid, SIGKILL); usleep(200000); }
    char pp[640];
    pid_path(pp, sizeof pp);
    unlink(pp);
    if (command_exists("termux-wake-unlock")) {
        char *wu[] = { "termux-wake-unlock", NULL };
        run_cmd(wu);
    }
    ui_ok("Home Cloud arrêté.");
    return 0;
}

static void cmd_install(void)
{
    ui_banner();
    ui_title("Installation");
    ui_info("Dossier de travail : %s", g_home);

    char conf[640];
    snprintf(conf, sizeof conf, "%s/homecloud.conf", g_home);
    if (access(conf, F_OK) == 0) {
        ui_warn("Une configuration existe déjà (%s).", conf);
        if (!ui_confirm("Écraser la configuration et continuer ?", 0)) exit(0);
        if (running_pid()) cmd_stop();
    }

    ui_title("Mode de configuration");
    const char *opts[] = { "Automatique (rapide)", "Manuelle" };
    char defdir[520];
    snprintf(defdir, sizeof defdir, "%.500s/data", g_home);
    char d0[700];
    snprintf(d0, sizeof d0, "Données dans %s, port 8650, compte « admin » avec mot de passe généré.", defdir);
    const char *desc[] = {
        d0,
        "Vous choisissez le dossier de stockage, le port, le compte administrateur, etc."
    };
    int mode = ui_choose("Comment souhaitez-vous configurer Home Cloud ?", opts, desc, 2, 1);

    config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    char admin[64] = "admin", pass[128] = "";
    int admin_quota = HC_MIN_QUOTA_GB, generated = 0, boot = 0;
    char host[64] = "HomeCloud";
    gethostname(host, sizeof host - 1);
    if (!strcmp(host, "localhost")) snprintf(host, sizeof host, "HomeCloud");

    if (mode == 1) {
        snprintf(cfg.server_name, sizeof cfg.server_name, "%s", host);
        snprintf(cfg.data_dir, sizeof cfg.data_dir, "%.500s", defdir);
        cfg.port = HC_DEFAULT_PORT;
        cfg.default_quota_gb = HC_MIN_QUOTA_GB;
        random_hex(pass, 8);
        generated = 1;
    } else {
        ui_title("Stockage");
        ui_info("Astuce : après « termux-setup-storage », ~/storage/shared pointe vers la mémoire du téléphone.");
        for (;;) {
            char raw[512];
            ui_ask("Dossier où stocker les fichiers des disques", defdir, raw, sizeof raw);
            expand_home(raw, cfg.data_dir, sizeof cfg.data_dir);
            if (cfg.data_dir[0] == '/') break;
            ui_err("Le chemin doit être absolu (ou commencer par ~/).");
        }
        if (!strncmp(cfg.data_dir, "/sdcard", 7) || !strncmp(cfg.data_dir, "/storage", 8) || strstr(cfg.data_dir, "/storage/shared"))
            ui_warn("Stockage partagé : lisible par les autres applis ayant accès aux fichiers. Les mots de passe restent, eux, dans %s.", g_home);
        ui_title("Réseau");
        ui_ask("Nom du serveur (affiché sur le réseau)", host, cfg.server_name, sizeof cfg.server_name);
        cfg.port = ask_number("Port TCP", HC_DEFAULT_PORT, 1024, 65535);
        ui_title("Compte administrateur");
        ask_admin_credentials(admin, sizeof admin, pass, sizeof pass);
        ui_title("Espaces (quotas logiciels)");
        admin_quota = ask_number("Quota de l'espace personnel de l'administrateur (Go)", HC_MIN_QUOTA_GB, HC_MIN_QUOTA_GB, 100000);
        cfg.default_quota_gb = ask_number("Quota par défaut d'un nouvel utilisateur (Go, min. 5)", HC_MIN_QUOTA_GB, HC_MIN_QUOTA_GB, 100000);
        if (getenv("HOME"))
            boot = ui_confirm("Démarrer automatiquement avec le téléphone (nécessite l'appli Termux:Boot) ?", 0);
    }

    ui_title("Récapitulatif");
    char tmp[64];
    ui_kv("Nom du serveur", cfg.server_name);
    ui_kv("Données", cfg.data_dir);
    snprintf(tmp, sizeof tmp, "%d (TCP) / %d (UDP découverte)", cfg.port, HC_DISCOVERY_PORT);
    ui_kv("Ports", tmp);
    ui_kv("Administrateur", admin);
    snprintf(tmp, sizeof tmp, "%d Go", cfg.default_quota_gb);
    ui_kv("Quota par défaut", tmp);
    ui_kv("Chiffrement", "aucun (dossiers simples, quotas logiciels)");
    printf("\n");
    if (!ui_confirm("Lancer l'installation ?", 1)) { ui_warn("Installation annulée."); exit(0); }

    ui_title("Installation en cours");
    g_cfg = cfg;
    if (config_save(&cfg) < 0) { ui_err("Écriture de la configuration impossible (%s).", strerror(errno)); exit(1); }
    ui_ok("Configuration enregistrée");
    if (store_init() < 0) { ui_err("Impossible de créer %s (%s).", cfg.data_dir, strerror(errno)); exit(1); }
    ui_ok("Dossier de données prêt");

    char err[400] = "";
    if (user_create(admin, pass, 1, (unsigned)admin_quota, err, sizeof err) < 0) {
        if (strstr(err, "existant")) ui_warn("Le compte « %s » existe déjà : conservé tel quel.", admin), generated = 0;
        else { ui_err("Échec : %s", err); exit(1); }
    } else ui_ok("Administrateur « %s » créé avec un espace personnel de %d Go", admin, admin_quota);

    if (boot) {
        if (install_boot_script() == 0) ui_ok("Script Termux:Boot installé (~/.termux/boot/homecloud-server)");
        else ui_warn("Impossible d'écrire le script Termux:Boot.");
    }

    ui_title("Terminé");
    ui_kv("Identifiant", admin);
    if (generated) {
        ui_kv("Mot de passe (à noter !)", pass);
        ui_warn("Ce mot de passe n'est affiché qu'une fois. Changez-le avec : homecloud-server passwd %s", admin);
    }
    printf("\n");
    if (ui_confirm("Démarrer le serveur maintenant ?", 1)) {
        if (cmd_start(0) == 0) {
            printf("\n  Adresses du serveur :\n");
            print_addresses(cfg.port);
        }
    } else ui_info("Démarrage manuel : homecloud-server start");
    printf("\n");
    ui_info("Ouvrez l'application Home Cloud sur un PC du même Wi-Fi : le serveur sera détecté automatiquement.");
    ui_info("Android : désactivez l'optimisation de batterie pour Termux, sinon le serveur peut être coupé.");
    printf("\n");
}

static void cmd_passwd(const char *user)
{
    if (load_or_die(1) < 0) exit(1);
    user_t u;
    if (user_get(user, &u) < 0) { ui_err("Utilisateur « %s » introuvable.", user); exit(1); }
    char p1[128], p2[128];
    ui_ask_secret("Nouveau mot de passe (8 car. min.)", p1, sizeof p1);
    ui_ask_secret("Confirmation", p2, sizeof p2);
    if (strlen(p1) < 8 || strcmp(p1, p2)) { ui_err("Mot de passe trop court ou différent."); exit(1); }
    if (user_set_password(user, p1) == 0) {
        ui_ok("Mot de passe de « %s » modifié.", user);
        if (running_pid()) ui_info("Redémarrez le serveur pour appliquer : homecloud-server restart");
    } else { ui_err("Échec."); exit(1); }
}

static void cmd_status(void)
{
    if (load_or_die(1) < 0) exit(1);
    static user_t us[256];
    static disk_t ds[512];
    int nu = user_list(us, 256), nd = disk_list(ds, 512);
    char b[96];
    pid_t pid = running_pid();
    ui_title("État de Home Cloud");
    if (pid) snprintf(b, sizeof b, "en marche (pid %d)", (int)pid); else snprintf(b, sizeof b, "arrêté");
    ui_kv("Service", b);
    ui_kv("Serveur", g_cfg.server_name);
    ui_kv("Données", g_cfg.data_dir);
    ui_kv("Dossier privé", g_home);
    snprintf(b, sizeof b, "%d", g_cfg.port); ui_kv("Port", b);
    snprintf(b, sizeof b, "%d", nu); ui_kv("Utilisateurs", b);
    snprintf(b, sizeof b, "%d", nd); ui_kv("Disques", b);
    printf("\n");
    for (int i = 0; i < nd; i++) {
        unsigned long long t = 0, u = 0;
        disk_usage(ds[i].id, &t, &u);
        if (ds[i].src[0]) snprintf(b, sizeof b, "lecture seule (monté) : %llu Mo utilisés / %llu Mo", u >> 20, t >> 20);
        else snprintf(b, sizeof b, "%llu Mo utilisés / quota %llu Mo", u >> 20, t >> 20);
        ui_kv(ds[i].name, b);
    }
    printf("\n");
    if (pid) { printf("  Adresses du serveur :\n"); print_addresses(g_cfg.port); printf("\n"); }
}

/* ---------------- montages en lecture seule ---------------- */
/* Le démon garde l'état en mémoire : on l'arrête pendant la modification, puis on le relance. */
static void cmd_mount(const char *raw, const char *name)
{
    char path[640], err[400] = "", id[17];
    int was = running_pid() != 0, rc;
    if (was) cmd_stop();
    if (load_or_die(1) < 0) exit(1);
    expand_home(raw, path, sizeof path);
    rc = disk_mount(name, path, id, err, sizeof err);
    if (rc < 0) ui_err("Montage impossible : %s", err);
    else {
        disk_t d;
        disk_get(id, &d);
        ui_ok("« %s » monté en lecture seule, visible par tous les utilisateurs.", d.name);
        ui_kv("Dossier source", d.src);
        ui_kv("Identifiant", d.id);
        ui_info("Aucun fichier ne peut y être ajouté, modifié ou supprimé via Home Cloud.");
    }
    if (was) cmd_start(0);
    else if (rc == 0) ui_info("Le montage sera actif au prochain démarrage : homecloud-server start");
    if (rc < 0) exit(1);
}

static int find_mount(const char *key, disk_t *out)
{
    static disk_t ds[512];
    int n = disk_list(ds, 512);
    for (int i = 0; i < n; i++)
        if (ds[i].src[0] && (!strcmp(ds[i].id, key) || !strcmp(ds[i].name, key))) { *out = ds[i]; return 0; }
    return -1;
}

static void cmd_umount(const char *key)
{
    char err[200] = "";
    disk_t d;
    int was = running_pid() != 0, rc = -1;
    if (was) cmd_stop();
    if (load_or_die(1) < 0) exit(1);
    if (find_mount(key, &d) < 0) ui_err("Aucun montage nommé « %s » (voir : homecloud-server mounts).", key);
    else if ((rc = disk_delete(d.id, err, sizeof err)) < 0) ui_err("Démontage impossible : %s", err);
    else {
        ui_ok("« %s » démonté.", d.name);
        ui_info("Le dossier source n'a pas été touché : %s", d.src);
    }
    if (was) cmd_start(0);
    if (rc < 0) exit(1);
}

static void cmd_mounts(void)
{
    if (load_or_die(1) < 0) exit(1);
    static disk_t ds[512];
    int n = disk_list(ds, 512), shown = 0;
    ui_title("Dossiers montés (lecture seule, pour tous)");
    for (int i = 0; i < n; i++) {
        if (!ds[i].src[0]) continue;
        char line[700];
        snprintf(line, sizeof line, "%.500s  [%.16s]", ds[i].src, ds[i].id);
        ui_kv(ds[i].name, line);
        shown++;
    }
    if (!shown) ui_info("Aucun. Exemple : homecloud-server mount ~/storage/shared/Photos Photos");
    printf("\n");
}

static void usage(void)
{
    ui_banner();
    printf("  Usage : homecloud-server <commande>\n\n");
    ui_kv("install", "assistant d'installation interactif");
    ui_kv("start", "démarre le serveur en arrière-plan");
    ui_kv("stop", "arrête le serveur");
    ui_kv("restart", "redémarre le serveur");
    ui_kv("run", "démarre au premier plan (journal à l'écran, Ctrl+C pour quitter)");
    ui_kv("status", "état du service, adresses, disques et occupation");
    ui_kv("passwd <utilisateur>", "réinitialise un mot de passe");
    ui_kv("mount <dossier> [nom]", "monte un dossier local en disque LECTURE SEULE pour tous");
    ui_kv("umount <nom|id>", "retire un montage (le dossier source n'est pas touché)");
    ui_kv("mounts", "liste les dossiers montés");
    ui_kv("version", "affiche la version");
    printf("\n");
}

int main(int argc, char **argv)
{
    hc_paths_init();
    if (argc < 2) { usage(); return 0; }
    if      (!strcmp(argv[1], "install")) cmd_install();
    else if (!strcmp(argv[1], "run"))     cmd_run();
    else if (!strcmp(argv[1], "start"))   return cmd_start(0) == 0 ? 0 : 1;
    else if (!strcmp(argv[1], "stop"))    return cmd_stop();
    else if (!strcmp(argv[1], "restart")) { cmd_stop(); return cmd_start(0) == 0 ? 0 : 1; }
    else if (!strcmp(argv[1], "status"))  cmd_status();
    else if (!strcmp(argv[1], "passwd") && argc == 3) cmd_passwd(argv[2]);
    else if (!strcmp(argv[1], "mount") && (argc == 3 || argc == 4)) cmd_mount(argv[2], argc == 4 ? argv[3] : NULL);
    else if (!strcmp(argv[1], "umount") && argc == 3) cmd_umount(argv[2]);
    else if (!strcmp(argv[1], "mounts"))  cmd_mounts();
    else if (!strcmp(argv[1], "version")) printf("homecloud-server %s\n", HC_VERSION);
    else { usage(); return 1; }
    return 0;
}
