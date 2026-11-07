#include "hc.h"
#include <unistd.h>
#include <termios.h>
#include <ctype.h>

static int use_color(void)
{
    static int c = -1;
    if (c < 0) c = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
    return c;
}

#define C(code) (use_color() ? code : "")
#define RESET  C("\033[0m")
#define BOLD   C("\033[1m")
#define DIM    C("\033[2m")
#define CYAN   C("\033[38;5;45m")
#define BLUE   C("\033[38;5;33m")
#define GREEN  C("\033[38;5;42m")
#define YELLOW C("\033[38;5;214m")
#define RED    C("\033[38;5;203m")
#define GREY   C("\033[38;5;245m")

void ui_banner(void)
{
    printf("\n");
    printf("%s    ╭─────────╮%s\n", CYAN, RESET);
    printf("%s    │  ☁ ☁ ☁  │%s   %s%sHome Cloud%s  %sserver %s%s\n", CYAN, RESET, BOLD, BLUE, RESET, GREY, HC_VERSION, RESET);
    printf("%s    ╰─────────╯%s   %sÉdition Termux : sans root, sans chiffrement de disque%s\n\n", CYAN, RESET, GREY, RESET);
}

void ui_title(const char *t)
{
    printf("\n%s%s▍ %s%s\n", BOLD, BLUE, t, RESET);
    printf("%s  ", GREY);
    for (size_t i = 0; i < 56; i++) printf("─");
    printf("%s\n", RESET);
}

static void line(const char *icon, const char *color, const char *fmt, va_list ap)
{
    printf("  %s%s%s ", color, icon, RESET);
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
}

void ui_ok(const char *fmt, ...)   { va_list ap; va_start(ap, fmt); line("✔", GREEN, fmt, ap); va_end(ap); }
void ui_info(const char *fmt, ...) { va_list ap; va_start(ap, fmt); line("●", CYAN, fmt, ap); va_end(ap); }
void ui_warn(const char *fmt, ...) { va_list ap; va_start(ap, fmt); line("▲", YELLOW, fmt, ap); va_end(ap); }
void ui_err(const char *fmt, ...)  { va_list ap; va_start(ap, fmt); line("✘", RED, fmt, ap); va_end(ap); }

void ui_kv(const char *k, const char *v)
{
    printf("  %s%-22s%s %s%s%s\n", GREY, k, RESET, BOLD, v, RESET);
}

static void read_line(char *out, size_t sz)
{
    if (!fgets(out, (int)sz, stdin)) { out[0] = 0; return; }
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = 0;
}

void ui_ask(const char *label, const char *def, char *out, size_t sz)
{
    if (def && *def) printf("  %s?%s %s %s(%s)%s : ", CYAN, RESET, label, GREY, def, RESET);
    else             printf("  %s?%s %s : ", CYAN, RESET, label);
    fflush(stdout);
    read_line(out, sz);
    if (!*out && def) snprintf(out, sz, "%s", def);
}

int ui_ask_secret(const char *label, char *out, size_t sz)
{
    struct termios old, nw;
    int tty = isatty(STDIN_FILENO);
    printf("  %s?%s %s : ", CYAN, RESET, label);
    fflush(stdout);
    if (tty) {
        tcgetattr(STDIN_FILENO, &old);
        nw = old;
        nw.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &nw);
    }
    read_line(out, sz);
    if (tty) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); printf("\n"); }
    return (int)strlen(out);
}

int ui_confirm(const char *label, int def)
{
    char buf[16];
    printf("  %s?%s %s %s[%s]%s : ", CYAN, RESET, label, GREY, def ? "O/n" : "o/N", RESET);
    fflush(stdout);
    read_line(buf, sizeof buf);
    if (!*buf) return def;
    return tolower((unsigned char)buf[0]) == 'o' || tolower((unsigned char)buf[0]) == 'y';
}

int ui_choose(const char *title, const char **opts, const char **desc, int n, int def)
{
    printf("  %s%s%s\n\n", BOLD, title, RESET);
    for (int i = 0; i < n; i++) {
        printf("    %s%s[%d]%s %s%s%s", BOLD, CYAN, i + 1, RESET, BOLD, opts[i], RESET);
        if (i + 1 == def) printf(" %s(défaut)%s", GREY, RESET);
        printf("\n        %s%s%s\n", GREY, desc[i], RESET);
    }
    printf("\n");
    for (;;) {
        char buf[16], d[8];
        snprintf(d, sizeof d, "%d", def);
        ui_ask("Votre choix", d, buf, sizeof buf);
        int v = atoi(buf);
        if (v >= 1 && v <= n) return v;
        ui_err("Choix invalide.");
    }
}
