// Safe PwnKit checker (non-exploit, read-only)
// Build: gcc -O2 -Wall -Wextra -o PwnKit_Check PwnKit_Check.c

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum distro_kind {
    DISTRO_UNKNOWN = 0,
    DISTRO_ARCH,
    DISTRO_DEBIAN,
    DISTRO_UBUNTU
};

struct os_info {
    enum distro_kind kind;
    char id[64];
    char id_like[128];
    char pretty_name[128];
};

static bool command_exists(const char *cmd)
{
    char probe[256];
    snprintf(probe, sizeof(probe), "command -v %s >/dev/null 2>&1", cmd);
    return system(probe) == 0;
}

static void trim_newline(char *s)
{
    char *p;
    if (!s) {
        return;
    }
    p = strchr(s, '\n');
    if (p) {
        *p = '\0';
    }
}

static void copy_bounded(char *dst, size_t dst_size, const char *src)
{
    size_t n;

    if (!dst || dst_size == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }

    n = strlen(src);
    if (n > dst_size - 1) {
        n = dst_size - 1;
    }

    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void unquote_value(char *s)
{
    size_t len;
    if (!s) {
        return;
    }
    len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static struct os_info detect_os(void)
{
    struct os_info info;
    FILE *fp;
    char line[512];

    memset(&info, 0, sizeof(info));
    info.kind = DISTRO_UNKNOWN;
    copy_bounded(info.pretty_name, sizeof(info.pretty_name), "unknown");

    fp = fopen("/etc/os-release", "r");
    if (!fp) {
        return info;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_newline(line);
        if (strncmp(line, "ID=", 3) == 0) {
            copy_bounded(info.id, sizeof(info.id), line + 3);
            unquote_value(info.id);
        } else if (strncmp(line, "ID_LIKE=", 8) == 0) {
            copy_bounded(info.id_like, sizeof(info.id_like), line + 8);
            unquote_value(info.id_like);
        } else if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
            copy_bounded(info.pretty_name, sizeof(info.pretty_name), line + 12);
            unquote_value(info.pretty_name);
        }
    }
    fclose(fp);

    if (strcmp(info.id, "ubuntu") == 0) {
        info.kind = DISTRO_UBUNTU;
    } else if (strcmp(info.id, "debian") == 0) {
        info.kind = DISTRO_DEBIAN;
    } else if (strcmp(info.id, "arch") == 0 || strcmp(info.id, "blackarch") == 0) {
        info.kind = DISTRO_ARCH;
    } else if (strstr(info.id_like, "ubuntu") != NULL) {
        info.kind = DISTRO_UBUNTU;
    } else if (strstr(info.id_like, "debian") != NULL) {
        info.kind = DISTRO_DEBIAN;
    } else if (strstr(info.id_like, "arch") != NULL) {
        info.kind = DISTRO_ARCH;
    }

    return info;
}

static void print_os_summary(const struct os_info *os)
{
    const char *family = "unknown";

    if (os->kind == DISTRO_ARCH) {
        family = "arch";
    } else if (os->kind == DISTRO_DEBIAN) {
        family = "debian";
    } else if (os->kind == DISTRO_UBUNTU) {
        family = "ubuntu";
    }

    printf("\n[os detection]\n");
    printf("  pretty name: %s\n", os->pretty_name[0] ? os->pretty_name : "unknown");
    printf("  id: %s\n", os->id[0] ? os->id : "unknown");
    printf("  id_like: %s\n", os->id_like[0] ? os->id_like : "unknown");
    printf("  detected family: %s\n", family);
}

static void print_cmd_output(const char *title, const char *cmd)
{
    char line[1024];
    FILE *fp;

    printf("\n[%s]\n", title);
    fp = popen(cmd, "r");
    if (!fp) {
        printf("  failed to run command (%s)\n", strerror(errno));
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs("  ", stdout);
        fputs(line, stdout);
    }

    pclose(fp);
}

static void check_pkexec_suid(void)
{
    struct stat st;
    const char *path = "/usr/bin/pkexec";

    printf("\n[pkexec binary]\n");
    if (stat(path, &st) != 0) {
        printf("  %s not found (%s)\n", path, strerror(errno));
        return;
    }

    printf("  path: %s\n", path);
    printf("  owner uid: %u gid: %u\n", (unsigned int)st.st_uid, (unsigned int)st.st_gid);
    printf("  mode: %04o\n", st.st_mode & 07777);

    if ((st.st_mode & S_ISUID) && st.st_uid == 0) {
        printf("  status: setuid-root is enabled (this is normal for pkexec)\n");
    } else {
        printf("  status: unexpected permissions (hardened/non-standard install)\n");
    }

    if (st.st_mode & 01000) {
        printf("  note: sticky bit is set\n");
    } else {
        printf("  note: sticky bit is not set\n");
    }
}

static void check_arch_fixed_version(void)
{
    char installed[128] = {0};
    char cmd[512];
    FILE *fp;

    printf("\n[arch fixed-version check]\n");
    if (!command_exists("pacman")) {
        printf("  pacman not found, skipping Arch-specific check\n");
        return;
    }

    fp = popen("pacman -Q polkit 2>/dev/null", "r");
    if (!fp || !fgets(installed, sizeof(installed), fp)) {
        if (fp) {
            pclose(fp);
        }
        printf("  could not query installed polkit package\n");
        return;
    }
    pclose(fp);

    char *space = strchr(installed, ' ');
    if (!space) {
        printf("  unexpected pacman output: %s", installed);
        return;
    }

    char *version = space + 1;
    char *nl = strchr(version, '\n');
    if (nl) {
        *nl = '\0';
    }

    printf("  installed polkit: %s\n", version);
    printf("  arch security tracker fixed version: 0.120-3\n");

    if (!command_exists("vercmp")) {
        printf("  vercmp not found, cannot compare versions automatically\n");
        return;
    }

    snprintf(cmd, sizeof(cmd), "vercmp '%s' '0.120-3'", version);
    fp = popen(cmd, "r");
    if (!fp) {
        printf("  failed to run vercmp\n");
        return;
    }

    char cmp[16] = {0};
    if (!fgets(cmp, sizeof(cmp), fp)) {
        pclose(fp);
        printf("  failed to read vercmp output\n");
        return;
    }
    pclose(fp);

    if (atoi(cmp) >= 0) {
        printf("  result: patched for CVE-2021-4034 based on package version\n");
    } else {
        printf("  result: potentially vulnerable (installed version older than 0.120-3)\n");
    }
}

static bool find_deb_polkit_package(char *pkg, size_t pkg_size)
{
    FILE *fp;
    char line[256];

    if (!command_exists("dpkg-query")) {
        return false;
    }

    fp = popen("dpkg-query -W -f='${Package}\\n' 2>/dev/null", "r");
    if (!fp) {
        return false;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_newline(line);
        if (strcmp(line, "policykit-1") == 0 || strcmp(line, "polkitd") == 0 || strcmp(line, "polkit") == 0) {
            copy_bounded(pkg, pkg_size, line);
            pclose(fp);
            return true;
        }
    }

    pclose(fp);
    return false;
}

static void check_debian_ubuntu_fixed_status(void)
{
    char pkg[64] = {0};
    char cmd[512];
    char version[256] = {0};
    FILE *fp;
    bool found_cve = false;
    const char *docs[] = {
        "/usr/share/doc/policykit-1/changelog.Debian.gz",
        "/usr/share/doc/polkitd/changelog.Debian.gz",
        "/usr/share/doc/polkit/changelog.Debian.gz"
    };
    size_t i;

    printf("\n[debian/ubuntu fixed-version check]\n");
    if (!find_deb_polkit_package(pkg, sizeof(pkg))) {
        printf("  could not find installed polkit package via dpkg-query\n");
        return;
    }

    snprintf(cmd, sizeof(cmd), "dpkg-query -W -f='${Version}' %s 2>/dev/null", pkg);
    fp = popen(cmd, "r");
    if (!fp || !fgets(version, sizeof(version), fp)) {
        if (fp) {
            pclose(fp);
        }
        printf("  failed to query version for package: %s\n", pkg);
        return;
    }
    pclose(fp);
    trim_newline(version);

    printf("  package: %s\n", pkg);
    printf("  installed version: %s\n", version);
    printf("  note: Debian/Ubuntu often backport the fix; CVE metadata is more reliable than upstream version-only checks.\n");

    for (i = 0; i < sizeof(docs) / sizeof(docs[0]); i++) {
        if (access(docs[i], R_OK) == 0) {
            snprintf(
                cmd,
                sizeof(cmd),
                "zgrep -n -i 'CVE-2021-4034|pwnkit|pkexec' '%s' | head -n 8",
                docs[i]
            );
            printf("  checking changelog: %s\n", docs[i]);
            fp = popen(cmd, "r");
            if (!fp) {
                continue;
            }

            char line[1024];
            while (fgets(line, sizeof(line), fp) != NULL) {
                found_cve = true;
                fputs("    ", stdout);
                fputs(line, stdout);
            }
            pclose(fp);
        }
    }

    if (found_cve) {
        printf("  result: changelog contains CVE-2021-4034/PwnKit references (likely patched package lineage).\n");
    } else {
        printf("  result: no local changelog CVE match found; verify with distro tracker command below.\n");
    }
}

static void check_basic_iocs(void)
{
    print_cmd_output(
        "ioc scan: suspicious UID 0 accounts",
        "awk -F: '$3==0 && $1!=\"root\" {print $1\":\"$3\":\"$7}' /etc/passwd"
    );

    print_cmd_output(
        "ioc scan: leftover pwnkit staging dirs in current tree",
        "find . -maxdepth 4 -type d \\( -name '.pkexec' -o -name 'GCONV_PATH=.' \\) 2>/dev/null"
    );
}

static void print_authoritative_command(const struct os_info *os)
{
    printf("\n[authoritative metadata command]\n");
    if (os->kind == DISTRO_ARCH) {
        printf("  curl -fsSL https://security.archlinux.org/CVE-2021-4034 | rg -n -i 'Package|Fixed|Status|polkit|0\\.120-3'\n");
    } else if (os->kind == DISTRO_UBUNTU) {
        printf("  curl -fsSL https://ubuntu.com/security/CVE-2021-4034 | rg -n -i 'Released|Not affected|policykit-1|Priority|Ubuntu'\n");
    } else if (os->kind == DISTRO_DEBIAN) {
        printf("  curl -fsSL https://security-tracker.debian.org/tracker/CVE-2021-4034 | rg -n -i 'policykit-1|fixed|vulnerable|bookworm|bullseye|trixie'\n");
    } else {
        printf("  curl -fsSL https://nvd.nist.gov/vuln/detail/CVE-2021-4034\n");
    }
}

int main(void)
{
    struct os_info os;

    printf("PwnKit (CVE-2021-4034) Safe Checker\n");
    printf("This tool performs read-only checks and does not attempt exploitation.\n");

    os = detect_os();
    print_os_summary(&os);

    print_cmd_output("pkexec version", "pkexec --version 2>&1");
    check_pkexec_suid();
    if (os.kind == DISTRO_ARCH) {
        check_arch_fixed_version();
    } else if (os.kind == DISTRO_DEBIAN || os.kind == DISTRO_UBUNTU) {
        check_debian_ubuntu_fixed_status();
    } else {
        printf("\n[fixed-version check]\n");
        printf("  unsupported distro family for automated package-version check\n");
    }
    check_basic_iocs();
    print_authoritative_command(&os);

    printf("\nDone.\n");
    return 0;
}
