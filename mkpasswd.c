/*
 * Copyright (C) 2001-2008  Marco d'Itri
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* for crypt, snprintf and strcasecmp */
#define _XOPEN_SOURCE 500
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#define __EXTENSIONS__ 1

/* System library */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define MY_ENTROPY_BITS 512
#define SALT_BITS 128

#include "utils.h"
#include "version.h"

/* Global variables */
#ifdef HAVE_GETOPT_LONG
static const struct option longopts[] = {
    {"method",        optional_argument,    NULL, 'm'},
    /* for backward compatibility with versions < 4.7.25 (< 20080321): */
    {"hash",        optional_argument,    NULL, 'H'},
    {"help",        no_argument,        NULL, 'h'},
    {"password-fd",    required_argument,    NULL, 'P'},
    {"stdin",        no_argument,        NULL, 's'},
    {"salt",        required_argument,    NULL, 'S'},
    {"rounds",        required_argument,    NULL, 'R'},
    {"version",        no_argument,        NULL, 'V'},
    {NULL,        0,            NULL, 0  }
};
#else
extern char *optarg;
extern int optind;
#endif

static const char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

struct crypt_method {
    const char *method;        /* short name used by the command line option */
    const char *prefix;        /* salt prefix */
    const unsigned int minlen;    /* minimum salt length */
    const unsigned int maxlen;    /* maximum salt length */
    const unsigned int rounds;    /* supports a variable number of rounds */
    const char *desc;        /* long description for the methods list */
};

static const struct crypt_method methods[] = {
    /* method        prefix    minlen,    maxlen    rounds description */
    { "des",        "",    2,    2,    0,
    N_("standard 56 bit DES-based crypt(3)") },
    { "md5",        "$1$",    8,    8,    0, "MD5" },
#if defined OpenBSD || defined FreeBSD || (defined __SVR4 && defined __sun)
# if (defined OpenBSD && OpenBSD >= 201405)
    /* http://marc.info/?l=openbsd-misc&m=139320023202696 */
    { "bf",        "$2b$", 22,    22,    1, "Blowfish" },
    { "bfa",        "$2a$", 22,    22,    1, "Blowfish (obsolete $2a$ version)" },
# else
    { "bf",        "$2a$", 22,    22,    1, "Blowfish" },
# endif
#endif
#if defined FreeBSD
    { "nt",        "$3$",  0,    0,    0, "NT-Hash" },
#endif
#if defined HAVE_SHA_CRYPT
    /* http://people.redhat.com/drepper/SHA-crypt.txt */
    { "sha-256",    "$5$",    8,    16,    1, "SHA-256" },
    { "sha-512",    "$6$",    8,    16,    1, "SHA-512" },
#endif
    /* http://www.crypticide.com/dropsafe/article/1389 */
    /*
     * Actually the maximum salt length is arbitrary, but Solaris by default
     * always uses 8 characters:
     * http://cvs.opensolaris.org/source/xref/onnv/onnv-gate/ \
     *   usr/src/lib/crypt_modules/sunmd5/sunmd5.c#crypt_gensalt_impl
     */
#if defined __SVR4 && defined __sun
    { "sunmd5",        "$md5$", 8,    8,    1, "SunMD5" },
#endif
    { NULL,        NULL,    0,    0,    0, NULL }
};

void NORETURN display_help(int error);
void display_version(void);
void display_methods(void);

char *read_line(FILE *fp) {
    int size = 128;
    int ch;
    size_t pos = 0;
    char *password;

    password = NOFAIL(malloc(size));

    while ((ch = fgetc(fp)) != EOF) {
    if (ch == '\n' || ch == '\r')
        break;
    password[pos++] = ch;
    if (pos == size) {
        size += 128;
        password = NOFAIL(realloc(password, size));
    }
    }
    password[pos] = '\0';

    if (ferror(fp)) {
    free(password);
    return NULL;
    }
    return password;
}

void NORETURN display_help(int error)
{
    fprintf((EXIT_SUCCESS == error) ? stdout : stderr,
        _("Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]\n"
        "Crypts the PASSWORD using crypt(3).\n\n"));
    fprintf(stderr, _(
"      -m, --method=TYPE     select method TYPE\n"
"      -5                    like --method=md5\n"
"      -S, --salt=SALT       use the specified SALT\n"
"      -R, --rounds=NUMBER   use the specified NUMBER of rounds\n"
"      -P, --password-fd=NUM read the password from file descriptor NUM\n"
"                            instead of /dev/tty\n"
"      -s, --stdin           like --password-fd=0\n"
"      -h, --help            display this help and exit\n"
"      -V, --version         output version information and exit\n"
"\n"
"If PASSWORD is missing then it is asked interactively.\n"
"If no SALT is specified, a random one is generated.\n"
"If TYPE is 'help', available methods are printed.\n"
"\n"
"Report bugs to %s.\n"), "<softman@tfm.ro>");
    exit(error);
}

void display_version(void)
{
    printf("mkpasswd %s\n\n", VERSION);
    puts("Copyright (C) 2018 Liviu Andreicut\n"
"Copyright (C) 2001-2018 Marco d'Itri\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.");
}

void display_methods(void)
{
    unsigned int i;

    printf(_("Available methods:\n"));
    for (i = 0; methods[i].method != NULL; i++)
    printf("%s\t%s\n", methods[i].method, methods[i].desc);
}



int b64_op(const void *in, int in_len, char *out, int out_len, int op) {
    int ret = 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    if (!op) {
        ret = BIO_write(b64, in, in_len);
        BIO_flush(b64);
        if (ret > 0) {
            ret = BIO_read(bio, out, out_len);
        }
    } else {
        ret = BIO_write(bio, in, in_len);
        BIO_flush(bio);
        if (ret) {
            ret = BIO_read(b64, out, out_len);
        }
    }
    BIO_free(b64);
    BIO_free(bio);
    return ret;
}

char *generate_salt(uint8_t salt_bytes, const char *salt_prefix) {
    uint8_t entropy_bytes=MY_ENTROPY_BITS >> 3;
    uint8_t salt_buffer[salt_bytes];

    uint8_t i,salt_len;
    char *gen_salt,*salt;

    printf("Gathering random bytes, this may take a while...\n");
    int rc = RAND_load_file("/dev/random", entropy_bytes);
    if (rc != entropy_bytes) {
        printf("Error collecting random bytes\n");
        return NULL;
    }

    rc = RAND_bytes(salt_buffer, salt_bytes);

    if (rc != 1) {
        printf("Error generating salt bytes\n");
        return NULL;
    }

    gen_salt=(char *)calloc(salt_bytes+1,sizeof(char));
    if (!gen_salt) {
        perror("calloc");
        return NULL;
    }

    rc=b64_op(salt_buffer,salt_bytes,gen_salt,salt_bytes,0);
    for (i=0;i<salt_bytes;i++)
        if ((gen_salt[i]=='+')||(gen_salt[i]=='=')) gen_salt[i]='.';

    salt_len=strlen(salt_prefix)+strlen(gen_salt)+1;
    salt=(char *)calloc(salt_len,1);
    if (!salt) {
        perror("calloc");
        free(gen_salt);
        return NULL;
    }
    snprintf(salt,salt_len,"%s%s",salt_prefix,gen_salt);
    free(gen_salt);
    return salt;
}

int main(int argc, char *argv[])
{
    int ch, i;
    int password_fd = -1;
    unsigned int salt_minlen = 0;
    unsigned int salt_maxlen = 0;
    unsigned int rounds_support = 0;
    const char *salt_prefix = NULL;
    const char *salt_arg = NULL;
    unsigned int rounds = 0;
    char *salt = NULL;
    char rounds_str[30];
    char *password = NULL;

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
    textdomain(NLS_CAT_NAME);
#endif

    /* prepend options from environment */
    argv = merge_args(getenv("MKPASSWD_OPTIONS"), argv, &argc);

    while ((ch = GETOPT_LONGISH(argc, argv, "hH:m:5P:R:sS:V", longopts, NULL)) > 0) {
        switch (ch) {
            case '5':
                optarg = (char *) "md5";
                /* fall through */
            case 'm':
            case 'H':
                if (!optarg || strcaseeq("help", optarg)) {
                    display_methods();
                    exit(0);
                }
                for (i = 0; methods[i].method != NULL; i++)
                    if (strcaseeq(methods[i].method, optarg)) {
                        salt_prefix = methods[i].prefix;
                        salt_minlen = methods[i].minlen;
                        salt_maxlen = methods[i].maxlen;
                        rounds_support = methods[i].rounds;
                        break;
                    }
                if (!salt_prefix) {
                    fprintf(stderr, _("Invalid method '%s'.\n"), optarg);
                    return 1;
                }
                break;
            case 'P':
                {
                    char *p;
                    password_fd = strtol(optarg, &p, 10);
                    if (p == NULL || *p != '\0' || password_fd < 0) {
                        fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
                    return 1;
                    }
                }
                break;
            case 'R':
                {
                    char *p;
                    long r;
                    r = strtol(optarg, &p, 10);
                    if (p == NULL || *p != '\0' || r < 0) {
                        fprintf(stderr, _("Invalid number '%s'.\n"), optarg);
                        return 1;
                    }
                    rounds = r;
                }
                break;
            case 's':
                password_fd = 0;
                break;
            case 'S':
                salt_arg = optarg;
                break;
            case 'V':
                display_version();
                exit(0);
            case 'h':
                display_help(EXIT_SUCCESS);
            default:
                fprintf(stderr, _("Try '%s --help' for more information.\n"), argv[0]);
                return 1;
            }
        }
    argc -= optind;
    argv += optind;

    if (argc == 2 && !salt_arg) {
        password = argv[0];
        salt_arg = argv[1];
    } else if (argc == 1) {
        password = argv[0];
    } else if (argc == 0) {
    } else {
        display_help(EXIT_FAILURE);
    }

    /* default: DES password */
    if (!salt_prefix) {
        salt_minlen = methods[0].minlen;
        salt_maxlen = methods[0].maxlen;
        salt_prefix = methods[0].prefix;
    }

    if (streq(salt_prefix, "$2a$") || streq(salt_prefix, "$2y$")) {
        /* OpenBSD Blowfish and derivatives */
        if (rounds <= 5)
            rounds = 5;
        /* actually for 2a/2y it is the logarithm of the number of rounds */
            snprintf(rounds_str, sizeof(rounds_str), "%02u$", rounds);
        } else if (rounds_support && rounds) snprintf(rounds_str, sizeof(rounds_str), "rounds=%u$", rounds);
    else rounds_str[0] = '\0';

    if (salt_arg) {
        unsigned int c = strlen(salt_arg);
        if (c < salt_minlen || c > salt_maxlen) {
            if (salt_minlen == salt_maxlen) {
                fprintf(stderr, ngettext(
                "Wrong salt length: %d byte when %d expected.\n",
                "Wrong salt length: %d bytes when %d expected.\n", c),
                c, salt_maxlen);
            } else {
                fprintf(stderr, ngettext(
                "Wrong salt length: %d byte when %d <= n <= %d"
                " expected.\n",
                "Wrong salt length: %d bytes when %d <= n <= %d"
                " expected.\n", c),
                c, salt_minlen, salt_maxlen);
            }
        return 1;
        }
        while (c-- > 0) {
            if (strchr(valid_salts, salt_arg[c]) == NULL) {
                fprintf(stderr, _("Illegal salt character '%c'.\n"),
                salt_arg[c]);
            return 1;
            }
        }

        salt = NOFAIL(malloc(strlen(salt_prefix) + strlen(rounds_str) + strlen(salt_arg) + 1));
        *salt = '\0';
        strcat(salt, salt_prefix);
        strcat(salt, rounds_str);
        strcat(salt, salt_arg);
    } else {
        salt=generate_salt(salt_maxlen,salt_prefix);
        if (!salt) {
            fprintf(stderr, _("Unable to generarte salt.\n"));
            return 2;
        }
    }

    if (password) {
    } else if (password_fd != -1) {
        FILE *fp;

        if (isatty(password_fd))
            fprintf(stderr, _("Password: "));
        fp = fdopen(password_fd, "r");
        if (!fp) {
            perror("fdopen");
            return 2;
        }

        password = read_line(fp);
        if (!password) {
            perror("fgetc");
            return 2;
        }
    } else {
        password = getpass(_("Password: "));
        if (!password) {
            perror("getpass");
            return 2;
        }
    }

    const char *result;
    result = crypt(password, salt);
    /* xcrypt returns "*0" on errors */
    if (!result || result[0] == '*') {
        fprintf(stderr, "crypt failed.\n");
        return 2;
    }
    /* yes, using strlen(salt_prefix) on salt. It's not
     * documented whether crypt_gensalt may change the prefix */
    if (!strneq(result, salt, strlen(salt_prefix))) {
        fprintf(stderr, _("Method not supported by crypt(3).\n"));
        return 2;
    }
    printf("%s\n", result);

    return 0;
}

