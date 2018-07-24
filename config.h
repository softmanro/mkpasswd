/* Configurable features */

/* autoconf in cpp macros */
#if defined __NetBSD__ || __OpenBSD__
# include <sys/param.h>
#endif

#ifdef linux
# define ENABLE_NLS
#endif

#ifdef __FreeBSD__
/* which versions? */
# define HAVE_GETOPT_LONG
# define HAVE_GETADDRINFO
# define ENABLE_NLS
# ifndef LOCALEDIR
#  define LOCALEDIR "/usr/local/share/locale"
# endif
#endif

#if defined __APPLE__ && defined __MACH__
# define HAVE_GETOPT_LONG
#endif

#ifdef __GLIBC__
# define HAVE_GETOPT_LONG
# if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 7
#  define HAVE_SHA_CRYPT
# endif
#endif

/* Unknown versions of Solaris */
#if defined __SVR4 && defined __sun
# define HAVE_SHA_CRYPT
# define HAVE_SOLARIS_CRYPT_GENSALT
#endif

#define HAVE_GETTIMEOFDAY

#ifdef ENABLE_NLS
# ifndef NLS_CAT_NAME
#  define NLS_CAT_NAME   "whois"
# endif
# ifndef LOCALEDIR
#  define LOCALEDIR     "/usr/share/locale"
# endif
#endif

