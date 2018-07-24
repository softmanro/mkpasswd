prefix = /usr

CFLAGS ?= -g -O2

INSTALL = install

mkpasswd_OBJECTS := mkpasswd.o utils.o

ifdef HAVE_LIBIDN2
whois_LDADD += -lidn2
DEFS += -DHAVE_LIBIDN2
else
ifdef HAVE_LIBIDN
whois_LDADD += -lidn
DEFS += -DHAVE_LIBIDN
endif
endif

ifdef HAVE_ICONV
whois_OBJECTS += simple_recode.o
DEFS += -DHAVE_ICONV
endif
mkpasswd_LDADD += -lcrypt -lssl -lcrypto

CPPFLAGS += $(DEFS) $(INCLUDES)

all: mkpasswd

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

mkpasswd: $(mkpasswd_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(mkpasswd_LDADD) $(LIBS)

install: install-mkpasswd

install-mkpasswd: mkpasswd
	$(INSTALL) -d $(BASEDIR)$(prefix)/bin/
	$(INSTALL) -d $(BASEDIR)$(prefix)/share/man/man1/
	$(INSTALL) -m 0755 mkpasswd $(BASEDIR)$(prefix)/bin/
	$(INSTALL) -m 0644 mkpasswd.1 $(BASEDIR)$(prefix)/share/man/man1/

distclean: clean

clean:
	rm -f *.o whois mkpasswd

.DELETE_ON_ERROR:
