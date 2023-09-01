lib_LTLIBRARIES = libtcpWinSD.la

libtcpWinSD_la_SOURCES = tcpWinSD.c

libtcpWinSD_la_CFLAGS = \
        -I$(top_srcdir)/../../utils \
        -I$(top_srcdir)/../../tranalyzer2/src

if APPLE
libtcpWinSD_la_CFLAGS += -D_DARWIN_C_SOURCE  # OSX specific flags
else
libtcpWinSD_la_CFLAGS += -D_GNU_SOURCE
endif

libtcpWinSD_la_LDFLAGS = -shrext .so  # extension for shared library
