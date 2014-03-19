AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libwallet.la
AM_CPPFLAGS = -I$(srcdir)/../include $(libbitcoin_CFLAGS)
libwallet_la_SOURCES = \
    deterministic_wallet.cpp \
    mnemonic.cpp \
    transaction.cpp \
    hd_keys.cpp \
    key_formats.cpp \
    uri.cpp

libwallet_la_LIBADD = $(libbitcoin_LIBS)

