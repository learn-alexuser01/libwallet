CXXFLAGS=$(shell pkg-config --cflags libbitcoin) -ggdb
LIBS=$(shell pkg-config --libs libbitcoin libwallet)

default: all

.cpp.o:
	$(CXX) -o $@ -c $< $(CXXFLAGS)

determ: determ.o
	$(CXX) -o $@ $< $(LIBS)

hd: hd.o
	$(CXX) -o $@ $< $(LIBS)

uri: uri.o
	$(CXX) -o $@ $< $(LIBS)

all: determ hd uri

clean:
	rm -f determ hd uri
	rm -f *.o
