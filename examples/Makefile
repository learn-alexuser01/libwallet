CXXFLAGS=$(shell pkg-config --cflags libbitcoin) -ggdb
LIBS=$(shell pkg-config --libs libbitcoin libwallet)

default: all

.cpp.o:
	$(CXX) -o $@ -c $< $(CXXFLAGS)

determ: determ.o
	$(CXX) -o $@ $< $(LIBS)

uri: uri.o
	$(CXX) -o $@ $< $(LIBS)

all: determ uri

clean:
	rm -f determ uri
	rm -f *.o
