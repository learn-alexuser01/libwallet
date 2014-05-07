CXXFLAGS=$(shell pkg-config --cflags libbitcoin) -ggdb
LIBS=$(shell pkg-config --libs libbitcoin libwallet)

default: all

.cpp.o:
	$(CXX) -o $@ -c $< $(CXXFLAGS)

ec: ec.o
	$(CXX) -o $@ $< $(LIBS)

determ: determ.o
	$(CXX) -o $@ $< $(LIBS)

hd: hd.o
	$(CXX) -o $@ $< $(LIBS)

uri: uri.o
	$(CXX) -o $@ $< $(LIBS)

all: determ hd uri ec

clean:
	rm -f determ hd uri ec
	rm -f *.o
