CXXFLAGS=$(shell pkg-config --cflags libbitcoin) -ggdb
LIBS=$(shell pkg-config --libs libbitcoin libwallet)

default: all

determ.o: determ.cpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

determ: determ.o
	$(CXX) -o $@ $< $(LIBS)

all: determ

clean:
	rm -f determ
	rm -f *.o
