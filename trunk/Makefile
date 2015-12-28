CXXFLAGS := $(shell pkg-config fuse --cflags)  -O3 -lgcrypt -static-libgcc -Wall -std=c++0x -Wextra -Wold-style-cast  -Weffc++ -pedantic -Wstrict-null-sentinel -Woverloaded-virtual -Wsign-promo
CFLAGS := $(shell pkg-config fuse --cflags)   -O3 -lgcrypt -static-libgcc -Wall -std=c++0x -Wextra -Wold-style-cast  -Weffc++ -pedantic -Wstrict-null-sentinel -Woverloaded-virtual -Wsign-promo
LDFLAGS := $(shell pkg-config fuse --libs) 

targets = failsafe-scan failsafefs

all: $(targets)

failsafefs: failsafefs.cpp failsafe.h
	g++ -o failsafefs failsafefs.cpp  ${CXXFLAGS} ${LDFLAGS}

failsafe-scan:	failsafe-scan.cpp failsafe.h
	g++ -o failsafe-scan failsafe-scan.cpp  ${CXXFLAGS} ${LDFLAGS} 


clean:
	rm -f *.o
	rm -f $(targets)
	rm -f deb/CONTENT/usr/bin/*
	rm -f deb/DEBIAN/*
	rm -f *.deb

deb: all
	rm -f deb/CONTENT/usr/bin/*
	cp failsafefs deb/CONTENT/usr/bin/
	cat control.template|sed -e "s/SVNREVISION/`svn info $1|grep 'Revision:' |sed -e 's/Revision: //'`/" >deb/DEBIAN/control
	dpkg -b deb/ failsafefs_rev_`svn info $1|grep 'Revision:' |sed -e 's/Revision: //'`.deb

format:
	astyle --style=linux *.cpp *.h 
	rm *.orig
