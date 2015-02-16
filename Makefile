DEFS=-DUSE_LINUX_SENDFILE -DWITH_MYSQL
#DEFS=-DUSE_LINUX_SENDFILE
CC=gcc
CCFLAGS=$(DEFS) -Wall -ggdb
#CCFLAGS=$(DEFS) -Wall -Werror -ggdb #-pg
LDFLAGS=-ggdb #-pg
#LIBS=
LIBS=-L/usr/local/lib/mysql -lmysqlclient
KEPOLLDEF=-DASIO_USE_KEPOLL
KEPOLLHDR=Kepoll.h
KEPOLLOBJ=Kepoll.o
KEPOLLDIR=asio/
OBJS=main.o kbuf/kbuf.o asio/asio.o $(KEPOLLDIR)$(KEPOLLOBJ) net.o log.o http.o cfg.o tracker.o

all: parabol
clean:
	@rm *.o */*.o parabol
setdist:
	./setdist.sh
dist.h: setdist
dist: setdist
	@rm -fr parabol-dist
	@mkdir parabol-dist parabol-dist/kbuf parabol-dist/asio
	cp README parabol-dist/
	cp Makefile *.[ch] *.sh parabol-dist/
	cp parabol.cfg parabol-dist/parabol.cfg.dist
	cp tracker.cfg parabol-dist/tracker.cfg.dist
	cp access.cfg parabol-dist/access.cfg.dist
	mv parabol-dist/config.h parabol-dist/config.h.dist
	cp kbuf/Makefile kbuf/*.[ch] parabol-dist/kbuf/
	cp asio/Makefile asio/*.[chs] parabol-dist/asio/
	tar cvfz tracker-dist.tar.gz parabol-dist/
	@cat dist.h|cut -d' ' -f3-
	@cat *.[ch] kbuf/*.[ch] asio/*.[chs] | wc -l
kbuf/kbuf.o: kbuf/kbuf.c kbuf/kbuf.h
	cd kbuf; make
asio/asio.o: asio/asio.c asio/asio.h
	cd asio;make KEPOLLHDR=$(KEPOLLHDR) KEPOLLOBJ=$(KEPOLLOBJ) KEPOLLDEF=$(KEPOLLDEF)
parabol: $(OBJS)
	$(CC) $(LDFLAGS) -o parabol $(OBJS) $(LIBS)
parabol.h: config.h kbuf/kbuf.h asio/asio.h net.h http.h log.h cfg.h tracker.h
main.o: main.c parabol.h config.h
	$(CC) $(CCFLAGS) -c main.c
net.o: net.c parabol.h config.h
	$(CC) $(CCFLAGS) -c net.c
log.o: log.c parabol.h config.h
	$(CC) $(CCFLAGS) -c log.c
http.o: http.c parabol.h config.h
	$(CC) $(CCFLAGS) -c http.c
cfg.o: cfg.c parabol.h config.h
	$(CC) $(CCFLAGS) -c cfg.c
tracker.o: tracker.c parabol.h config.h tracker.h
	$(CC) $(CCFLAGS) -c tracker.c
