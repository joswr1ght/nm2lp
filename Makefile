##################################
# <jwright> Well, I may be doing stupid things with make
# <jwright> OK, it was Makefile stupid'ness
# <jwright> I don't really understand what the hell I am doing with Make, I'm
#           just copying other files and seeing what works.
# <dragorn> heh
# <dragorn> i think thats all anyone does
# <dragorn> make is a twisted beast
##################################
LDLIBS		= -lpcap
CFLAGS		= -pipe -Wall -I/usr/include/wireshark/wiretap
CFLAGS		+= -g3 -ggdb
#CFLAGS		+= -O2
CFLAGS		+=$(shell pkg-config --cflags glib-2.0 gtk+-2.0)
LDFLAGS		+=$(shell pkg-config --libs glib-2.0 gtk+-2.0)
LDLIBS		+= -lpcap -lwiretap
PROGOBJ		= nm2lp.o utils.o
PROG		= nm2lp
BINDIR		= /usr/local/bin

all: $(PROGOBJ) $(PROG)

nm2lp: common.h utils.c utils.h nm2lp.c nm2lp.h
	$(CC) $(CFLAGS) nm2lp.c -o nm2lp utils.o $(LDLIBS)

utils: utils.c utils.h
	$(CC) $(CFLAGS) utils.c -c

clean:
	@rm $(PROGOBJ) $(PROG)

strip:
	@ls -l $(PROG)
	@strip $(PROG)
	@ls -l $(PROG)

install: all
	install -d $(BINDIR)
	install -m 755 $(PROG) $(BINDIR)
