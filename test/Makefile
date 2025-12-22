OW = $(PWD)/../source
HALIF = $(PWD)/halinterface
HAL = $(PWD)/rdk-wifi-hal

INCLUDE = \
	-I $(OW)/db \
	-I $(OW)/stubs \
	-I $(OW)/../include \
	-I $(OW)/core/services/ \
	-I $(OW)/core \
	-I $(OW)/stats \
	-I $(OW)/utils \
	-I $(OW)/platform/common/ \
	-I $(OW)/platform/linux/ \
	-I $(OW)/platform/linux/he_bus/inc \
	-I $(OW)/ccsp/ \
	-I $(OW)/apps/ \
	-I $(OW)/apps/analytics/ \
	-I $(OW)/apps/levl/ \
	-I $(OW)/apps/csi/ \
	-I $(OW)/apps/sm \
	-I $(OW)/apps/motion/ \
	-I $(OW)/apps/whix/ \
	-I $(OW)/apps/harvester/ \
	-I $(OW)/apps/ocs/ \
	-I $(OW)/dml/linux/ \
	-I $(HALIF)/include \
	-I $(HAL)/src/

CFLAGS = \
	-Og -g3 -ggdb -pipe \
	-Wno-implicit-function-declaration \
	-DSTATIC=static

CC = gcc

ifneq ($(COV),)
CFLAGS += --coverage
endif

all::
	@true

clean::
	@true

distclean:: clean
	@true

FORCE:

LIBOW_SO = \
	$(OW)/core/wifi_ctrl.c \
	$(OW)/core/wifi_events.c \
	$(OW)/utils/collection.c

libow.so: $(LIBOW_SO)
	$(CC) $(INCLUDE) $(CFLAGS) \
		-shared -fPIC \
		-o $@ \
		$(LIBOW_SO)

clean::
	rm -f libow.so

libstubs.so: stubs.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ stubs.c

clean::
	rm -f libstubs.so

libs:: libow.so libstubs.so

ctrl-queue: ctrl-queue.c libow.so libstubs.so
	$(CC) $(INCLUDE) $(CFLAGS) -o ctrl-queue ctrl-queue.c -L. -low -lstubs

clean::
	rm -f ctrl-queue

stubs.c: libow.so
	$(CC) $(INCLUDE) $(CFLAGS) -o ignore ctrl-queue.c -L. -low 2>&1 | \
		grep 'undefined reference' | \
		cut -d\` -f2 | cut -d\' -f1 | \
		sort | uniq | \
		while read n ; do \
			echo "void $${n} (void) { ldk(); }" ; \
		done > $@
	sed -i '1i extern void ldk (void);' $@

clean::
	rm -f stubs.c

all:: ctrl-queue

r:
	LD_LIBRARY_PATH=$$PWD ./ctrl-queue

bt:
	LD_LIBRARY_PATH=$$PWD gdb -q \
		-ex 'set confirm off' \
		-ex 'r' \
		-ex 'bt' \
		-ex 'q' \
		./ctrl-queue

gdb:
	LD_LIBRARY_PATH=$$PWD gdb -q \
		-ex 'set confirm off' \
		-ex 'b main' \
		-ex 'r' \
		./ctrl-queue


coverage.info: FORCE
	lcov \
		--quiet \
		--rc branch_coverage=1 \
		--no-external \
		--capture \
		--directory . \
		--output-file coverage.info

lcov: coverage.info
	genhtml \
		--legend \
		--rc branch_coverage=1 \
		$< \
		-o tmp

clean::
	rm -f coverage.info
	[ -d tmp ] && rm -r tmp || true
	rm -f *.gcda *.gcno
