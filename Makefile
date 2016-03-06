EXTRA_CFLAGS += -Wno-declaration-after-statement
APP_EXTRA_FLAGS:= -O2 -ansi -pedantic -std=c99 
KERNEL_SRC:= /lib/modules/$(shell uname -r)/build
SUBDIR= $(PWD)
GCC:=gcc
RM:=rm

.PHONY : clean

all: clean modules app

obj-m:= rate_monotonic_scheduler.o

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules

app: userapp.c userapp.h
	$(GCC) -o userapp userapp.c $(APP_EXTRA_FLAGS)

clean:
	$(RM) -f userapp *~ *.ko *.o *.mod.c Module.symvers modules.order
