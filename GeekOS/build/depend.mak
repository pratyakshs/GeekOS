geekos/idt.o: ../src/geekos/idt.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/idt.h ../include/geekos/int.h \
 ../include/geekos/lock.h ../include/geekos/smp.h
geekos/int.o: ../src/geekos/int.c /usr/include/stdc-predef.h \
 ../include/geekos/idt.h ../include/geekos/int.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/lock.h \
 ../include/geekos/paging.h ../include/geekos/bootinfo.h \
 ../include/geekos/list.h
geekos/trap.o: ../src/geekos/trap.c /usr/include/stdc-predef.h \
 ../include/geekos/idt.h ../include/geekos/int.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/lock.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/syscall.h ../include/geekos/trap.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/elf.h ../include/geekos/signal.h \
 ../include/geekos/paging.h ../include/geekos/bootinfo.h \
 ../include/geekos/projects.h
geekos/irq.o: ../src/geekos/irq.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/idt.h ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/io.h ../include/geekos/irq.h \
 ../include/geekos/smp.h
geekos/io.o: ../src/geekos/io.c /usr/include/stdc-predef.h \
 ../include/geekos/io.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h
geekos/keyboard.o: ../src/geekos/keyboard.c /usr/include/stdc-predef.h \
 ../include/geekos/kthread.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/irq.h ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/io.h ../include/geekos/keyboard.h
geekos/screen.o: ../src/geekos/screen.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdarg.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/io.h ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/fmtout.h \
 ../include/geekos/../libc/fmtout.h
geekos/timer.o: ../src/geekos/timer.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/projects.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/features.h /usr/include/sys/cdefs.h \
 /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h \
 /usr/include/gnu/stubs-32.h /usr/include/bits/posix1_lim.h \
 /usr/include/bits/local_lim.h /usr/include/linux/limits.h \
 /usr/include/bits/posix2_lim.h ../include/geekos/io.h \
 ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/irq.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/timer.h ../include/geekos/smp.h
geekos/mem.o: ../src/geekos/mem.c /usr/include/stdc-predef.h \
 ../include/geekos/defs.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/lock.h ../include/geekos/bootinfo.h \
 ../include/geekos/gdt.h ../include/geekos/int.h \
 ../include/geekos/malloc.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/paging.h ../include/geekos/mem.h
geekos/crc32.o: ../src/geekos/crc32.c /usr/include/stdc-predef.h \
 ../include/geekos/crc32.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h
geekos/gdt.o: ../src/geekos/gdt.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/segment.h ../include/geekos/int.h \
 ../include/geekos/defs.h ../include/geekos/lock.h \
 ../include/geekos/tss.h ../include/geekos/gdt.h
geekos/tss.o: ../src/geekos/tss.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/gdt.h \
 ../include/geekos/segment.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/tss.h ../include/geekos/smp.h
geekos/smp.o: ../src/geekos/smp.c /usr/include/stdc-predef.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/apic.h \
 ../include/geekos/smp.h ../include/geekos/list.h \
 ../include/geekos/lock.h ../include/geekos/int.h \
 ../include/geekos/defs.h ../include/geekos/idt.h \
 ../include/geekos/malloc.h ../include/geekos/kthread.h \
 ../include/geekos/io.h ../include/geekos/timer.h ../include/geekos/tss.h \
 ../include/geekos/trap.h ../include/geekos/mem.h \
 ../include/geekos/paging.h ../include/geekos/bootinfo.h \
 ../include/geekos/gdt.h
geekos/segment.o: ../src/geekos/segment.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/tss.h ../include/geekos/segment.h
geekos/malloc.o: ../src/geekos/malloc.c /usr/include/stdc-predef.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/int.h ../include/geekos/kassert.h \
 ../include/geekos/defs.h ../include/geekos/lock.h \
 ../include/geekos/bget.h ../include/geekos/../libc/bget.h \
 ../include/geekos/malloc.h /usr/include/string.h /usr/include/features.h \
 /usr/include/sys/cdefs.h /usr/include/bits/wordsize.h \
 /usr/include/gnu/stubs.h /usr/include/gnu/stubs-32.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 /usr/include/xlocale.h
geekos/synch.o: ../src/geekos/synch.c /usr/include/stdc-predef.h \
 ../include/geekos/kthread.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/synch.h
geekos/kthread.o: ../src/geekos/kthread.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/int.h \
 ../include/geekos/lock.h ../include/geekos/mem.h \
 ../include/geekos/list.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/symbol.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/kthread.h ../include/geekos/malloc.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/elf.h ../include/geekos/signal.h \
 ../include/geekos/alarm.h ../include/geekos/projects.h \
 ../include/geekos/smp.h
geekos/user.o: ../src/geekos/user.c /usr/include/stdc-predef.h \
 ../include/geekos/errno.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/mem.h \
 ../include/geekos/list.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/malloc.h \
 ../include/geekos/kthread.h ../include/geekos/vfs.h \
 ../include/geekos/fileio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/blockdev.h ../include/geekos/tss.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/elf.h ../include/geekos/signal.h \
 ../include/geekos/projects.h ../include/geekos/smp.h \
 ../include/libc/string.h
geekos/userseg.o: ../src/geekos/userseg.c /usr/include/stdc-predef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/defs.h ../include/geekos/mem.h \
 ../include/geekos/list.h ../include/geekos/lock.h \
 ../include/geekos/paging.h ../include/geekos/bootinfo.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/malloc.h ../include/geekos/int.h \
 ../include/geekos/gdt.h ../include/geekos/segment.h \
 ../include/geekos/tss.h ../include/geekos/kthread.h \
 ../include/geekos/argblock.h ../include/geekos/user.h \
 ../include/geekos/elf.h ../include/geekos/signal.h
geekos/argblock.o: ../src/geekos/argblock.c /usr/include/stdc-predef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/argblock.h
geekos/syscall.o: ../src/geekos/syscall.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/geekos/errno.h \
 ../include/geekos/kthread.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/int.h ../include/geekos/defs.h ../include/geekos/elf.h \
 ../include/geekos/malloc.h ../include/geekos/keyboard.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/signal.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/timer.h \
 ../include/geekos/vfs.h ../include/geekos/fileio.h \
 ../include/geekos/blockdev.h ../include/geekos/sem.h \
 ../include/geekos/projects.h ../include/geekos/sys_net.h \
 ../include/geekos/pipe.h ../include/geekos/mem.h
geekos/dma.o: ../src/geekos/dma.c /usr/include/stdc-predef.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/range.h ../include/geekos/int.h \
 ../include/geekos/kassert.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/io.h ../include/geekos/dma.h
geekos/floppy.o: ../src/geekos/floppy.c /usr/include/stdc-predef.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/mem.h ../include/geekos/defs.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/lock.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/malloc.h \
 ../include/geekos/int.h ../include/geekos/irq.h ../include/geekos/dma.h \
 ../include/geekos/io.h ../include/geekos/timer.h \
 ../include/geekos/kthread.h ../include/geekos/blockdev.h \
 ../include/geekos/fileio.h ../include/geekos/floppy.h
geekos/elf.o: ../src/geekos/elf.c /usr/include/stdc-predef.h \
 ../include/geekos/errno.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/pfat.h ../include/geekos/fileio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/vfs.h ../include/geekos/list.h \
 ../include/geekos/lock.h ../include/geekos/fileio.h \
 ../include/geekos/blockdev.h ../include/geekos/kthread.h \
 ../include/geekos/malloc.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h ../include/geekos/user.h \
 ../include/geekos/segment.h ../include/geekos/elf.h \
 ../include/geekos/signal.h ../include/geekos/paging.h \
 ../include/geekos/defs.h ../include/geekos/bootinfo.h
geekos/blockdev.o: ../src/geekos/blockdev.c /usr/include/stdc-predef.h \
 ../include/geekos/errno.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/malloc.h ../include/geekos/int.h \
 ../include/geekos/kassert.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/kthread.h \
 ../include/geekos/list.h ../include/geekos/synch.h \
 ../include/geekos/blockdev.h ../include/geekos/fileio.h
geekos/ide.o: ../src/geekos/ide.c /usr/include/stdc-predef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/errno.h ../include/geekos/malloc.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/io.h ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/timer.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/blockdev.h ../include/geekos/fileio.h \
 ../include/geekos/ide.h
geekos/vfs.o: ../src/geekos/vfs.c /usr/include/stdc-predef.h \
 ../include/geekos/errno.h ../include/geekos/list.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/lock.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/malloc.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/vfs.h \
 ../include/geekos/fileio.h ../include/geekos/blockdev.h \
 ../include/geekos/projects.h
geekos/pfat.o: ../src/geekos/pfat.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/features.h /usr/include/sys/cdefs.h \
 /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h \
 /usr/include/gnu/stubs-32.h /usr/include/bits/posix1_lim.h \
 /usr/include/bits/local_lim.h /usr/include/linux/limits.h \
 /usr/include/bits/posix2_lim.h ../include/geekos/errno.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/malloc.h ../include/geekos/ide.h \
 ../include/geekos/blockdev.h ../include/geekos/kthread.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/lock.h ../include/geekos/fileio.h \
 ../include/geekos/bitset.h ../include/geekos/vfs.h \
 ../include/geekos/synch.h ../include/geekos/pfat.h \
 ../include/geekos/fileio.h ../include/geekos/vfs.h \
 ../include/geekos/projects.h
geekos/bitset.o: ../src/geekos/bitset.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/malloc.h ../include/geekos/bitset.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/libc/conio.h ../include/geekos/keyboard.h
geekos/bufcache.o: ../src/geekos/bufcache.c /usr/include/stdc-predef.h \
 ../include/geekos/errno.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/mem.h ../include/geekos/defs.h \
 ../include/geekos/list.h ../include/geekos/lock.h \
 ../include/geekos/paging.h ../include/geekos/bootinfo.h \
 ../include/geekos/malloc.h ../include/geekos/blockdev.h \
 ../include/geekos/kthread.h ../include/geekos/fileio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/bufcache.h ../include/geekos/synch.h
geekos/signal.o: ../src/geekos/signal.c /usr/include/stdc-predef.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/int.h \
 ../include/geekos/lock.h ../include/geekos/mem.h \
 ../include/geekos/list.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/symbol.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/kthread.h ../include/geekos/malloc.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/elf.h ../include/geekos/signal.h \
 ../include/geekos/projects.h ../include/geekos/alarm.h
geekos/paging.o: ../src/geekos/paging.c /usr/include/stdc-predef.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/int.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/lock.h \
 ../include/geekos/idt.h ../include/geekos/kthread.h \
 ../include/geekos/list.h ../include/geekos/mem.h \
 ../include/geekos/paging.h ../include/geekos/bootinfo.h \
 ../include/geekos/malloc.h ../include/geekos/gdt.h \
 ../include/geekos/segment.h ../include/geekos/user.h \
 ../include/geekos/elf.h ../include/geekos/signal.h \
 ../include/geekos/vfs.h ../include/geekos/fileio.h \
 ../include/geekos/blockdev.h ../include/geekos/crc32.h \
 ../include/geekos/errno.h ../include/geekos/projects.h \
 ../include/geekos/smp.h ../include/libc/mmap.h
geekos/sem.o: ../src/geekos/sem.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/geekos/errno.h \
 ../include/geekos/kthread.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/int.h ../include/geekos/defs.h ../include/geekos/elf.h \
 ../include/geekos/malloc.h ../include/geekos/keyboard.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/signal.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/timer.h \
 ../include/geekos/vfs.h ../include/geekos/fileio.h \
 ../include/geekos/blockdev.h ../include/geekos/sem.h \
 ../include/geekos/projects.h
geekos/gosfs.o: ../src/geekos/gosfs.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/features.h /usr/include/sys/cdefs.h \
 /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h \
 /usr/include/gnu/stubs-32.h /usr/include/bits/posix1_lim.h \
 /usr/include/bits/local_lim.h /usr/include/linux/limits.h \
 /usr/include/bits/posix2_lim.h ../include/geekos/errno.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/malloc.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/bitset.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/lock.h ../include/geekos/bufcache.h \
 ../include/geekos/gosfs.h ../include/geekos/blockdev.h \
 ../include/geekos/fileio.h ../include/geekos/vfs.h \
 ../include/geekos/projects.h
geekos/gfs2.o: ../src/geekos/gfs2.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/features.h /usr/include/sys/cdefs.h \
 /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h \
 /usr/include/gnu/stubs-32.h /usr/include/bits/posix1_lim.h \
 /usr/include/bits/local_lim.h /usr/include/linux/limits.h \
 /usr/include/bits/posix2_lim.h ../include/geekos/errno.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/malloc.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/bitset.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/lock.h ../include/geekos/bufcache.h \
 ../include/geekos/gfs2.h ../include/geekos/vfs.h \
 ../include/geekos/fileio.h ../include/geekos/blockdev.h \
 ../include/geekos/projects.h
geekos/cfs.o: ../src/geekos/cfs.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/features.h /usr/include/sys/cdefs.h \
 /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h \
 /usr/include/gnu/stubs-32.h /usr/include/bits/posix1_lim.h \
 /usr/include/bits/local_lim.h /usr/include/linux/limits.h \
 /usr/include/bits/posix2_lim.h /usr/include/ctype.h \
 /usr/include/bits/types.h /usr/include/bits/typesizes.h \
 /usr/include/endian.h /usr/include/bits/endian.h \
 /usr/include/bits/byteswap.h /usr/include/bits/byteswap-16.h \
 /usr/include/xlocale.h ../include/geekos/errno.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/malloc.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/bitset.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/lock.h ../include/geekos/bufcache.h \
 ../include/geekos/cfs.h ../include/geekos/blockdev.h \
 ../include/geekos/fileio.h ../include/geekos/vfs.h \
 ../include/geekos/projects.h ../include/geekos/mem.h \
 ../include/geekos/defs.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h
geekos/rip.o: ../src/geekos/net/rip.c /usr/include/stdc-predef.h \
 ../include/geekos/net/rip.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/net/socket.h ../include/geekos/net/ip.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/alarm.h \
 ../include/geekos/net/routing.h ../include/geekos/projects.h
geekos/socket.o: ../src/geekos/net/socket.c /usr/include/stdc-predef.h \
 ../include/geekos/net/socket.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/net/ip.h ../include/geekos/list.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/lock.h ../include/geekos/net/net.h \
 ../include/geekos/synch.h ../include/geekos/kthread.h \
 ../include/geekos/net/netbuf.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/malloc.h \
 ../include/geekos/errno.h ../include/geekos/net/udp.h \
 ../include/geekos/net/tcp.h ../include/geekos/alarm.h \
 ../include/geekos/projects.h
geekos/net.o: ../src/geekos/net/net.c /usr/include/stdc-predef.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/defs.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/malloc.h ../include/geekos/int.h \
 ../include/geekos/net/ne2000.h ../include/geekos/io.h \
 ../include/geekos/errno.h ../include/geekos/net/ethernet.h \
 ../include/geekos/syscall.h ../include/geekos/sys_net.h
geekos/tcp.o: ../src/geekos/net/tcp.c /usr/include/stdc-predef.h \
 ../include/geekos/net/tcp.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/defs.h ../include/geekos/net/ip.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/malloc.h \
 ../include/geekos/errno.h ../include/geekos/net/socket.h \
 ../include/geekos/projects.h
geekos/arp.o: ../src/geekos/net/arp.c /usr/include/stdc-predef.h \
 ../include/geekos/malloc.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/errno.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/kthread.h \
 ../include/geekos/list.h ../include/geekos/lock.h \
 ../include/geekos/int.h ../include/geekos/defs.h \
 ../include/geekos/timer.h ../include/geekos/alarm.h \
 ../include/geekos/net/arp.h ../include/geekos/net/net.h \
 ../include/geekos/synch.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ethernet.h ../include/geekos/net/ip.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/projects.h
geekos/ethernet.o: ../src/geekos/net/ethernet.c /usr/include/stdc-predef.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/int.h ../include/geekos/kassert.h \
 ../include/geekos/defs.h ../include/geekos/lock.h \
 ../include/geekos/malloc.h ../include/geekos/errno.h \
 ../include/geekos/net/ethernet.h ../include/geekos/net/net.h \
 ../include/geekos/synch.h ../include/geekos/kthread.h \
 ../include/geekos/list.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/projects.h
geekos/ip.o: ../src/geekos/net/ip.c /usr/include/stdc-predef.h \
 ../include/geekos/net/ip.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/errno.h \
 ../include/geekos/malloc.h ../include/geekos/net/arp.h \
 ../include/geekos/net/routing.h ../include/geekos/net/ethernet.h \
 ../include/geekos/int.h ../include/geekos/net/udp.h \
 ../include/geekos/net/socket.h ../include/geekos/net/tcp.h \
 ../include/geekos/projects.h
geekos/ne2000.o: ../src/geekos/net/ne2000.c /usr/include/stdc-predef.h \
 ../include/geekos/net/ne2000.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/defs.h \
 ../include/geekos/net/netbuf.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/io.h ../include/geekos/irq.h ../include/geekos/int.h \
 ../include/geekos/malloc.h ../include/geekos/idt.h
geekos/netbuf.o: ../src/geekos/net/netbuf.c /usr/include/stdc-predef.h \
 ../include/geekos/net/netbuf.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/list.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/lock.h ../include/geekos/defs.h \
 ../include/geekos/errno.h ../include/geekos/malloc.h
geekos/sys_net.o: ../src/geekos/net/sys_net.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/geekos/errno.h \
 ../include/geekos/kthread.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/int.h ../include/geekos/defs.h ../include/geekos/elf.h \
 ../include/geekos/malloc.h ../include/geekos/keyboard.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/signal.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/timer.h \
 ../include/geekos/vfs.h ../include/geekos/fileio.h \
 ../include/geekos/blockdev.h ../include/geekos/sem.h \
 ../include/geekos/sys_net.h ../include/geekos/projects.h \
 ../include/geekos/net/ethernet.h ../include/geekos/net/net.h \
 ../include/geekos/synch.h ../include/geekos/net/netbuf.h \
 ../include/geekos/net/arp.h ../include/geekos/net/ip.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/net/routing.h \
 ../include/geekos/net/socket.h
geekos/udp.o: ../src/geekos/net/udp.c /usr/include/stdc-predef.h \
 ../include/geekos/net/udp.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/net/ip.h ../include/geekos/list.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/lock.h ../include/geekos/net/net.h \
 ../include/geekos/synch.h ../include/geekos/kthread.h \
 ../include/geekos/net/netbuf.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/net/socket.h \
 ../include/geekos/malloc.h ../include/geekos/errno.h \
 ../include/geekos/projects.h
geekos/routing.o: ../src/geekos/net/routing.c /usr/include/stdc-predef.h \
 ../include/geekos/net/routing.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/lock.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/net/ip.h ../include/geekos/net/ipdefs.h \
 ../include/geekos/malloc.h ../include/geekos/errno.h \
 ../include/geekos/int.h ../include/geekos/timer.h \
 ../include/geekos/projects.h
geekos/sound.o: ../src/geekos/sound/sound.c /usr/include/stdc-predef.h \
 ../include/geekos/io.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/int.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/defs.h \
 ../include/geekos/lock.h ../include/geekos/irq.h ../include/geekos/dma.h \
 ../include/geekos/malloc.h ../include/geekos/errno.h \
 ../include/geekos/kthread.h ../include/geekos/list.h \
 ../include/geekos/timer.h ../include/geekos/alarm.h \
 ../include/geekos/mem.h ../include/geekos/paging.h \
 ../include/geekos/bootinfo.h ../include/geekos/vfs.h \
 ../include/geekos/fileio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/blockdev.h ../include/geekos/projects.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 ../include/geekos/sound.h
geekos/alarm.o: ../src/geekos/alarm.c /usr/include/stdc-predef.h \
 ../include/geekos/timer.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/alarm.h ../include/geekos/list.h \
 ../include/geekos/kassert.h ../include/geekos/screen.h \
 ../include/geekos/lock.h ../include/geekos/malloc.h \
 ../include/geekos/errno.h ../include/geekos/int.h \
 ../include/geekos/kthread.h
geekos/pipe.o: ../src/geekos/pipe.c /usr/include/stdc-predef.h \
 ../include/geekos/pipe.h ../include/geekos/vfs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/fileio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/blockdev.h ../include/geekos/kthread.h \
 ../include/geekos/malloc.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h ../include/geekos/errno.h \
 ../include/geekos/projects.h ../include/geekos/int.h \
 ../include/geekos/defs.h
geekos/main.o: ../src/geekos/main.c /usr/include/stdc-predef.h \
 ../include/geekos/bootinfo.h ../include/geekos/string.h \
 ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/screen.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/mem.h ../include/geekos/defs.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/lock.h ../include/geekos/paging.h \
 ../include/geekos/crc32.h ../include/geekos/tss.h \
 ../include/geekos/int.h ../include/geekos/kthread.h \
 ../include/geekos/trap.h ../include/geekos/timer.h \
 ../include/geekos/keyboard.h ../include/geekos/dma.h \
 ../include/geekos/ide.h ../include/geekos/floppy.h \
 ../include/geekos/pfat.h ../include/geekos/fileio.h \
 ../include/geekos/vfs.h ../include/geekos/fileio.h \
 ../include/geekos/blockdev.h ../include/geekos/vfs.h \
 ../include/geekos/user.h ../include/geekos/segment.h \
 ../include/geekos/elf.h ../include/geekos/signal.h \
 ../include/geekos/gosfs.h ../include/geekos/gfs2.h \
 ../include/geekos/cfs.h ../include/geekos/net/ne2000.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/net/netbuf.h ../include/geekos/net/arp.h \
 ../include/geekos/alarm.h ../include/geekos/net/ip.h \
 ../include/geekos/net/ipdefs.h ../include/geekos/net/routing.h \
 ../include/geekos/net/socket.h ../include/geekos/net/rip.h \
 ../include/geekos/projects.h ../include/geekos/sound.h \
 ../include/geekos/smp.h ../include/geekos/io.h
libc/socket.o: ../src/libc/socket.c /usr/include/stdc-predef.h \
 ../include/libc/socket.h ../include/geekos/defs.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/syscall.h
libc/net.o: ../src/libc/net.c /usr/include/stdc-predef.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/syscall.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/net/ip.h ../include/geekos/defs.h \
 ../include/geekos/list.h ../include/geekos/kassert.h \
 ../include/geekos/screen.h ../include/geekos/lock.h \
 ../include/geekos/net/net.h ../include/geekos/synch.h \
 ../include/geekos/kthread.h ../include/geekos/net/netbuf.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 ../include/geekos/net/ipdefs.h
libc/fileio.o: ../src/libc/fileio.c /usr/include/stdc-predef.h \
 ../include/geekos/errno.h ../include/geekos/syscall.h \
 ../include/libc/fileio.h ../include/geekos/fileio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/libc/string.h
libc/spin.o: ../src/libc/spin.c /usr/include/stdc-predef.h \
 ../include/geekos/projects.h ../include/libc/conio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/keyboard.h ../include/geekos/screen.h
libc/sched.o: ../src/libc/sched.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h
libc/compat.o: ../src/libc/compat.c /usr/include/stdc-predef.h \
 ../include/libc/conio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/keyboard.h ../include/geekos/screen.h
libc/signal.o: ../src/libc/signal.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/geekos/signal.h \
 ../include/libc/fmtout.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdarg.h \
 ../include/libc/process.h ../include/geekos/user.h \
 ../include/libc/conio.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/keyboard.h ../include/geekos/screen.h
libc/process.o: ../src/libc/process.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/syscall.h ../include/geekos/errno.h \
 ../include/libc/string.h ../include/libc/process.h \
 ../include/geekos/user.h ../include/libc/conio.h \
 ../include/geekos/keyboard.h ../include/geekos/screen.h
libc/sema.o: ../src/libc/sema.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/geekos/sem.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/libc/sema.h
libc/entry.o: ../src/libc/entry.c /usr/include/stdc-predef.h \
 ../include/geekos/argblock.h ../include/libc/signal.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/signal.h
libc/conio.o: ../src/libc/conio.c /usr/include/stdc-predef.h \
 ../include/geekos/syscall.h ../include/libc/fmtout.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdarg.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/libc/conio.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/keyboard.h ../include/geekos/screen.h
libc/errno.o: libc/errno.c /usr/include/stdc-predef.h
common/fmtout.o: ../src/common/fmtout.c /usr/include/stdc-predef.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdarg.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/geekos/string.h ../include/geekos/../libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/limits.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include-fixed/syslimits.h \
 /usr/include/limits.h /usr/include/features.h /usr/include/sys/cdefs.h \
 /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h \
 /usr/include/gnu/stubs-32.h /usr/include/bits/posix1_lim.h \
 /usr/include/bits/local_lim.h /usr/include/linux/limits.h \
 /usr/include/bits/posix2_lim.h ../include/geekos/fmtout.h \
 ../include/geekos/../libc/fmtout.h
common/string.o: ../src/common/string.c /usr/include/stdc-predef.h \
 ../include/libc/fmtout.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdarg.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h
common/memmove.o: ../src/common/memmove.c /usr/include/stdc-predef.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h
common/bget.o: ../src/common/bget.c /usr/include/stdc-predef.h \
 ../include/libc/string.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stddef.h \
 ../include/libc/conio.h ../include/geekos/ktypes.h \
 /usr/lib/gcc/x86_64-linux-gnu/4.9/include/stdbool.h \
 ../include/geekos/keyboard.h ../include/geekos/screen.h \
 ../include/geekos/bget.h ../include/geekos/../libc/bget.h
