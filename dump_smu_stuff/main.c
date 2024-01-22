#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <kernel.h>
#include <libdbg.h>
#include <sceerror.h>
#include <scetypes.h>
#include <net.h>
#include <libhttp.h>



int khax(struct thread* td, uint64_t* uap) {
    size_t(*kprintf)(const char* fmt, ...) = (void*)0xFFFFFFFF824CE1A0ULL;
    uint32_t(*readl) (uint32_t unk, uint32_t index) = (void*)0xFFFFFFFF826C32E0ULL;
    uint32_t(*writel) (uint32_t unk, uint32_t index, uint32_t val) = (void*)0xFFFFFFFF826C3300ULL;

	kprintf("first test\n");

    uint32_t i = 0;
    for (i = 0xC010702C; i < 0xC010722C; i = i + 4) {
        kprintf("%08X\n", readl(0, i));
    }

    kprintf("second test\n");

    for (i = 0; i < 0x40000; i = i + 4) {
        kprintf("%08X\n", readl(0, i));
    }

    return 0;
}

/* Main entry point of program*/
SceInt32 main(int argc, const char *const argv[])
{
    printf("dumping smu stuff\n");
    
    syscall(11, khax);
    
}
