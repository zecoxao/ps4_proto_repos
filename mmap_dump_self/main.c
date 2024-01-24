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
#include "elf64.h"

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

#define TRUE 1
#define FALSE 0

typedef struct {
	int index;
	uint64_t fileoff;
	size_t bufsz;
	size_t filesz;
	int enc;
} SegmentBufInfo;

void print_phdr(Elf64_Phdr *phdr) {
	printf("=================================\n");
	printf("     p_type %08x\n", phdr->p_type);
	printf("     p_flags %08x\n", phdr->p_flags);
	printf("     p_offset %016llx\n", phdr->p_offset);
	printf("     p_vaddr %016llx\n", phdr->p_vaddr);
	printf("     p_paddr %016llx\n", phdr->p_paddr);
	printf("     p_filesz %016llx\n", phdr->p_filesz);
	printf("     p_memsz %016llx\n", phdr->p_memsz);
	printf("     p_align %016llx\n", phdr->p_align);
}

#define SELF_MAGIC	0x1D3D154F
#define ELF_MAGIC	0x464C457F

int is_self(const char *fn)
{
	struct stat st;
	int res = 0;
	int fd = open(fn, O_RDONLY, 0);
	if (fd != -1) {
		stat(fn, &st);
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			printf("mmap %s : %p\n", fn, addr);
			if (st.st_size >= 4)
			{
				uint32_t selfMagic = *(uint32_t*)((uint8_t*)addr + 0x00);
				if (selfMagic == SELF_MAGIC)
				{
					uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
					if (st.st_size >= (0x20 + snum * 0x20 + 4))
					{
						uint32_t elfMagic = *(uint32_t*)((uint8_t*)addr + 0x20 + snum * 0x20);
						if ((selfMagic == SELF_MAGIC) && (elfMagic == ELF_MAGIC))
							res = 1;
					}
				}
			}
			munmap(addr, 0x4000);
		}
		else {
			printf("mmap file %s err : %s\n", fn, strerror(errno));
		}
		close(fd);
	}
	else {
		printf("open %s err : %s\n", fn, strerror(errno));
	}

	return res;
}

#define DECRYPT_SIZE 0x100000

bool read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out)
{
	uint8_t *outPtr = out;
	uint64_t outSize = size;
	uint64_t realOffset = (index << 32) | offset;
	while (outSize > 0)
	{
		size_t bytes = (outSize > DECRYPT_SIZE) ? DECRYPT_SIZE : outSize;
		uint8_t *addr = (uint8_t*)mmap(0, bytes, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
		if (addr != MAP_FAILED)
		{
			memcpy(outPtr, addr, bytes);
			munmap(addr, bytes);
		}
		else
		{
			printf("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
			return FALSE;
		}
		outPtr += bytes;
		outSize -= bytes;
		realOffset += bytes;
	}
	return TRUE;
}

int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
	for (int i = 0; i < num; i += 1) {
		Elf64_Phdr *p = &phdrs[i];
		if (i != index) {
			if (p->p_filesz > 0) {
				printf("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				printf("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}


SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
	printf("segment num : %d\n", num);
	SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
	int segindex = 0;
	for (int i = 0; i < num; i += 1) {
		Elf64_Phdr *phdr = &phdrs[i];
		print_phdr(phdr);

		if (phdr->p_filesz > 0) {
			if ((!is_segment_in_other_segment(phdr, i, phdrs, num)) || (phdr->p_type == 0x6fffff01)) {
				SegmentBufInfo *info = &infos[segindex];
				segindex += 1;
				info->index = i;
				info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
				info->filesz = phdr->p_filesz;
				info->fileoff = phdr->p_offset;
				info->enc = (phdr->p_type != 0x6fffff01) ? TRUE : FALSE;

				printf("seg buf info %d -->\n", segindex);
				printf("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				printf("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
			}
		}
	}
	*segBufNum = segindex;
	return infos;
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
	int sf = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (sf != -1) {
		size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
		printf("elf header + phdr size : 0x%08X\n", elfsz);
		write(sf, ehdr, elfsz);

		for (int i = 0; i < segBufNum; i += 1) {
			printf("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x, enc : %d\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz, segBufs[i].enc);
			uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
			memset(buf, 0, segBufs[i].bufsz);
			if (segBufs[i].enc)
			{
				if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
					lseek(sf, segBufs[i].fileoff, SEEK_SET);
					write(sf, buf, segBufs[i].bufsz);
				}
			}
			else
			{
				lseek(fd, -segBufs[i].filesz, SEEK_END);
				read(fd, buf, segBufs[i].filesz);
				lseek(sf, segBufs[i].fileoff, SEEK_SET);
				write(sf, buf, segBufs[i].filesz);
			}
			free(buf);
		}
		close(sf);
	}
	else {
		printf("open %s err : %s\n", saveFile, strerror(errno));
	}
}

void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	int fd = open(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			printf("mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			printf("ehdr : %p\n", ehdr);

			// shdr fix
			ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

			Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			printf("phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			printf("dump completed\n");

			free(segBufs);
			munmap(addr, 0x4000);
		}
		else {
			printf("mmap file %s err : %s\n", selfFile, strerror(errno));
		}
		close(fd);
	}
	else {
		printf("open %s err : %s\n", selfFile, strerror(errno));
	}
}

int khax(struct thread* td, uint64_t* uap) {
	size_t(*kprintf)(const char* fmt, ...) = (void*)0xFFFFFFFF824CE1A0ULL;
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

	kprintf("return to userland\n");

	return 0;
}

/* Main entry point of program*/
SceInt32 main(int argc, const char *const argv[])
{


	printf("getuid:%08X\n", getuid());

	printf("getpid:%08X\n", getpid());

	syscall(11, khax);

	printf("rechecking getuid:%08X\n", getuid());

	printf("rechecking getpid:%08X\n", getpid());

	if (getuid() == 0) {
		printf("Successfully jailbroken!\n");
	}

	decrypt_and_dump_self("/system/sys_adm/fsck_ufs.elf","/data/fsck_ufs.elf");

	return 0;
}