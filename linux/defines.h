#define	SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

#define	SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	TRACEBUF

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

struct knote;



struct filterops {
	int	f_isfd;		/* true if ident == filedescriptor */
	int	(*f_attach)(struct knote *kn);
	void	(*f_detach)(struct knote *kn);
	int	(*f_event)(struct knote *kn, long hint);
	void	(*f_touch)(struct knote *kn, struct kevent *kev, unsigned long type);
};

struct knote {
	SLIST_ENTRY(knote)	kn_link;	/* for kq */
	SLIST_ENTRY(knote)	kn_selnext;	/* for struct selinfo */
	struct			knlist *kn_knlist;	/* f_attach populated */
	TAILQ_ENTRY(knote)	kn_tqe;
	struct			kqueue *kn_kq;	/* which queue we are on */
	struct 			kevent kn_kevent;
	int			kn_status;	/* protected by kq lock */
	int			kn_sfflags;	/* saved filter flags */
	intptr_t		kn_sdata;	/* saved data field */
	union {
		struct		file *p_fp;	/* file data pointer */
		struct		proc *p_proc;	/* proc pointer */
		struct		aiocblist *p_aio;	/* AIO job pointer */
		struct		aioliojob *p_lio;	/* LIO job pointer */ 
	} kn_ptr;
	struct			filterops *kn_fop;
	void			*kn_hook;
	int			kn_hookid;
};



struct sendto_args {
	int	s;
	void *	buf;
	size_t	len;
	int	flags;
	void *	to;
	int	tolen;
};

struct auditinfo_addr {
	/*
	4	ai_auid;
	8	ai_mask;
	24	ai_termid;
	4	ai_asid;
	8	ai_flags;r
	*/
	char useless[184];
};

//struct ucred {
//	u_int	cr_ref;			/* reference count */
//	uid_t	cr_uid;			/* effective user id */
//	uid_t	cr_ruid;		/* real user id */
//	uid_t	cr_svuid;		/* saved user id */
//	int	cr_ngroups;		/* number of groups */
//	gid_t	cr_rgid;		/* real group id */
//	gid_t	cr_svgid;		/* saved group id */
//	struct uidinfo	*cr_uidinfo;	/* per euid resource consumption */
//	struct uidinfo	*cr_ruidinfo;	/* per ruid resource consumption */
//	struct prison	*cr_prison;	/* jail(2) */
//	struct loginclass	*cr_loginclass; /* login class */
//	u_int		cr_flags;	/* credential flags */
//	void 		*cr_pspare2[2];	/* general use 2 */
//	struct label	*cr_label;	/* MAC label */
//	struct auditinfo_addr	cr_audit;	/* Audit properties. */
//	gid_t	*cr_groups;		/* groups */
//	int	cr_agroups;		/* Available groups */
//};

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

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

struct fileops {
	void	*fo_read;
	void	*fo_write;
	void	*fo_truncate;
	void	*fo_ioctl;
	void	*fo_poll;
	void	*fo_kqfilter;
	void	*fo_stat;
	void	*fo_close;
	void	*fo_chmod;
	void	*fo_chown;
	int	fo_flags;	/* DFLAG_* below */
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct kpayload_args{
	uint64_t user_arg;
};

struct kdump_args{
    	uint64_t argArrayPtr;
};

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}

