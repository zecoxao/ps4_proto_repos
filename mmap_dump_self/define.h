#include <kernel.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct knote {
	SLIST_ENTRY(knote)	kn_link;
	SLIST_ENTRY(knote)	kn_selnext;
	struct			knlist *kn_knlist;
	TAILQ_ENTRY(knote)	kn_tqe;
	struct			kqueue *kn_kq;
	struct 			kevent kn_kevent;
	int			kn_status;
#define KN_ACTIVE	0x01
#define KN_QUEUED	0x02
#define KN_DISABLED	0x04
#define KN_DETACHED	0x08
#define KN_INFLUX	0x10
#define KN_MARKER	0x20
#define KN_KQUEUE	0x40
#define KN_HASKQLOCK	0x80
#define	KN_SCAN		0x100
	int			kn_sfflags;
	intptr_t		kn_sdata;
	union {
		struct		file *p_fp;
		struct		proc *p_proc;
		struct		aiocblist *p_aio;
		struct		aioliojob *p_lio;
	} kn_ptr;
	struct			filterops *kn_fop;
	void			*kn_hook;
	int			kn_hookid;

#define kn_id		kn_kevent.ident
#define kn_filter	kn_kevent.filter
#define kn_flags	kn_kevent.flags
#define kn_fflags	kn_kevent.fflags
#define kn_data		kn_kevent.data
#define kn_fp		kn_ptr.p_fp
};

struct filterops {
	int	f_isfd;
	int(*f_attach)(struct knote *kn);
	void(*f_detach)(struct knote *kn);
	int(*f_event)(struct knote *kn, long hint);
	void(*f_touch)(struct knote *kn, struct kevent *kev, u_long type);
};

struct in6_addr {
	union {
		uint8_t		__u6_addr8[16];
		uint16_t	__u6_addr16[8];
		uint32_t	__u6_addr32[4];
	} __u6_addr;
};

struct sockaddr_in6 {
	uint8_t		sin6_len;
	sa_family_t	sin6_family;
	in_port_t	sin6_port;
	uint32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
	uint32_t	sin6_scope_id;
};

struct route_in6 {
	struct	rtentry *ro_rt;
	struct	llentry *ro_lle;
	struct	in6_addr *ro_ia6;
	int		ro_flags;
	struct	sockaddr_in6 ro_dst;
};

struct ip6_rthdr {
	u_int8_t  ip6r_nxt;
	u_int8_t  ip6r_len;
	u_int8_t  ip6r_type;
	u_int8_t  ip6r_segleft;
} __packed;

struct in6_pktinfo {
	struct in6_addr	ipi6_addr;
	unsigned int	ipi6_ifindex;
};

struct ip6po_nhinfo {
	struct	sockaddr *ip6po_nhi_nexthop;
	struct	route_in6 ip6po_nhi_route;
};

struct ip6po_rhinfo {
	struct	ip6_rthdr *ip6po_rhi_rthdr;
	struct	route_in6 ip6po_rhi_route;
};

struct ip6_pktopts {
	struct	mbuf *ip6po_m;
	int	ip6po_hlim;

	struct	in6_pktinfo *ip6po_pktinfo;
	struct	ip6po_nhinfo ip6po_nhinfo;
	struct	ip6_hbh *ip6po_hbh;
	struct	ip6_dest *ip6po_dest1;

	struct	ip6po_rhinfo ip6po_rhinfo;
	struct	ip6_dest *ip6po_dest2;

	int	ip6po_tclass;

	int	ip6po_minmtu;
#define IP6PO_MINMTU_MCASTONLY	-1
#define IP6PO_MINMTU_DISABLE	 0
#define IP6PO_MINMTU_ALL	 1

	int	ip6po_prefer_tempaddr;

#define IP6PO_TEMPADDR_SYSTEM	-1
#define IP6PO_TEMPADDR_NOTPREFER 0
#define IP6PO_TEMPADDR_PREFER	 1

	int ip6po_flags;
#if 0
#define IP6PO_REACHCONF	0x01
#define IP6PO_MINMTU	0x02
#endif
#define IP6PO_DONTFRAG	0x04
#define IP6PO_USECOA	0x08
};

struct lock_object {
	const	char *lo_name;
	u_int	lo_flags;
	u_int	lo_data;
	struct	witness *lo_witness;
};

struct mtx {
	struct lock_object	lock_object;
	volatile uintptr_t	mtx_lock;
};

struct sx {
	struct lock_object	lock_object;
	volatile uintptr_t	sx_lock;
};

struct rwlock {
	struct lock_object	lock_object;
	volatile uintptr_t	rw_lock;
};

struct selfd {
	STAILQ_ENTRY(selfd)	sf_link;
	TAILQ_ENTRY(selfd)	sf_threads;
	struct selinfo		*sf_si;
	struct mtx		*sf_mtx;
	struct seltd		*sf_td;
	void			*sf_cookie;
};
TAILQ_HEAD(selfdlist, selfd);

struct selinfo {
	struct selfdlist	si_tdlist;
	struct knlist		si_note;
	struct mtx		*si_mtx;
};

struct	sockbuf {
	struct	selinfo sb_sel;
	struct	mtx sb_mtx;
	struct	sx sb_sx;
	short	sb_state;
#define	sb_startzero	sb_mb
	struct	mbuf *sb_mb;
	struct	mbuf *sb_mbtail;
	struct	mbuf *sb_lastrecord;

	struct	mbuf *sb_sndptr;
	u_int	sb_sndptroff;
	u_int	sb_cc;
	u_int	sb_hiwat;
	u_int	sb_mbcnt;
	u_int   sb_mcnt;
	u_int   sb_ccnt;
	u_int	sb_mbmax;
	u_int	sb_ctl;
	int	sb_lowat;
	int	sb_timeo;
	short sb_flags;
	int(*sb_upcall)(struct socket *, void *, int);
	void	*sb_upcallarg;
};

typedef u_quad_t so_gen_t;

struct socket {
	int	so_count;
	short	so_type;
	short	so_options;
	short	so_linger;
	short	so_state;
	int	so_qstate;
	void	*so_pcb;
	struct	vnet *so_vnet;
	struct	protosw *so_proto;
	struct	socket *so_head;
	TAILQ_HEAD(, socket) so_incomp;
	TAILQ_HEAD(, socket) so_comp;
	TAILQ_ENTRY(socket) so_list;
	u_short	so_qlen;
	u_short	so_incqlen;
	u_short	so_qlimit;
	short	so_timeo;
	u_short	so_error;
	struct	sigio *so_sigio;
	u_long	so_oobmark;
	TAILQ_HEAD(, aiocblist) so_aiojobq;

	struct sockbuf so_rcv, so_snd;

	struct	ucred *so_cred;
	struct	label *so_label;
	struct	label *so_peerlabel;
	so_gen_t so_gencnt;
	void	*so_emuldata;
	struct so_accf {
		struct	accept_filter *so_accept_filter;
		void	*so_accept_filter_arg;
		char	*so_accept_filter_str;
	} *so_accf;

	int so_fibnum;
	uint32_t so_user_cookie;
};

typedef	u_quad_t	inp_gen_t;

struct in_addr_4in6 {
	u_int32_t	ia46_pad32[3];
	struct	in_addr	ia46_addr4;
};

struct in_endpoints {
	u_int16_t	ie_fport;
	u_int16_t	ie_lport;

	union {
		struct	in_addr_4in6 ie46_foreign;
		struct	in6_addr ie6_foreign;
	} ie_dependfaddr;
	union {
		struct	in_addr_4in6 ie46_local;
		struct	in6_addr ie6_local;
	} ie_dependladdr;
};

struct in_conninfo {
	u_int8_t	inc_flags;
	u_int8_t	inc_len;
	u_int16_t	inc_fibnum;
	struct	in_endpoints inc_ie;
};

struct inpcb {
	LIST_ENTRY(inpcb) inp_hash;
	LIST_ENTRY(inpcb) inp_pcbgrouphash;
	LIST_ENTRY(inpcb) inp_list;
	void	*inp_ppcb;
	struct	inpcbinfo *inp_pcbinfo;
	struct	inpcbgroup *inp_pcbgroup;
	LIST_ENTRY(inpcb) inp_pcbgroup_wild;
	struct	socket *inp_socket;
	struct	ucred	*inp_cred;
	u_int32_t inp_flow;
	int	inp_flags;
	int	inp_flags2;
	u_char	inp_vflag;
	u_char	inp_ip_ttl;
	u_char	inp_ip_p;
	u_char	inp_ip_minttl;
	uint32_t inp_flowid;
	u_int	inp_refcount;
	void	*inp_pspare[5];
	u_int	inp_ispare[6];

	struct	in_conninfo inp_inc;

	struct	label *inp_label;
	struct	inpcbpolicy *inp_sp;

	struct {
		u_char	inp4_ip_tos;
		struct	mbuf *inp4_options;
		struct	ip_moptions *inp4_moptions;
	} inp_depend4;
	struct {
		struct	mbuf *inp6_options;
		struct	ip6_pktopts *inp6_outputopts;
		struct	ip6_moptions *inp6_moptions;
		struct	icmp6_filter *inp6_icmp6filt;
		int	inp6_cksum;
		short	inp6_hops;
	} inp_depend6;
	LIST_ENTRY(inpcb) inp_portlist;
	struct	inpcbport *inp_phd;
#define inp_zero_size offsetof(struct inpcb, inp_gencnt)
	inp_gen_t	inp_gencnt;
	struct llentry	*inp_lle;
	struct rtentry	*inp_rt;
	struct rwlock	inp_lock;
};

#define	in6p_outputopts	inp_depend6.inp6_outputopts

#define NDSLOTTYPE	u_long

struct filedesc {
	struct	file **fd_ofiles;
	char	*fd_ofileflags;
	struct	vnode *fd_cdir;
	struct	vnode *fd_rdir;
	struct	vnode *fd_jdir;
	int	fd_nfiles;
	NDSLOTTYPE *fd_map;
	int	fd_lastfile;
	int	fd_freefile;
	u_short	fd_cmask;
	u_short	fd_refcnt;
	u_short	fd_holdcnt;
	struct	sx fd_sx;
	struct	kqlist fd_kqlist;
	int	fd_holdleaderscount;
	int	fd_holdleaderswakeup;
};

struct file {
	void* f_data;
	struct fileops	*f_ops;
	struct ucred	*f_cred;
	struct vnode 	*f_vnode;
	short		f_type;
	short		f_vnread_flags;
	volatile u_int	f_flag;
	volatile u_int 	f_count;

	int		f_seqcount;
	off_t		f_nextoff;
	struct cdev_privdata *f_cdevpriv;
	off_t		f_offset;

	void		*f_label;

	void *f_iosched_priority;
	void *f_mdbg_data;
	int             f_budid;
};

struct callout {
	union {
		SLIST_ENTRY(callout) sle;
		TAILQ_ENTRY(callout) tqe;
	} c_links;
	int	c_time;
	void	*c_arg;
	void(*c_func)(void *);
	struct lock_object *c_lock;
	int	c_flags;
	volatile int c_cpu;
};

struct ucred {
	int	cr_ref;
	int	cr_uid;
	int	cr_ruid;
	int	cr_svuid;
	int	cr_ngroups;
	int	cr_rgid;
	char 	unk1[24];
	uint64_t	*cr_prison;
	char 	unk2[224];
	int	*cr_groups;
	int	cr_agroups;
};

struct proc {
	LIST_ENTRY(proc) p_list;
	TAILQ_HEAD(, thread) p_threads;
	struct mtx	p_slock;
	struct ucred	*p_ucred;
	struct filedesc	*p_fd;
	struct filedesc_to_leader *p_fdtol;
	struct pstats	*p_stats;
	struct plimit	*p_limit;
	struct callout	p_limco;
	struct sigacts	*p_sigacts;

	int		p_flag;
	enum {
		PRS_NEW = 0,
		PRS_NORMAL,
		PRS_ZOMBIE
	} p_state;
	pid_t		p_pid;
};

struct thread {
	void *unk1;
	struct proc *td_proc;
	char unk2[288];
	struct ucred *td_ucred;
};
