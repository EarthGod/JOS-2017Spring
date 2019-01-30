// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800
extern void _pgfault_upcall(void);
//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if ((err & FEC_WR) == 0)
		panic("pgfault: address??? [%08x]\n", addr);

	void* page_aligned_addr = (void*)ROUNDDOWN(addr, PGSIZE);
	uint32_t page_num = (uint32_t)page_aligned_addr / PGSIZE;
	if (!(uvpt[page_num] & PTE_COW))
		panic("pgfault: fault was not on a copy-on-write page\n");
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.

	//panic("pgfault not implemented");
	if ((r = sys_page_alloc(0, PFTEMP, PTE_P | PTE_U | PTE_W)) < 0)
		panic("sys_page_alloc: %e\n", r);

	void* src_addr = (void*)ROUNDDOWN(addr, PGSIZE);
	memmove(PFTEMP, src_addr, PGSIZE);

	if ((r = sys_page_map(0, PFTEMP, 0, src_addr, PTE_P | PTE_U | PTE_W)) < 0)
		panic("sys_page_map: %e\n", r);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	//panic("duppage not implemented");

	uint32_t perm = PTE_P | PTE_COW;
	envid_t this_envid = thisenv->env_id;

	// LAB 4: Your code here.
	if (uvpt[pn] & PTE_SHARE){
		if ((r = sys_page_map(this_envid, (void*)(pn*PGSIZE), envid, (void*)(pn*PGSIZE), uvpt[pn] & PTE_SYSCALL)) < 0)
			panic("sys_page_map: %e\n", r);
	}
	else if (uvpt[pn] & PTE_COW || uvpt[pn] & PTE_W){
		if (uvpt[pn] & PTE_U)
			perm |= PTE_U;

		if ((r = sys_page_map(this_envid, (void*)(pn * PGSIZE), envid, (void*)(pn * PGSIZE), perm)) < 0)
			panic("sys_page_map: %e\n", r);

		if ((r = sys_page_map(this_envid, (void*)(pn * PGSIZE), this_envid, (void*)(pn * PGSIZE), perm)) < 0)
			panic("sys_page_map: %e\n", r);

	}
	else{
		if((r = sys_page_map(this_envid, (void*)(pn * PGSIZE), envid, (void*)(pn * PGSIZE), uvpt[pn] & PTE_SYSCALL)) < 0)
			panic("sys_page_map: %e\n", r);
	}
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	//panic("fork not implemented");
	int r;
	envid_t child_envid;

	set_pgfault_handler(pgfault);

	child_envid = sys_exofork();
	if (child_envid < 0)
		panic("sys_exofork: %e\n", child_envid);
	if (child_envid == 0){
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	pte_t *pte;
	for (int page_num = 0; page_num < PGNUM(UTOP - PGSIZE); ++page_num){
		uint32_t pdx = ROUNDDOWN(page_num, NPDENTRIES) / NPDENTRIES;
		if ((uvpd[pdx] & PTE_P) == PTE_P && ((uvpt[page_num] & PTE_P) == PTE_P))
				duppage(child_envid, page_num);
	}

	if ((r = sys_page_alloc(child_envid, (void*)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W)) < 0)
		panic("sys_page_alloc: %e\n", r);
	if ((r = sys_env_set_pgfault_upcall(child_envid, _pgfault_upcall)) < 0)
		panic("sys_env_set_pgfault_upcall: %e\n", r);
	if ((r = sys_env_set_status(child_envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e\n", r);

	return child_envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
