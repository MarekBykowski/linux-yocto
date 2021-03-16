// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2018 INTEL

/*
 * ===========================================================================
 * ===========================================================================
 * Private
 * ===========================================================================
 * ===========================================================================
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

static struct vm_struct *area_expender;

static phys_addr_t phys_addr = 0x0018000000ULL;
#define PSIZE (PAGE_SIZE)
#define VSIZE (SZ_2M)

LIST_HEAD(expdr_unmapped);
LIST_HEAD(expdr_mapped);

struct expdr_window {
	unsigned long addr;
	struct list_head list;
};

static int __expender_map(unsigned long addr,
			  unsigned int esr,
			  struct pt_regs *regs)
{
	int err = 0;
	bool found = false;
	struct expdr_window *mapped, *p, *tmp;

#if 0
	if (false)
		mem_abort_decode(esr);
#endif

	pr_info("expdr: unable to handle paging request at VA %016lx\n", addr);

	/* Page align the mapping address */
	addr &= PAGE_MASK;

	/* Unmap the mapped area */
	list_for_each_entry_safe(p, tmp, &expdr_mapped, list) {
		unmap_kernel_range_noflush(p->addr, PAGE_SIZE);
		list_move_tail(&p->list, &expdr_unmapped);
	}

	/* If the newly reqested area is on the unmapped move to the mapped */
	list_for_each_entry_safe(p, tmp, &expdr_unmapped, list) {
		if (p->addr == addr) {
			list_move_tail(&p->list, &expdr_mapped);
			found = true;
		}
	}

	/* If not on the mapped, create the area and add to the list */
	if (found == false) {
		mapped = kzalloc(sizeof(*mapped), GFP_KERNEL);
		mapped->addr = addr;
		list_add(&mapped->list, &expdr_mapped);
	}

	/* and map */
	err = ioremap_page_range(addr, addr + PSIZE,
				 area_expender->phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE));
	if (err) {
		unmap_kernel_range_noflush(addr, PAGE_SIZE);
		err = -ENOMEM;
		goto expdr_error;
	}

{
	struct expdr_window *p;

	pr_info("expdr: mapped: ");
	list_for_each_entry(p, &expdr_mapped, list) {
		pr_cont("%lx ", p->addr);
	}
	pr_info("expdr: unmapped: ");
	list_for_each_entry(p, &expdr_unmapped, list) {
		pr_cont("%lx ", p->addr);
	}
	pr_cont("\n");
}

expdr_error:
	return err;
}

int expender_map(unsigned long addr,
	      unsigned int esr,
	      struct pt_regs *regs)
{
	if (addr >= (unsigned long)area_expender->addr &&
	    addr < ((size_t)area_expender->addr + area_expender->size))
		return __expender_map(addr, esr, regs);

	return -1;
}

static int expender_init(void)
{
	unsigned long addr;
	int err = 0;

	phys_addr &= PAGE_MASK;
	area_expender = get_vm_area(VSIZE, VM_IOREMAP);
	area_expender->phys_addr = phys_addr;

	pr_info("expdr: reserve VM %pS-%zx from VMALLOC area (%lx-%lx)\n",
		area_expender->addr,
		(size_t)area_expender->addr + area_expender->size,
		VMALLOC_START, VMALLOC_END);
	pr_info("expdr: VA is reserved for PA %pap-%zx\n",
		&area_expender->phys_addr,
		(size_t)area_expender->phys_addr + PSIZE);

#define TEST 0
#if TEST
	ioremap_page_range((unsigned long)area_expender->addr,
			   (unsigned long)(area_expender->addr + PAGE_SIZE),
			   area_expender->phys_addr,
			   __pgprot(PROT_DEVICE_nGnRE));
	unmap_kernel_range_noflush((unsigned long)area_expender->addr,
				   PAGE_SIZE);
#endif

#if 1
{
	int i = 0;

	for (; i < 1; i++) {
		pr_info("expdr: loop %d\n", i);
		addr = (unsigned long)area_expender->addr;
		writel(0xdeadbeef, (void *)addr);
		writel(0xdeadbeef, (void *)(addr + 0x3000ULL));
		writel(0xdeadbeef, (void *)addr);
	}
}
#endif

	return err;
}

device_initcall(expender_init);

MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Expender mapping");
