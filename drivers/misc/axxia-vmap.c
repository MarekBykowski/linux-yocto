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
#include <asm/cacheflush.h>

void __iomem *expender_virt_addr;
size_t expender_virt_size = SZ_2M;

static int
axxia_oem_init(void)
{
	phys_addr_t phys_addr = 0x0018000000ULL;

	unsigned long addr;

	int err = 0;
	size_t psize = SZ_4K;
	struct vm_struct *area;
	unsigned long offset = phys_addr & ~PAGE_MASK;

	/*
	 * Page align the mapping address and size, taking account of any
	 * offset.
	 */
	phys_addr &= PAGE_MASK;
	expender_virt_size = PAGE_ALIGN(expender_virt_size + offset);

	area = get_vm_area(expender_virt_size, VM_IOREMAP);
	if (!area)
		return err;

	addr = (unsigned long)area->addr;
	area->phys_addr = phys_addr;

	err = ioremap_page_range(addr, addr + psize, phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE));
	if (err) {
		vunmap((void *)addr);
		return err;
	}

	err = ioremap_page_range(addr + 10 * PAGE_SIZE, addr +
				 10 * PAGE_SIZE + psize, phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE));
	if (err) {
		vunmap((void *)addr);
		return err;
	}

	expender_virt_addr = (void __iomem *)(offset + addr);

	pr_info("mb: %s() called from %pS\n", __func__, (void *) _RET_IP_);
	pr_info("mb: VMALLOC_START-VMALLOC_END: %lx-%lx\n", VMALLOC_START,
		VMALLOC_END);
	pr_info("mb: VA start-end: %lx-%lx PA start-end: %pap-%lx\n",
		addr, addr + expender_virt_size, &phys_addr,
		(unsigned long)phys_addr + psize);
	pr_info("mb: VA %pS - PA %pap\n", expender_virt_addr, &phys_addr);

	/* Write to mapped VA */
	writel(0xdeadbeef, (void *)addr);

	/*__asm__ volatile("b .\n");*/

	/* Write to unmapped VA -> MMU fault */
	writel(0xdeadbeef, (void *)(addr + 0x4000));

	return err;
}

device_initcall(axxia_oem_init);

MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Axxia OEM Control");
