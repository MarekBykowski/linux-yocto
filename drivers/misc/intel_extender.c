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
#include <linux/seq_file.h>

static struct vm_struct *area_expender;
static void __iomem *base;

/* MMU and Span Extender defines */
#define VSIZE			(SZ_2M)
#define EXTENDER_BASE		0x90000000UL
#define EXTENDER_SIZE		(PAGE_SIZE)

#define EXTENDER_CTRL_BASE	0xF9000000UL
#define EXTENDER_CTRL_CSR	0x2000

LIST_HEAD(expdr_unmapped);
LIST_HEAD(expdr_mapped);

struct expdr_window {
	unsigned long addr;
	struct list_head list;
};

static unsigned long expdr_offset = 0x0;

static int __expender_map(unsigned long addr,
			  unsigned int esr,
			  struct pt_regs *regs)
{
	int err = 0;
	bool found = false;
	struct expdr_window *mapped, *p, *tmp;
	unsigned long offset;

#if 0
	if (false)
		mem_abort_decode(esr);
#endif

	pr_info("expdr: unable to handle paging request at VA %016lx\n", addr);

	/* Page align the mapping address */
	addr &= PAGE_MASK;

	/* Unmap the mapped area */
	list_for_each_entry_safe(p, tmp, &expdr_mapped, list) {
		/*unmap_kernel_range_noflush(p->addr, PAGE_SIZE);*/
		unmap_kernel_range(p->addr, PAGE_SIZE);
		list_move_tail(&p->list, &expdr_unmapped);
	}

	/*
	 * If the newly reqested area is on the unmapped list move it
	 * to the mapped.
	 */
	list_for_each_entry_safe(p, tmp, &expdr_unmapped, list) {
		if (p->addr == addr) {
			list_move_tail(&p->list, &expdr_mapped);
			found = true;
		}
	}

	/*
	 * If the area is not on the mapped, create it and add it to
	 * the mapped list.
	 */
	if (found == false) {
		mapped = kzalloc(sizeof(*mapped), GFP_KERNEL);
		mapped->addr = addr;
		list_add(&mapped->list, &expdr_mapped);
	}

	/* Map the area */
	err = ioremap_page_range(addr, addr + EXTENDER_SIZE,
				 area_expender->phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE));
	if (err) {
		unmap_kernel_range_noflush(addr, PAGE_SIZE);
		err = -ENOMEM;
		goto expdr_error;
	}

	offset = addr - (unsigned long)area_expender->addr;
	pr_info("expdr: offset %lx\n", offset);
	/* Steer Span Extender */
	if (offset == 0) {
		pr_info("expdr: steer to low\n");
		writeq(0x0, base + EXTENDER_CTRL_CSR);
	} else if (offset == 0x1000) {
		pr_info("expdr: steer to mid\n");
		writeq(0x4000000000, base + EXTENDER_CTRL_CSR);
	} else if (offset == 0x2000) {
		pr_info("expdr: steer to high\n");
		writeq(0x8000000000, base + EXTENDER_CTRL_CSR);
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

/*
 * Use procfs to read/write from/to the area extender exposes
 */


static ssize_t expdr_offset_read(struct file *filp, char *buffer, size_t length,
		      loff_t *offset)
{
	char buf[80];
	int len = 0;

	if (*offset > 0 || length < 80)
		return 0;

	len += sprintf(buf, "%lx\n", expdr_offset);

	if (copy_to_user(buffer, buf, len))
		return -EFAULT;

	*offset = len;

	return len;
}

static ssize_t expdr_offset_write(struct file *file, const char __user *buffer,
		   size_t count, loff_t *ppos)
{
	char *input;
	unsigned int new_expdr_offset;
	int rc;
	unsigned long res;

	if (!buffer)
		return -EINVAL;

	input = kmalloc(count + 1, GFP_KERNEL);

	if (!input)
		return -ENOSPC;

	rc = copy_from_user(input, buffer, count);

	if (rc) {
		kfree(input);
		return -EFAULT;
	}

	input[count] = 0;
	rc = kstrtoul(input, 0, &res);

	if (rc) {
		kfree(input);
		return rc;
	}

	new_expdr_offset = (unsigned int)res;
	expdr_offset = (unsigned int)new_expdr_offset;
	kfree(input);

	return count;
}

static const struct file_operations expdr_offset_proc_ops = {
	.read	    = expdr_offset_read,
	.write	    = expdr_offset_write,
	.llseek     = noop_llseek,
};

static ssize_t expdr_value_read(struct file *filp, char *buffer, size_t length,
		     loff_t *offset)
{
	char buf[80];
	int len = 0;

	if (*offset > 0 || length < 80)
		return 0;

	len += sprintf(buf, "%x\n",
		       readl((void __iomem *)
		       ((unsigned long)area_expender->addr + expdr_offset)));

	if (copy_to_user(buffer, buf, len))
		return -EFAULT;

	*offset = len;

	return len;
}

static ssize_t expdr_value_write(struct file *file, const char __user *buffer,
		  size_t count, loff_t *ppos)
{
	char *input;
	int rc;
	unsigned int res;

	input = kmalloc(count + 1, __GFP_RECLAIMABLE);

	if (!input)
		return -ENOSPC;

	if (copy_from_user(input, buffer, count)) {
		kfree(input);
		return -EFAULT;
	}

	input[count] = '\0';
	rc = kstrtou32(input, 0, &res);

	if (rc) {
		kfree(input);
		return rc;
	}

	writel(res, (void __iomem *)
	       ((unsigned long)area_expender->addr + expdr_offset));

	kfree(input);

	return count;
}

static const struct file_operations expdr_value_proc_ops = {
	.read	    = expdr_value_read,
	.write	    = expdr_value_write,
	.llseek     = noop_llseek,
};


static int expender_init(void)
{
	unsigned long addr __maybe_unused;
	int err = 0;
	phys_addr_t phys_addr = (phys_addr_t)EXTENDER_BASE;

	phys_addr &= PAGE_MASK;
	area_expender = get_vm_area(VSIZE, VM_IOREMAP | VM_NO_GUARD);
	area_expender->phys_addr = phys_addr;

	base = ioremap(EXTENDER_CTRL_BASE, SZ_2M);
	pr_info("expdr: mapped %lx + %x to base %pS\n",
		EXTENDER_CTRL_BASE, (unsigned)SZ_2M, base);

	pr_info("expdr: reserve VA area %pS-0x%zx (size 0x%lx) from VMALLOC area 0x%lx-0x%lx\n",
		area_expender->addr,
		(size_t)area_expender->addr + area_expender->size,
		area_expender->size,
		VMALLOC_START, VMALLOC_END);
	pr_info("expdr: VA is reserved for PA %pap-0x%zx\n",
		&area_expender->phys_addr,
		(size_t)area_expender->phys_addr + EXTENDER_SIZE);

#if 0
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
	if (proc_create("driver/expdr_offset", 0200, NULL,
			&expdr_offset_proc_ops) == NULL) {
		pr_err("Could not create /proc/driver/expdr_offset!\n");
		err = -EFAULT;
	} else if (proc_create("driver/expdr_value", 0200, NULL,
			       &expdr_value_proc_ops) == NULL) {
		pr_err("Could not create /proc/driver/expdr_value!\n");
		err = -EFAULT;
	}


	return err;
}

device_initcall(expender_init);

MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Extender mapping");
