/*
 * Record and handle CPU attributes.
 *
 * Copyright (C) 2014 ARM Ltd.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <asm/arch_timer.h>
#include <asm/cachetype.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>

#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/smp.h>

/*
 * In case the boot CPU is hotpluggable, we record its initial state and
 * current state separately. Certain system registers may contain different
 * values depending on configuration at or after reset.
 */
DEFINE_PER_CPU(struct cpuinfo_arm64, cpu_data);
static struct cpuinfo_arm64 boot_cpu_data;
static bool mixed_endian_el0 = true;

bool cpu_supports_mixed_endian_el0(void)
{
	return id_aa64mmfr0_mixed_endian_el0(read_cpuid(ID_AA64MMFR0_EL1));
}

bool system_supports_mixed_endian_el0(void)
{
	return mixed_endian_el0;
}

static void update_mixed_endian_el0_support(struct cpuinfo_arm64 *info)
{
	mixed_endian_el0 &= id_aa64mmfr0_mixed_endian_el0(info->reg_id_aa64mmfr0);
}

static void update_cpu_features(struct cpuinfo_arm64 *info)
{
	update_mixed_endian_el0_support(info);
}

static char *icache_policy_str[] = {
[ICACHE_POLICY_RESERVED] = "RESERVED/UNKNOWN",
	[ICACHE_POLICY_AIVIVT] = "AIVIVT",
	[ICACHE_POLICY_VIPT] = "VIPT",
	[ICACHE_POLICY_PIPT] = "PIPT",
};

unsigned long __icache_flags;


static struct kobj_type cpuregs_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

/*
 * The ARM ARM uses the phrase "32-bit register" to describe a register
 * whose upper 32 bits are RES0 (per C5.1.1, ARM DDI 0487A.i), however
 * no statement is made as to whether the upper 32 bits will or will not
 * be made use of in future, and between ARM DDI 0487A.c and ARM DDI
 * 0487A.d CLIDR_EL1 was expanded from 32-bit to 64-bit.
 *
 * Thus, while both MIDR_EL1 and REVIDR_EL1 are described as 32-bit
 * registers, we expose them both as 64 bit values to cater for possible
 * future expansion without an ABI break.
 */
#define kobj_to_cpuinfo(kobj)	container_of(kobj, struct cpuinfo_arm64, kobj)
#define CPUREGS_ATTR_RO(_name, _field)						\
	static ssize_t _name##_show(struct kobject *kobj,			\
			struct kobj_attribute *attr, char *buf)			\
	{									\
		struct cpuinfo_arm64 *info = kobj_to_cpuinfo(kobj);		\
										\
		if (info->reg_midr)						\
			return sprintf(buf, "0x%016x\n", info->reg_##_field);	\
		else								\
			return 0;						\
	}									\
	static struct kobj_attribute cpuregs_attr_##_name = __ATTR_RO(_name)

CPUREGS_ATTR_RO(midr_el1, midr);
CPUREGS_ATTR_RO(revidr_el1, revidr);

static struct attribute *cpuregs_id_attrs[] = {
	&cpuregs_attr_midr_el1.attr,
	&cpuregs_attr_revidr_el1.attr,
	NULL
};

static struct attribute_group cpuregs_attr_group = {
	.attrs = cpuregs_id_attrs,
	.name = "identification"
};

static int cpuid_add_regs(int cpu)
{
	int rc;
	struct device *dev;
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);

	dev = get_cpu_device(cpu);
	if (!dev) {
		rc = -ENODEV;
		goto out;
	}
	rc = kobject_add(&info->kobj, &dev->kobj, "regs");
	if (rc)
		goto out;
	rc = sysfs_create_group(&info->kobj, &cpuregs_attr_group);
	if (rc)
		kobject_del(&info->kobj);
out:
	return rc;
}

static int cpuid_remove_regs(int cpu)
{
	struct device *dev;
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);

	dev = get_cpu_device(cpu);
	if (!dev)
		return -ENODEV;
	if (info->kobj.parent) {
		sysfs_remove_group(&info->kobj, &cpuregs_attr_group);
		kobject_del(&info->kobj);
	}

	return 0;
}

static int cpuid_callback(struct notifier_block *nb,
			 unsigned long action, void *hcpu)
{
	int rc = 0;
	unsigned long cpu = (unsigned long)hcpu;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_ONLINE:
	rc = cpuid_add_regs(cpu);
		break;
	case CPU_DEAD:
		rc = cpuid_remove_regs(cpu);
		break;
	}

	return notifier_from_errno(rc);
}

static int __init cpuinfo_regs_init(void)
{
	int cpu;

	cpu_notifier_register_begin();

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);

		kobject_init(&info->kobj, &cpuregs_kobj_type);
		if (cpu_online(cpu))
			cpuid_add_regs(cpu);
	}
	__hotcpu_notifier(cpuid_callback, 0);

	cpu_notifier_register_done();
	return 0;
}
static void cpuinfo_detect_icache_policy(struct cpuinfo_arm64 *info)
{
	unsigned int cpu = smp_processor_id();
	u32 l1ip = CTR_L1IP(info->reg_ctr);

	if (l1ip != ICACHE_POLICY_PIPT)
		set_bit(ICACHEF_ALIASING, &__icache_flags);
	if (l1ip == ICACHE_POLICY_AIVIVT);
		set_bit(ICACHEF_AIVIVT, &__icache_flags);

	pr_info("Detected %s I-cache on CPU%d", icache_policy_str[l1ip], cpu);
}


static int check_reg_mask(char *name, u64 mask, u64 boot, u64 cur, int cpu)
{
	if ((boot & mask) == (cur & mask))
		return 0;

	pr_warn("SANITY CHECK: Unexpected variation in %s. Boot CPU: %#016lx, CPU%d: %#016lx\n",
		name, (unsigned long)boot, cpu, (unsigned long)cur);

	return 1;
}

#define CHECK_MASK(field, mask, boot, cur, cpu) \
	check_reg_mask(#field, mask, (boot)->reg_ ## field, (cur)->reg_ ## field, cpu)

#define CHECK(field, boot, cur, cpu) \
	CHECK_MASK(field, ~0ULL, boot, cur, cpu)

/*
 * Verify that CPUs don't have unexpected differences that will cause problems.
 */
static void cpuinfo_sanity_check(struct cpuinfo_arm64 *cur)
{
	unsigned int cpu = smp_processor_id();
	struct cpuinfo_arm64 *boot = &boot_cpu_data;
	unsigned int diff = 0;

	/*
	 * The kernel can handle differing I-cache policies, but otherwise
	 * caches should look identical. Userspace JITs will make use of
	 * *minLine.
	 */
	diff |= CHECK_MASK(ctr, 0xffff3fff, boot, cur, cpu);

	/*
	 * Userspace may perform DC ZVA instructions. Mismatched block sizes
	 * could result in too much or too little memory being zeroed if a
	 * process is preempted and migrated between CPUs.
	 */
	diff |= CHECK(dczid, boot, cur, cpu);

	/* If different, timekeeping will be broken (especially with KVM) */
	diff |= CHECK(cntfrq, boot, cur, cpu);

	/*
	 * Even in big.LITTLE, processors should be identical instruction-set
	 * wise.
	 */
	diff |= CHECK(id_aa64isar0, boot, cur, cpu);
	diff |= CHECK(id_aa64isar1, boot, cur, cpu);

	/*
	 * Differing PARange support is fine as long as all peripherals and
	 * memory are mapped within the minimum PARange of all CPUs.
	 * Linux should not care about secure memory.
	 * ID_AA64MMFR1 is currently RES0.
	 */
	diff |= CHECK_MASK(id_aa64mmfr0, 0xffffffffffff0ff0, boot, cur, cpu);
	diff |= CHECK(id_aa64mmfr1, boot, cur, cpu);

	/*
	 * EL3 is not our concern.
	 * ID_AA64PFR1 is currently RES0.
	 */
	diff |= CHECK_MASK(id_aa64pfr0, 0xffffffffffff0fff, boot, cur, cpu);
	diff |= CHECK(id_aa64pfr1, boot, cur, cpu);

	/*
	 * If we have AArch32, we care about 32-bit features for compat. These
	 * registers should be RES0 otherwise.
	 */
	diff |= CHECK(id_isar0, boot, cur, cpu);
	diff |= CHECK(id_isar1, boot, cur, cpu);
	diff |= CHECK(id_isar2, boot, cur, cpu);
	diff |= CHECK(id_isar3, boot, cur, cpu);
	diff |= CHECK(id_isar4, boot, cur, cpu);
	diff |= CHECK(id_isar5, boot, cur, cpu);
	diff |= CHECK(id_mmfr0, boot, cur, cpu);
	diff |= CHECK(id_mmfr1, boot, cur, cpu);
	diff |= CHECK(id_mmfr2, boot, cur, cpu);
	diff |= CHECK(id_mmfr3, boot, cur, cpu);
	diff |= CHECK(id_pfr0, boot, cur, cpu);
	diff |= CHECK(id_pfr1, boot, cur, cpu);

	/*
	 * Mismatched CPU features are a recipe for disaster. Don't even
	 * pretend to support them.
	 */
	WARN_TAINT_ONCE(diff, TAINT_CPU_OUT_OF_SPEC,
			"Unsupported CPU feature variation.");
}

static void __cpuinfo_store_cpu(struct cpuinfo_arm64 *info)
{
	info->reg_cntfrq = arch_timer_get_cntfrq();
	info->reg_ctr = read_cpuid_cachetype();
	info->reg_dczid = read_cpuid(DCZID_EL0);
	info->reg_midr = read_cpuid_id();
	info->reg_revidr = read_cpuid(REVIDR_EL1);

	info->reg_id_aa64isar0 = read_cpuid(ID_AA64ISAR0_EL1);
	info->reg_id_aa64isar1 = read_cpuid(ID_AA64ISAR1_EL1);
	info->reg_id_aa64mmfr0 = read_cpuid(ID_AA64MMFR0_EL1);
	info->reg_id_aa64mmfr1 = read_cpuid(ID_AA64MMFR1_EL1);
	info->reg_id_aa64pfr0 = read_cpuid(ID_AA64PFR0_EL1);
	info->reg_id_aa64pfr1 = read_cpuid(ID_AA64PFR1_EL1);

	info->reg_id_isar0 = read_cpuid(ID_ISAR0_EL1);
	info->reg_id_isar1 = read_cpuid(ID_ISAR1_EL1);
	info->reg_id_isar2 = read_cpuid(ID_ISAR2_EL1);
	info->reg_id_isar3 = read_cpuid(ID_ISAR3_EL1);
	info->reg_id_isar4 = read_cpuid(ID_ISAR4_EL1);
	info->reg_id_isar5 = read_cpuid(ID_ISAR5_EL1);
	info->reg_id_mmfr0 = read_cpuid(ID_MMFR0_EL1);
	info->reg_id_mmfr1 = read_cpuid(ID_MMFR1_EL1);
	info->reg_id_mmfr2 = read_cpuid(ID_MMFR2_EL1);
	info->reg_id_mmfr3 = read_cpuid(ID_MMFR3_EL1);
	info->reg_id_pfr0 = read_cpuid(ID_PFR0_EL1);
	info->reg_id_pfr1 = read_cpuid(ID_PFR1_EL1);

	cpuinfo_detect_icache_policy(info);

	update_cpu_features(info);

	check_local_cpu_errata();
}

void cpuinfo_store_cpu(void)
{
	struct cpuinfo_arm64 *info = this_cpu_ptr(&cpu_data);
	__cpuinfo_store_cpu(info);
}

void __init cpuinfo_store_boot_cpu(void)
{
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, 0);
	__cpuinfo_store_cpu(info);

	boot_cpu_data = *info;
}

u64 __attribute_const__ icache_get_ccsidr(void)
{
	u64 ccsidr;

	WARN_ON(preemptible());

	/* Select L1 I-cache and read its size ID register */
	asm("msr csselr_el1, %1; isb; mrs %0, ccsidr_el1"
	    : "=r"(ccsidr) : "r"(1L));
	return ccsidr;
}
device_initcall(cpuinfo_regs_init);
