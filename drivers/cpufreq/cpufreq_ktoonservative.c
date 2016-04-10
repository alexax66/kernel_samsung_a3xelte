/*
 *  drivers/cpufreq/cpufreq_ktoonservative.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
 *            (C)  2009 Alexander Clouter <alex@digriz.org.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpufreq_kt.h>
#include <linux/cpu.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>
#include <linux/mutex.h>
#include <linux/hrtimer.h>
#include <linux/tick.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/android_aid.h>

/*
 * dbs is used in this file as a shortform for demandbased switching
 * It helps to keep variable names smaller, simpler
 */

#define DEF_BOOST_CPU_CL0			(1400000)
#define DEF_BOOST_CPU_CL1			(1704000)
#define DEF_BOOST_GPU				(420)
#define DEF_BOOST_HOLD_CYCLES			(22)
#define DEF_DISABLE_hotplug			(0)
#define CPUS_AVAILABLE				num_possible_cpus()

bool ktoonservative_is_active = false;

static int hotplug_cpu_enable_up[] = { 0, 50, 55, 60, 65, 70, 75, 80 };
static int hotplug_cpu_enable_down[] = { 0, 35, 40, 45, 50, 55, 60, 65 };
static int hotplug_cpu_single_up[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static int hotplug_cpu_single_down[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static int hotplug_cpu_lockout[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static int hotplug_cpu_boosted[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

static unsigned int boost_bools_touch[] = { 0, 1, 1, 0, 0, 0, 0, 0 };
static bool boost_bools_touch_are_present = true;
static unsigned int boost_bools_button_son[] = { 0, 1, 1, 0, 0, 0, 0, 0 };
static bool boost_bools_button_son_are_present = true;
static unsigned int boost_bools_button_soff[] = { 0, 1, 1, 0, 1, 0, 0, 0 };
static bool boost_bools_button_soff_are_present = true;

static unsigned int touch_boost_cpu_array[] = { 1400000, 1400000, 1400000, 1400000, 1704000, 1704000, 1704000, 1704000 };
static unsigned int cpu_load[] = { -1, -1, -1, -1, -1, -1, -1, -1 };
static bool hotplug_flag_on = false;
static bool disable_hotplug_chrg_override;
static bool disable_hotplug_media_override;

unsigned int is_charging;
bool call_in_progress;

void set_core_flag_up(unsigned int cpu, unsigned int val);
void set_core_flag_down(unsigned int cpu, unsigned int val);
static unsigned int kt_cpu_core_smp_status[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
extern unsigned int cpu_core_smp_status[];
static unsigned int cpus_online;	/* number of CPUs using this policy */
/*
 * The polling frequency of this governor depends on the capability of
 * the processor. Default polling frequency is 1000 times the transition
 * latency of the processor. The governor will work on any processor with
 * transition latency <= 10mS, using appropriate sampling
 * rate.
 * For CPUs with transition latency > 10mS (mostly drivers with CPUFREQ_ETERNAL)
 * this governor will not work.
 * All times here are in uS.
 */
#define MIN_SAMPLING_RATE_RATIO			(2)

static bool turned_off_super_conservative_screen_off = false;
static bool fake_screen_on = false;

unsigned int ktoonservative_hp_active = 1;
static bool disable_hotplug_bt_active = false;
static unsigned int min_sampling_rate;
static unsigned int stored_sampling_rate = 35000;
static bool boostpulse_relayf = false;
static int boost_hold_cycles_cnt = 0;
extern void boost_the_gpu(int freq, bool getfreq);

static bool hotplugInProgress = false;

#define LATENCY_MULTIPLIER			(1000)
#define MIN_LATENCY_MULTIPLIER			(100)
#define TRANSITION_LATENCY_LIMIT		(10 * 1000 * 1000)
#define OVERRIDE_DISABLER			(-999999)

struct work_struct hotplug_offline_work;
struct work_struct hotplug_online_work;
static spinlock_t cpufreq_up_lock;
static spinlock_t cpufreq_down_lock;

static void do_dbs_timer(struct work_struct *work);

struct cpufreq_ktoonservative_cpuinfo {
	cputime64_t prev_cpu_idle;
	cputime64_t prev_cpu_wall;
	cputime64_t prev_cpu_nice;
	struct cpufreq_policy *policy;
	struct delayed_work work;
	unsigned int down_skip;
	unsigned int requested_freq;
	int cpu;
	unsigned int enable:1;
	/*
	 * percpu mutex that serializes governor limit change with
	 * do_dbs_timer invocation. We do not want do_dbs_timer to run
	 * when user is changing the governor or limits.
	 */
	struct mutex timer_mutex;
	unsigned int Lblock_cycles_online;
	unsigned int Lblock_cycles_raise;
};
static DEFINE_PER_CPU(struct cpufreq_ktoonservative_cpuinfo, cpuinfo);
static unsigned int Lblock_cycles_online_OVERRIDE[] = { OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER };
static int Lblock_cycles_offline_OVERRIDE[] = { OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER, OVERRIDE_DISABLER };
static int Lblock_cycles_offline[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

/*
 * dbs_mutex protects cpus_online in governor start/stop.
 */
static struct mutex dbs_mutex;

static struct workqueue_struct *dbs_wq;

struct cpufreq_ktoonservative_tunables {
	unsigned int *policy;
	int usage_count;
	unsigned int sampling_rate;
	unsigned int sampling_rate_min;
	unsigned int sampling_rate_screen_off;
	unsigned int up_threshold_screen_on;
	unsigned int up_threshold_screen_on_hotplug_1;
	unsigned int up_threshold_screen_on_hotplug_2;
	unsigned int up_threshold_screen_on_hotplug_3;
	unsigned int up_threshold_screen_on_hotplug_4;
	unsigned int up_threshold_screen_on_hotplug_5;
	unsigned int up_threshold_screen_on_hotplug_6;
	unsigned int up_threshold_screen_on_hotplug_7;
	unsigned int up_threshold_screen_off;
	unsigned int up_threshold_screen_off_hotplug_1;
	unsigned int up_threshold_screen_off_hotplug_2;
	unsigned int up_threshold_screen_off_hotplug_3;
	unsigned int up_threshold_screen_off_hotplug_4;
	unsigned int up_threshold_screen_off_hotplug_5;
	unsigned int up_threshold_screen_off_hotplug_6;
	unsigned int up_threshold_screen_off_hotplug_7;
	unsigned int down_threshold_screen_on;
	unsigned int down_threshold_screen_on_hotplug_1;
	unsigned int down_threshold_screen_on_hotplug_2;
	unsigned int down_threshold_screen_on_hotplug_3;
	unsigned int down_threshold_screen_on_hotplug_4;
	unsigned int down_threshold_screen_on_hotplug_5;
	unsigned int down_threshold_screen_on_hotplug_6;
	unsigned int down_threshold_screen_on_hotplug_7;
	unsigned int down_threshold_screen_off;
	unsigned int down_threshold_screen_off_hotplug_1;
	unsigned int down_threshold_screen_off_hotplug_2;
	unsigned int down_threshold_screen_off_hotplug_3;
	unsigned int down_threshold_screen_off_hotplug_4;
	unsigned int down_threshold_screen_off_hotplug_5;
	unsigned int down_threshold_screen_off_hotplug_6;
	unsigned int down_threshold_screen_off_hotplug_7;
	unsigned int block_cycles_online_screen_on;
	int block_cycles_offline_screen_on;
	unsigned int block_cycles_raise_screen_on;
	unsigned int block_cycles_online_screen_off;
	int block_cycles_offline_screen_off;
	unsigned int block_cycles_raise_screen_off;
	unsigned int super_conservative_screen_on;
	unsigned int super_conservative_screen_off;
	unsigned int touch_boost_cpu_cl0;
	unsigned int touch_boost_cpu_cl1;
	unsigned int touch_boost_core_1;
	unsigned int touch_boost_core_2;
	unsigned int touch_boost_core_3;
	unsigned int touch_boost_core_4;
	unsigned int touch_boost_core_5;
	unsigned int touch_boost_core_6;
	unsigned int touch_boost_core_7;
	unsigned int button_boost_screen_on_core_1;
	unsigned int button_boost_screen_on_core_2;
	unsigned int button_boost_screen_on_core_3;
	unsigned int button_boost_screen_on_core_4;
	unsigned int button_boost_screen_on_core_5;
	unsigned int button_boost_screen_on_core_6;
	unsigned int button_boost_screen_on_core_7;
	unsigned int button_boost_screen_off_core_1;
	unsigned int button_boost_screen_off_core_2;
	unsigned int button_boost_screen_off_core_3;
	unsigned int button_boost_screen_off_core_4;
	unsigned int button_boost_screen_off_core_5;
	unsigned int button_boost_screen_off_core_6;
	unsigned int button_boost_screen_off_core_7;
	unsigned int lockout_hotplug_screen_on_core_1;
	unsigned int lockout_hotplug_screen_on_core_2;
	unsigned int lockout_hotplug_screen_on_core_3;
	unsigned int lockout_hotplug_screen_on_core_4;
	unsigned int lockout_hotplug_screen_on_core_5;
	unsigned int lockout_hotplug_screen_on_core_6;
	unsigned int lockout_hotplug_screen_on_core_7;
	unsigned int lockout_hotplug_screen_off_core_1;
	unsigned int lockout_hotplug_screen_off_core_2;
	unsigned int lockout_hotplug_screen_off_core_3;
	unsigned int lockout_hotplug_screen_off_core_4;
	unsigned int lockout_hotplug_screen_off_core_5;
	unsigned int lockout_hotplug_screen_off_core_6;
	unsigned int lockout_hotplug_screen_off_core_7;
	unsigned int lockout_changes_when_boosting;
	int touch_boost_gpu;
	unsigned int cpu_load_adder_at_max_gpu;
	unsigned int cpu_load_adder_at_max_gpu_ignore_tb;
	unsigned int boost_hold_cycles;
	unsigned int disable_hotplug;
	unsigned int disable_hotplug_chrg;
	unsigned int disable_hotplug_media;
	unsigned int disable_hotplug_bt;
	unsigned int no_extra_cores_screen_off;
	unsigned int ignore_nice_load;
	unsigned int freq_step_raise_screen_on;
	unsigned int freq_step_raise_screen_off;
	unsigned int freq_step_lower_screen_on;
	unsigned int freq_step_lower_screen_off;
	unsigned int debug_enabled;
};
unsigned int debug_is_enabled;

static struct cpufreq_ktoonservative_tunables *common_tunables;
static struct cpufreq_ktoonservative_tunables *tuned_parameters[NR_CPUS] = {NULL, };
static struct attribute_group *get_sysfs_attr(void);

static inline cputime64_t get_cpu_idle_time_jiffy(unsigned int cpu,
						  cputime64_t *wall)
{
	u64 idle_time;
	u64 cur_wall_time;
	u64 busy_time;

	cur_wall_time = jiffies64_to_cputime64(get_jiffies_64());

	busy_time  = kcpustat_cpu(cpu).cpustat[CPUTIME_USER];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_SYSTEM];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_IRQ];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_SOFTIRQ];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_STEAL];
	busy_time += kcpustat_cpu(cpu).cpustat[CPUTIME_NICE];

	idle_time = cur_wall_time - busy_time;
	if (wall)
		*wall = jiffies_to_usecs(cur_wall_time);

	return jiffies_to_usecs(idle_time);
}

static inline cputime64_t get_cpu_idle_time(unsigned int cpu, cputime64_t *wall)
{
	u64 idle_time = get_cpu_idle_time_us(cpu, wall);

	if (idle_time == -1ULL)
		idle_time = get_cpu_idle_time_jiffy(cpu, wall);
	
	return idle_time;
}

/* keep track of frequency transitions */
static int dbs_cpufreq_notifier(struct notifier_block *nb, unsigned long val,
		     void *data)
{
	struct cpufreq_freqs *freq = data;
	struct cpufreq_ktoonservative_cpuinfo *this_dbs_info = &per_cpu(cpuinfo,
							freq->cpu);

	struct cpufreq_policy *policy;

	if (!this_dbs_info->enable)
		return 0;

	policy = this_dbs_info->policy;

	/*
	 * we only care if our internally tracked freq moves outside
	 * the 'valid' ranges of freqency available to us otherwise
	 * we do not change it
	*/
	if (this_dbs_info->requested_freq > policy->max
			|| this_dbs_info->requested_freq < policy->min)
		this_dbs_info->requested_freq = freq->new;

	return 0;
}

static struct notifier_block cpufreq_notifier_block = {
	.notifier_call = dbs_cpufreq_notifier
};

void set_bluetooth_state_kt(bool val, int cpu)
{
	struct cpufreq_ktoonservative_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_ktoonservative_tunables *tunables =
		pcpu->policy->governor_data;
	if (val == true && tunables->disable_hotplug_bt == 1)
	{
		disable_hotplug_bt_active = true;
		if (num_online_cpus() < 2)
		{
			int cpu;
			for (cpu = 1; cpu < CPUS_AVAILABLE; cpu++)
			{
				if (!cpu_online(cpu))
					set_core_flag_up(cpu, 1);
			}
			queue_work_on(0, dbs_wq, &hotplug_online_work);
		}
	}
	else
		disable_hotplug_bt_active = false;
}

void send_cable_state_kt(unsigned int state, int cpu)
{
	int cpuloop;
	struct cpufreq_ktoonservative_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_ktoonservative_tunables *tunables =
		pcpu->policy->governor_data;
	if (state && tunables->disable_hotplug_chrg)
	{
		disable_hotplug_chrg_override = true;
		for (cpuloop = 1; cpuloop < CPUS_AVAILABLE; cpuloop++)
			set_core_flag_up(cpuloop, 1);
		queue_work_on(0, dbs_wq, &hotplug_online_work);
	}
	else
		disable_hotplug_chrg_override = false;
}

bool set_music_playing_statekt(bool state, int cpu)
{
	int cpuloop;
	bool ret = false;
	struct cpufreq_ktoonservative_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_ktoonservative_tunables *tunables =
		pcpu->policy->governor_data;
	if (state && tunables->disable_hotplug_media)
	{
		disable_hotplug_media_override = true;
		for (cpuloop = 1; cpuloop < CPUS_AVAILABLE; cpuloop++)
			set_core_flag_up(cpuloop, 1);
		queue_work_on(0, dbs_wq, &hotplug_online_work);
		ret = true;
	}
	else
		disable_hotplug_media_override = false;
	
	return ret;
}

/************************** sysfs interface ************************/
#define show_one_kt(file_name)						\
static ssize_t show_##file_name						\
(struct cpufreq_ktoonservative_tunables *tunables, char *buf)				\
{									\
	return sprintf(buf, "%u\n", tunables->file_name);		\
}
show_one_kt(ignore_nice_load);
show_one_kt(debug_enabled);
show_one_kt(freq_step_lower_screen_on);
show_one_kt(freq_step_lower_screen_off);
show_one_kt(freq_step_raise_screen_on);
show_one_kt(freq_step_raise_screen_off);
show_one_kt(no_extra_cores_screen_off);
show_one_kt(disable_hotplug_bt);
show_one_kt(disable_hotplug_media);
show_one_kt(disable_hotplug_chrg);
show_one_kt(disable_hotplug);
show_one_kt(boost_hold_cycles);
show_one_kt(cpu_load_adder_at_max_gpu_ignore_tb);
show_one_kt(cpu_load_adder_at_max_gpu);
show_one_kt(touch_boost_gpu);
show_one_kt(lockout_changes_when_boosting);
show_one_kt(lockout_hotplug_screen_off_core_1);
show_one_kt(lockout_hotplug_screen_off_core_2);
show_one_kt(lockout_hotplug_screen_off_core_3);
show_one_kt(lockout_hotplug_screen_off_core_4);
show_one_kt(lockout_hotplug_screen_off_core_5);
show_one_kt(lockout_hotplug_screen_off_core_6);
show_one_kt(lockout_hotplug_screen_off_core_7);
show_one_kt(lockout_hotplug_screen_on_core_1);
show_one_kt(lockout_hotplug_screen_on_core_2);
show_one_kt(lockout_hotplug_screen_on_core_3);
show_one_kt(lockout_hotplug_screen_on_core_4);
show_one_kt(lockout_hotplug_screen_on_core_5);
show_one_kt(lockout_hotplug_screen_on_core_6);
show_one_kt(lockout_hotplug_screen_on_core_7);
show_one_kt(touch_boost_core_1);
show_one_kt(touch_boost_core_2);
show_one_kt(touch_boost_core_3);
show_one_kt(touch_boost_core_4);
show_one_kt(touch_boost_core_5);
show_one_kt(touch_boost_core_6);
show_one_kt(touch_boost_core_7);
show_one_kt(button_boost_screen_on_core_1);
show_one_kt(button_boost_screen_on_core_2);
show_one_kt(button_boost_screen_on_core_3);
show_one_kt(button_boost_screen_on_core_4);
show_one_kt(button_boost_screen_on_core_5);
show_one_kt(button_boost_screen_on_core_6);
show_one_kt(button_boost_screen_on_core_7);
show_one_kt(button_boost_screen_off_core_1);
show_one_kt(button_boost_screen_off_core_2);
show_one_kt(button_boost_screen_off_core_3);
show_one_kt(button_boost_screen_off_core_4);
show_one_kt(button_boost_screen_off_core_5);
show_one_kt(button_boost_screen_off_core_6);
show_one_kt(button_boost_screen_off_core_7);
show_one_kt(super_conservative_screen_on);
show_one_kt(super_conservative_screen_off);
show_one_kt(block_cycles_raise_screen_off);
show_one_kt(block_cycles_offline_screen_off);
show_one_kt(block_cycles_online_screen_off);
show_one_kt(block_cycles_raise_screen_on);
show_one_kt(block_cycles_offline_screen_on);
show_one_kt(block_cycles_online_screen_on);
show_one_kt(down_threshold_screen_off_hotplug_1);
show_one_kt(down_threshold_screen_off_hotplug_2);
show_one_kt(down_threshold_screen_off_hotplug_3);
show_one_kt(down_threshold_screen_off_hotplug_4);
show_one_kt(down_threshold_screen_off_hotplug_5);
show_one_kt(down_threshold_screen_off_hotplug_6);
show_one_kt(down_threshold_screen_off_hotplug_7);
show_one_kt(down_threshold_screen_off);
show_one_kt(down_threshold_screen_on_hotplug_1);
show_one_kt(down_threshold_screen_on_hotplug_2);
show_one_kt(down_threshold_screen_on_hotplug_3);
show_one_kt(down_threshold_screen_on_hotplug_4);
show_one_kt(down_threshold_screen_on_hotplug_5);
show_one_kt(down_threshold_screen_on_hotplug_6);
show_one_kt(down_threshold_screen_on_hotplug_7);
show_one_kt(down_threshold_screen_on);
show_one_kt(up_threshold_screen_off_hotplug_1);
show_one_kt(up_threshold_screen_off_hotplug_2);
show_one_kt(up_threshold_screen_off_hotplug_3);
show_one_kt(up_threshold_screen_off_hotplug_4);
show_one_kt(up_threshold_screen_off_hotplug_5);
show_one_kt(up_threshold_screen_off_hotplug_6);
show_one_kt(up_threshold_screen_off_hotplug_7);
show_one_kt(up_threshold_screen_off);
show_one_kt(up_threshold_screen_on_hotplug_1);
show_one_kt(up_threshold_screen_on_hotplug_2);
show_one_kt(up_threshold_screen_on_hotplug_3);
show_one_kt(up_threshold_screen_on_hotplug_4);
show_one_kt(up_threshold_screen_on_hotplug_5);
show_one_kt(up_threshold_screen_on_hotplug_6);
show_one_kt(up_threshold_screen_on_hotplug_7);
show_one_kt(up_threshold_screen_on);
show_one_kt(sampling_rate_screen_off);
show_one_kt(sampling_rate);
show_one_kt(touch_boost_cpu_cl0);
show_one_kt(touch_boost_cpu_cl1);

static ssize_t show_sampling_rate_min(struct cpufreq_ktoonservative_tunables
		*tunables, char *buf)
{
	return sprintf(buf, "%u\n", min_sampling_rate);
}

static ssize_t store_sampling_rate(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	tunables->sampling_rate = max(input, min_sampling_rate);
	stored_sampling_rate = max(input, min_sampling_rate);
	return count;
}

static ssize_t store_sampling_rate_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	tunables->sampling_rate_screen_off = max(input, min_sampling_rate);
	return count;
}

#define store_up_threshold(file_name, scrstate, ndx)					\
static ssize_t store_up_##file_name							\
(struct cpufreq_ktoonservative_tunables *tunables, const char *buf, size_t count)	\
{											\
	unsigned int input;								\
	int ret;									\
	ret = sscanf(buf, "%u", &input);						\
	if (ret != 1 || input > 100 || input <= tunables->down_##file_name)		\
		return -EINVAL;								\
	tunables->up_##file_name = input;							\
	if (screen_is_on == scrstate && ndx >= 0)					\
		hotplug_cpu_enable_up[ndx] = input;					\
	return count;									\
}
store_up_threshold(threshold_screen_on, true, -1);
store_up_threshold(threshold_screen_on_hotplug_1, true, 1);
store_up_threshold(threshold_screen_on_hotplug_2, true, 2);
store_up_threshold(threshold_screen_on_hotplug_3, true, 3);
store_up_threshold(threshold_screen_on_hotplug_4, true, 4);
store_up_threshold(threshold_screen_on_hotplug_5, true, 5);
store_up_threshold(threshold_screen_on_hotplug_6, true, 6);
store_up_threshold(threshold_screen_on_hotplug_7, true, 7);
store_up_threshold(threshold_screen_off, false, -1);
store_up_threshold(threshold_screen_off_hotplug_1, false, 1);
store_up_threshold(threshold_screen_off_hotplug_2, false, 2);
store_up_threshold(threshold_screen_off_hotplug_3, false, 3);
store_up_threshold(threshold_screen_off_hotplug_4, false, 4);
store_up_threshold(threshold_screen_off_hotplug_5, false, 5);
store_up_threshold(threshold_screen_off_hotplug_6, false, 6);
store_up_threshold(threshold_screen_off_hotplug_7, false, 7);

#define store_down_threshold(file_name, scrstate, ndx)						\
static ssize_t store_down_##file_name								\
(struct cpufreq_ktoonservative_tunables *tunables, const char *buf, size_t count)		\
{												\
	unsigned int input;									\
	int ret;										\
	ret = sscanf(buf, "%u", &input);							\
	if (ret != 1 || input < 11 || input > 100 || input >= tunables->up_##file_name)		\
		return -EINVAL;									\
	tunables->down_##file_name = input;							\
	if (screen_is_on == scrstate && ndx >= 0)						\
		hotplug_cpu_enable_down[ndx] = input;						\
	return count;										\
}
store_down_threshold(threshold_screen_on, true, -1);
store_down_threshold(threshold_screen_on_hotplug_1, true, 1);
store_down_threshold(threshold_screen_on_hotplug_2, true, 2);
store_down_threshold(threshold_screen_on_hotplug_3, true, 3);
store_down_threshold(threshold_screen_on_hotplug_4, true, 4);
store_down_threshold(threshold_screen_on_hotplug_5, true, 5);
store_down_threshold(threshold_screen_on_hotplug_6, true, 6);
store_down_threshold(threshold_screen_on_hotplug_7, true, 7);
store_down_threshold(threshold_screen_off, false, -1);
store_down_threshold(threshold_screen_off_hotplug_1, false, 1);
store_down_threshold(threshold_screen_off_hotplug_2, false, 2);
store_down_threshold(threshold_screen_off_hotplug_3, false, 3);
store_down_threshold(threshold_screen_off_hotplug_4, false, 4);
store_down_threshold(threshold_screen_off_hotplug_5, false, 5);
store_down_threshold(threshold_screen_off_hotplug_6, false, 6);
store_down_threshold(threshold_screen_off_hotplug_7, false, 7);

static ssize_t store_block_cycles_online_screen_on(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (input < 0)
		return -EINVAL;

	tunables->block_cycles_online_screen_on = input;
	return count;
}

static ssize_t store_block_cycles_offline_screen_on(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (input < 0)
		return -EINVAL;

	tunables->block_cycles_offline_screen_on = input;
	return count;
}

static ssize_t store_block_cycles_raise_screen_on(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (input < 0)
		return -EINVAL;

	tunables->block_cycles_raise_screen_on = input;
	return count;
}

static ssize_t store_block_cycles_online_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (input < 0)
		return -EINVAL;

	tunables->block_cycles_online_screen_off = input;
	return count;
}

static ssize_t store_block_cycles_offline_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (input < 0)
		return -EINVAL;

	tunables->block_cycles_offline_screen_off = input;
	return count;
}

static ssize_t store_block_cycles_raise_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	/* cannot be lower than 11 otherwise freq will not fall */
	if (input < 0)
		return -EINVAL;

	tunables->block_cycles_raise_screen_off = input;
	return count;
}

static ssize_t store_super_conservative_screen_on(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->super_conservative_screen_on = input;
	return count;
}

static ssize_t store_super_conservative_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->super_conservative_screen_off = input;
	return count;
}

static ssize_t store_touch_boost_cpu_cl0(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > GLOBALKT_MAX_FREQ_LIMIT[0])
		input = GLOBALKT_MAX_FREQ_LIMIT[0];
	if (input < 0)
		input = 0;
	tunables->touch_boost_cpu_cl0 = input;
	touch_boost_cpu_array[0] = input;
	touch_boost_cpu_array[1] = input;
	touch_boost_cpu_array[2] = input;
	touch_boost_cpu_array[3] = input;
	return count;
}

static ssize_t store_touch_boost_cpu_cl1(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > GLOBALKT_MAX_FREQ_LIMIT[4])
		input = GLOBALKT_MAX_FREQ_LIMIT[4];
	if (input < 0)
		input = 0;
	tunables->touch_boost_cpu_cl1 = input;
	touch_boost_cpu_array[4] = input;
	touch_boost_cpu_array[5] = input;
	touch_boost_cpu_array[6] = input;
	touch_boost_cpu_array[7] = input;
	return count;
}

#define store_boost_core(file_name, theArray, theArrayMux, ndx)				\
static ssize_t store_##file_name							\
(struct cpufreq_ktoonservative_tunables *tunables, const char *buf, size_t count)	\
{											\
	unsigned int input, cpu;							\
	int ret;									\
	ret = sscanf(buf, "%u", &input);						\
	if (input != 0 && input != 1)							\
		input = 0;								\
	tunables->file_name = input;							\
	theArray[ndx] = input;								\
	theArrayMux = false;								\
	for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)					\
	{										\
		if (theArray[ndx])							\
			theArrayMux = true;						\
	}										\
	return count;									\
}
store_boost_core(touch_boost_core_1, boost_bools_touch, boost_bools_touch_are_present, 1);
store_boost_core(touch_boost_core_2, boost_bools_touch, boost_bools_touch_are_present, 2);
store_boost_core(touch_boost_core_3, boost_bools_touch, boost_bools_touch_are_present, 3);
store_boost_core(touch_boost_core_4, boost_bools_touch, boost_bools_touch_are_present, 4);
store_boost_core(touch_boost_core_5, boost_bools_touch, boost_bools_touch_are_present, 5);
store_boost_core(touch_boost_core_6, boost_bools_touch, boost_bools_touch_are_present, 6);
store_boost_core(touch_boost_core_7, boost_bools_touch, boost_bools_touch_are_present, 7);
store_boost_core(button_boost_screen_on_core_1, boost_bools_button_son, boost_bools_button_son_are_present, 1);
store_boost_core(button_boost_screen_on_core_2, boost_bools_button_son, boost_bools_button_son_are_present, 2);
store_boost_core(button_boost_screen_on_core_3, boost_bools_button_son, boost_bools_button_son_are_present, 3);
store_boost_core(button_boost_screen_on_core_4, boost_bools_button_son, boost_bools_button_son_are_present, 4);
store_boost_core(button_boost_screen_on_core_5, boost_bools_button_son, boost_bools_button_son_are_present, 5);
store_boost_core(button_boost_screen_on_core_6, boost_bools_button_son, boost_bools_button_son_are_present, 6);
store_boost_core(button_boost_screen_on_core_7, boost_bools_button_son, boost_bools_button_son_are_present, 7);
store_boost_core(button_boost_screen_off_core_1, boost_bools_button_soff, boost_bools_button_soff_are_present, 1);
store_boost_core(button_boost_screen_off_core_2, boost_bools_button_soff, boost_bools_button_soff_are_present, 2);
store_boost_core(button_boost_screen_off_core_3, boost_bools_button_soff, boost_bools_button_soff_are_present, 3);
store_boost_core(button_boost_screen_off_core_4, boost_bools_button_soff, boost_bools_button_soff_are_present, 4);
store_boost_core(button_boost_screen_off_core_5, boost_bools_button_soff, boost_bools_button_soff_are_present, 5);
store_boost_core(button_boost_screen_off_core_6, boost_bools_button_soff, boost_bools_button_soff_are_present, 6);
store_boost_core(button_boost_screen_off_core_7, boost_bools_button_soff, boost_bools_button_soff_are_present, 7);

#define store_lockout_core(file_name, ndx)						\
static ssize_t store_##file_name							\
(struct cpufreq_ktoonservative_tunables *tunables, const char *buf, size_t count)	\
{											\
	unsigned int input;								\
	int ret;									\
	ret = sscanf(buf, "%u", &input);						\
											\
	if (input != 0 && input != 1 && input != 2)					\
		input = 0;								\
											\
	tunables->file_name = input;							\
	if (screen_is_on)								\
		hotplug_cpu_lockout[ndx] = input;					\
	if (screen_is_on && input == 1)							\
	{										\
		set_core_flag_up(ndx, 1);						\
		queue_work_on(0, dbs_wq, &hotplug_online_work);				\
	}										\
	else if (screen_is_on && input == 2 && !main_cpufreq_control[ndx])		\
	{										\
		set_core_flag_down(ndx, 1);						\
		queue_work_on(0, dbs_wq, &hotplug_offline_work);			\
	}										\
	return count;									\
}
store_lockout_core(lockout_hotplug_screen_on_core_1, 1);
store_lockout_core(lockout_hotplug_screen_on_core_2, 2);
store_lockout_core(lockout_hotplug_screen_on_core_3, 3);
store_lockout_core(lockout_hotplug_screen_on_core_4, 4);
store_lockout_core(lockout_hotplug_screen_on_core_5, 5);
store_lockout_core(lockout_hotplug_screen_on_core_6, 6);
store_lockout_core(lockout_hotplug_screen_on_core_7, 7);
store_lockout_core(lockout_hotplug_screen_off_core_1, 1);
store_lockout_core(lockout_hotplug_screen_off_core_2, 2);
store_lockout_core(lockout_hotplug_screen_off_core_3, 3);
store_lockout_core(lockout_hotplug_screen_off_core_4, 4);
store_lockout_core(lockout_hotplug_screen_off_core_5, 5);
store_lockout_core(lockout_hotplug_screen_off_core_6, 6);
store_lockout_core(lockout_hotplug_screen_off_core_7, 7);

static ssize_t store_lockout_changes_when_boosting(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->lockout_changes_when_boosting = input;
	return count;
}

static ssize_t store_touch_boost_gpu(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 266 && input != 350 && input != 420 && input != 544 && input != 600 && input != 700 && input != 772)
		input = 0;
	
	if (input == 0)
		boost_the_gpu(tunables->touch_boost_gpu, false);
		
	tunables->touch_boost_gpu = input;
	return count;
}

static ssize_t store_cpu_load_adder_at_max_gpu(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input < 0 || input > 100)
		input = 0;
	
	tunables->cpu_load_adder_at_max_gpu = input;
	return count;
}

static ssize_t store_cpu_load_adder_at_max_gpu_ignore_tb(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input < 0 || input > 100)
		input = 0;
	
	tunables->cpu_load_adder_at_max_gpu_ignore_tb = input;
	return count;
}

static ssize_t store_boost_hold_cycles(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input < 0)
		return -EINVAL;

	tunables->boost_hold_cycles = input;
	return count;
}

static ssize_t store_disable_hotplug(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret, cpu;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->disable_hotplug = input;
	if (input == 1)
	{
		ktoonservative_hp_active = 0;
		for (cpu = 1; cpu < CPUS_AVAILABLE; cpu++)
			set_core_flag_up(cpu, 1);
		queue_work_on(0, dbs_wq, &hotplug_online_work);
	}
	else
		ktoonservative_hp_active = 1;

	return count;
}

static ssize_t store_disable_hotplug_chrg(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input, c_state, c_stateW;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->disable_hotplug_chrg = input;
	c_state = is_charging;
	c_stateW = is_charging;

	if (c_state != 0 || c_stateW != 0)
	{
		send_cable_state_kt(1, 0);
		send_cable_state_kt(1, 4);
	}
	else
	{
		send_cable_state_kt(0, 0);
		send_cable_state_kt(0, 4);
	}
		
	return count;
}

static ssize_t store_disable_hotplug_media(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->disable_hotplug_media = input;
		
	return count;
}

static ssize_t store_no_extra_cores_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->no_extra_cores_screen_off = input;
	return count;
}

static ssize_t store_disable_hotplug_bt(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (input != 0 && input != 1)
		input = 0;

	tunables->disable_hotplug_bt = input;
	return count;
}

static ssize_t store_ignore_nice_load(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;

	unsigned int j;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	if (input == tunables->ignore_nice_load) /* nothing to do */
		return count;

	tunables->ignore_nice_load = input;

	/* we need to re-evaluate prev_cpu_idle */
	for_each_online_cpu(j) {
		struct cpufreq_ktoonservative_cpuinfo *dbs_info;
		dbs_info = &per_cpu(cpuinfo, j);
		dbs_info->prev_cpu_idle = get_cpu_idle_time(j,
						&dbs_info->prev_cpu_wall);
		if (tunables->ignore_nice_load)
			dbs_info->prev_cpu_nice = kcpustat_cpu(j).cpustat[CPUTIME_NICE];
	}
	return count;
}

static ssize_t store_freq_step_raise_screen_on(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 100)
		input = 100;

	/* no need to test here if freq_step_raise_screen_on is zero as the user might actually
	 * want this, they would be crazy though :) */
	tunables->freq_step_raise_screen_on = input;
	return count;
}

static ssize_t store_freq_step_raise_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 100)
		input = 100;

	/* no need to test here if freq_step_raise_screen_off is zero as the user might actually
	 * want this, they would be crazy though :) */
	tunables->freq_step_raise_screen_off = input;
	return count;
}

static ssize_t store_freq_step_lower_screen_on(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 100)
		input = 100;

	/* no need to test here if freq_step_lower_screen_on is zero as the user might actually
	 * want this, they would be crazy though :) */
	tunables->freq_step_lower_screen_on = input;
	return count;
}

static ssize_t store_freq_step_lower_screen_off(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 100)
		input = 100;

	/* no need to test here if freq_step_lower_screen_off is zero as the user might actually
	 * want this, they would be crazy though :) */
	tunables->freq_step_lower_screen_off = input;
	return count;
}

static ssize_t store_debug_enabled(struct cpufreq_ktoonservative_tunables
		*tunables, const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	tunables->debug_enabled = input;
	debug_is_enabled = input;
	return count;
}

/* cpufreq_ktoonservative Governor Tunables */
/*
 * Create show/store routines
 * - sys: One governor instance for complete SYSTEM
 * - pol: One governor instance per struct cpufreq_policy
 */
#define show_gov_pol_sys(file_name)					\
static ssize_t show_##file_name##_gov_sys				\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return show_##file_name(common_tunables, buf);			\
}									\
									\
static ssize_t show_##file_name##_gov_pol				\
(struct cpufreq_policy *policy, char *buf)				\
{									\
	return show_##file_name(policy->governor_data, buf);		\
}

#define store_gov_pol_sys(file_name)					\
static ssize_t store_##file_name##_gov_sys				\
(struct kobject *kobj, struct attribute *attr, const char *buf,		\
	size_t count)							\
{									\
	return store_##file_name(common_tunables, buf, count);		\
}									\
									\
static ssize_t store_##file_name##_gov_pol				\
(struct cpufreq_policy *policy, const char *buf, size_t count)		\
{									\
	return store_##file_name(policy->governor_data, buf, count);	\
}

#define show_store_gov_pol_sys(file_name)				\
show_gov_pol_sys(file_name);						\
store_gov_pol_sys(file_name)

show_store_gov_pol_sys(sampling_rate);
show_store_gov_pol_sys(sampling_rate_screen_off);
show_store_gov_pol_sys(up_threshold_screen_on);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_1);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_2);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_3);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_4);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_5);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_6);
show_store_gov_pol_sys(up_threshold_screen_on_hotplug_7);
show_store_gov_pol_sys(up_threshold_screen_off);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_1);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_2);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_3);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_4);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_5);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_6);
show_store_gov_pol_sys(up_threshold_screen_off_hotplug_7);
show_store_gov_pol_sys(down_threshold_screen_on);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_1);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_2);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_3);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_4);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_5);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_6);
show_store_gov_pol_sys(down_threshold_screen_on_hotplug_7);
show_store_gov_pol_sys(down_threshold_screen_off);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_1);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_2);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_3);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_4);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_5);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_6);
show_store_gov_pol_sys(down_threshold_screen_off_hotplug_7);
show_store_gov_pol_sys(block_cycles_online_screen_on);
show_store_gov_pol_sys(block_cycles_offline_screen_on);
show_store_gov_pol_sys(block_cycles_raise_screen_on);
show_store_gov_pol_sys(block_cycles_online_screen_off);
show_store_gov_pol_sys(block_cycles_offline_screen_off);
show_store_gov_pol_sys(block_cycles_raise_screen_off);
show_store_gov_pol_sys(super_conservative_screen_on);
show_store_gov_pol_sys(super_conservative_screen_off);
show_store_gov_pol_sys(touch_boost_core_1);
show_store_gov_pol_sys(touch_boost_core_2);
show_store_gov_pol_sys(touch_boost_core_3);
show_store_gov_pol_sys(touch_boost_core_4);
show_store_gov_pol_sys(touch_boost_core_5);
show_store_gov_pol_sys(touch_boost_core_6);
show_store_gov_pol_sys(touch_boost_core_7);
show_store_gov_pol_sys(button_boost_screen_on_core_1);
show_store_gov_pol_sys(button_boost_screen_on_core_2);
show_store_gov_pol_sys(button_boost_screen_on_core_3);
show_store_gov_pol_sys(button_boost_screen_on_core_4);
show_store_gov_pol_sys(button_boost_screen_on_core_5);
show_store_gov_pol_sys(button_boost_screen_on_core_6);
show_store_gov_pol_sys(button_boost_screen_on_core_7);
show_store_gov_pol_sys(button_boost_screen_off_core_1);
show_store_gov_pol_sys(button_boost_screen_off_core_2);
show_store_gov_pol_sys(button_boost_screen_off_core_3);
show_store_gov_pol_sys(button_boost_screen_off_core_4);
show_store_gov_pol_sys(button_boost_screen_off_core_5);
show_store_gov_pol_sys(button_boost_screen_off_core_6);
show_store_gov_pol_sys(button_boost_screen_off_core_7);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_1);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_2);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_3);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_4);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_5);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_6);
show_store_gov_pol_sys(lockout_hotplug_screen_on_core_7);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_1);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_2);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_3);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_4);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_5);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_6);
show_store_gov_pol_sys(lockout_hotplug_screen_off_core_7);
show_store_gov_pol_sys(lockout_changes_when_boosting);
show_store_gov_pol_sys(touch_boost_gpu);
show_store_gov_pol_sys(cpu_load_adder_at_max_gpu);
show_store_gov_pol_sys(cpu_load_adder_at_max_gpu_ignore_tb);
show_store_gov_pol_sys(boost_hold_cycles);
show_store_gov_pol_sys(disable_hotplug);
show_store_gov_pol_sys(disable_hotplug_chrg);
show_store_gov_pol_sys(disable_hotplug_media);
show_store_gov_pol_sys(disable_hotplug_bt);
show_store_gov_pol_sys(no_extra_cores_screen_off);
show_store_gov_pol_sys(freq_step_raise_screen_on);
show_store_gov_pol_sys(freq_step_raise_screen_off);
show_store_gov_pol_sys(freq_step_lower_screen_on);
show_store_gov_pol_sys(freq_step_lower_screen_off);
show_store_gov_pol_sys(debug_enabled);
show_store_gov_pol_sys(ignore_nice_load);
show_store_gov_pol_sys(touch_boost_cpu_cl0);
show_store_gov_pol_sys(touch_boost_cpu_cl1);
show_gov_pol_sys(sampling_rate_min);

static struct global_attr sampling_rate_min_gov_sys =
	__ATTR(sampling_rate_min, 0444, show_sampling_rate_min_gov_sys, NULL);

static struct freq_attr sampling_rate_min_gov_pol =
	__ATTR(sampling_rate_min, 0444, show_sampling_rate_min_gov_pol, NULL);

#define gov_sys_attr_rw(_name)						\
static struct global_attr _name##_gov_sys =				\
__ATTR(_name, 0664, show_##_name##_gov_sys, store_##_name##_gov_sys)

#define gov_pol_attr_rw(_name)						\
static struct freq_attr _name##_gov_pol =				\
__ATTR(_name, 0664, show_##_name##_gov_pol, store_##_name##_gov_pol)

#define gov_sys_pol_attr_rw(_name)					\
	gov_sys_attr_rw(_name);						\
	gov_pol_attr_rw(_name)

gov_sys_pol_attr_rw(sampling_rate);
gov_sys_pol_attr_rw(sampling_rate_screen_off);
gov_sys_pol_attr_rw(up_threshold_screen_on);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_1);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_2);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_3);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_4);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_5);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_6);
gov_sys_pol_attr_rw(up_threshold_screen_on_hotplug_7);
gov_sys_pol_attr_rw(up_threshold_screen_off);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_1);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_2);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_3);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_4);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_5);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_6);
gov_sys_pol_attr_rw(up_threshold_screen_off_hotplug_7);
gov_sys_pol_attr_rw(down_threshold_screen_on);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_1);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_2);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_3);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_4);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_5);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_6);
gov_sys_pol_attr_rw(down_threshold_screen_on_hotplug_7);
gov_sys_pol_attr_rw(down_threshold_screen_off);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_1);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_2);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_3);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_4);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_5);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_6);
gov_sys_pol_attr_rw(down_threshold_screen_off_hotplug_7);
gov_sys_pol_attr_rw(block_cycles_online_screen_on);
gov_sys_pol_attr_rw(block_cycles_offline_screen_on);
gov_sys_pol_attr_rw(block_cycles_raise_screen_on);
gov_sys_pol_attr_rw(block_cycles_online_screen_off);
gov_sys_pol_attr_rw(block_cycles_offline_screen_off);
gov_sys_pol_attr_rw(block_cycles_raise_screen_off);
gov_sys_pol_attr_rw(super_conservative_screen_on);
gov_sys_pol_attr_rw(super_conservative_screen_off);
gov_sys_pol_attr_rw(touch_boost_cpu_cl0);
gov_sys_pol_attr_rw(touch_boost_cpu_cl1);
gov_sys_pol_attr_rw(touch_boost_core_1);
gov_sys_pol_attr_rw(touch_boost_core_2);
gov_sys_pol_attr_rw(touch_boost_core_3);
gov_sys_pol_attr_rw(touch_boost_core_4);
gov_sys_pol_attr_rw(touch_boost_core_5);
gov_sys_pol_attr_rw(touch_boost_core_6);
gov_sys_pol_attr_rw(touch_boost_core_7);
gov_sys_pol_attr_rw(button_boost_screen_on_core_1);
gov_sys_pol_attr_rw(button_boost_screen_on_core_2);
gov_sys_pol_attr_rw(button_boost_screen_on_core_3);
gov_sys_pol_attr_rw(button_boost_screen_on_core_4);
gov_sys_pol_attr_rw(button_boost_screen_on_core_5);
gov_sys_pol_attr_rw(button_boost_screen_on_core_6);
gov_sys_pol_attr_rw(button_boost_screen_on_core_7);
gov_sys_pol_attr_rw(button_boost_screen_off_core_1);
gov_sys_pol_attr_rw(button_boost_screen_off_core_2);
gov_sys_pol_attr_rw(button_boost_screen_off_core_3);
gov_sys_pol_attr_rw(button_boost_screen_off_core_4);
gov_sys_pol_attr_rw(button_boost_screen_off_core_5);
gov_sys_pol_attr_rw(button_boost_screen_off_core_6);
gov_sys_pol_attr_rw(button_boost_screen_off_core_7);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_1);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_2);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_3);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_4);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_5);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_6);
gov_sys_pol_attr_rw(lockout_hotplug_screen_on_core_7);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_1);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_2);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_3);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_4);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_5);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_6);
gov_sys_pol_attr_rw(lockout_hotplug_screen_off_core_7);
gov_sys_pol_attr_rw(lockout_changes_when_boosting);
gov_sys_pol_attr_rw(touch_boost_gpu);
gov_sys_pol_attr_rw(cpu_load_adder_at_max_gpu);
gov_sys_pol_attr_rw(cpu_load_adder_at_max_gpu_ignore_tb);
gov_sys_pol_attr_rw(boost_hold_cycles);
gov_sys_pol_attr_rw(disable_hotplug);
gov_sys_pol_attr_rw(disable_hotplug_chrg);
gov_sys_pol_attr_rw(disable_hotplug_media);
gov_sys_pol_attr_rw(disable_hotplug_bt);
gov_sys_pol_attr_rw(no_extra_cores_screen_off);
gov_sys_pol_attr_rw(ignore_nice_load);
gov_sys_pol_attr_rw(freq_step_raise_screen_on);
gov_sys_pol_attr_rw(freq_step_raise_screen_off);
gov_sys_pol_attr_rw(freq_step_lower_screen_on);
gov_sys_pol_attr_rw(freq_step_lower_screen_off);
gov_sys_pol_attr_rw(debug_enabled);

static struct attribute *dbs_attributes_gov_sys[] = {
	&sampling_rate_min_gov_sys.attr,
	&sampling_rate_gov_sys.attr,
	&sampling_rate_screen_off_gov_sys.attr,
	&up_threshold_screen_on_gov_sys.attr,
	&up_threshold_screen_on_hotplug_1_gov_sys.attr,
	&up_threshold_screen_on_hotplug_2_gov_sys.attr,
	&up_threshold_screen_on_hotplug_3_gov_sys.attr,
	&up_threshold_screen_on_hotplug_4_gov_sys.attr,
	&up_threshold_screen_on_hotplug_5_gov_sys.attr,
	&up_threshold_screen_on_hotplug_6_gov_sys.attr,
	&up_threshold_screen_on_hotplug_7_gov_sys.attr,
	&up_threshold_screen_off_gov_sys.attr,
	&up_threshold_screen_off_hotplug_1_gov_sys.attr,
	&up_threshold_screen_off_hotplug_2_gov_sys.attr,
	&up_threshold_screen_off_hotplug_3_gov_sys.attr,
	&up_threshold_screen_off_hotplug_4_gov_sys.attr,
	&up_threshold_screen_off_hotplug_5_gov_sys.attr,
	&up_threshold_screen_off_hotplug_6_gov_sys.attr,
	&up_threshold_screen_off_hotplug_7_gov_sys.attr,
	&down_threshold_screen_on_gov_sys.attr,
	&down_threshold_screen_on_hotplug_1_gov_sys.attr,
	&down_threshold_screen_on_hotplug_2_gov_sys.attr,
	&down_threshold_screen_on_hotplug_3_gov_sys.attr,
	&down_threshold_screen_on_hotplug_4_gov_sys.attr,
	&down_threshold_screen_on_hotplug_5_gov_sys.attr,
	&down_threshold_screen_on_hotplug_6_gov_sys.attr,
	&down_threshold_screen_on_hotplug_7_gov_sys.attr,
	&down_threshold_screen_off_gov_sys.attr,
	&down_threshold_screen_off_hotplug_1_gov_sys.attr,
	&down_threshold_screen_off_hotplug_2_gov_sys.attr,
	&down_threshold_screen_off_hotplug_3_gov_sys.attr,
	&down_threshold_screen_off_hotplug_4_gov_sys.attr,
	&down_threshold_screen_off_hotplug_5_gov_sys.attr,
	&down_threshold_screen_off_hotplug_6_gov_sys.attr,
	&down_threshold_screen_off_hotplug_7_gov_sys.attr,
	&block_cycles_online_screen_on_gov_sys.attr,
	&block_cycles_offline_screen_on_gov_sys.attr,
	&block_cycles_raise_screen_on_gov_sys.attr,
	&block_cycles_online_screen_off_gov_sys.attr,
	&block_cycles_offline_screen_off_gov_sys.attr,
	&block_cycles_raise_screen_off_gov_sys.attr,
	&super_conservative_screen_on_gov_sys.attr,
	&super_conservative_screen_off_gov_sys.attr,
	&touch_boost_cpu_cl0_gov_sys.attr,
	&touch_boost_cpu_cl1_gov_sys.attr,
	&touch_boost_core_1_gov_sys.attr,
	&touch_boost_core_2_gov_sys.attr,
	&touch_boost_core_3_gov_sys.attr,
	&touch_boost_core_4_gov_sys.attr,
	&touch_boost_core_5_gov_sys.attr,
	&touch_boost_core_6_gov_sys.attr,
	&touch_boost_core_7_gov_sys.attr,
	&button_boost_screen_on_core_1_gov_sys.attr,
	&button_boost_screen_on_core_2_gov_sys.attr,
	&button_boost_screen_on_core_3_gov_sys.attr,
	&button_boost_screen_on_core_4_gov_sys.attr,
	&button_boost_screen_on_core_5_gov_sys.attr,
	&button_boost_screen_on_core_6_gov_sys.attr,
	&button_boost_screen_on_core_7_gov_sys.attr,
	&button_boost_screen_off_core_1_gov_sys.attr,
	&button_boost_screen_off_core_2_gov_sys.attr,
	&button_boost_screen_off_core_3_gov_sys.attr,
	&button_boost_screen_off_core_4_gov_sys.attr,
	&button_boost_screen_off_core_5_gov_sys.attr,
	&button_boost_screen_off_core_6_gov_sys.attr,
	&button_boost_screen_off_core_7_gov_sys.attr,
	&lockout_hotplug_screen_on_core_1_gov_sys.attr,
	&lockout_hotplug_screen_on_core_2_gov_sys.attr,
	&lockout_hotplug_screen_on_core_3_gov_sys.attr,
	&lockout_hotplug_screen_on_core_4_gov_sys.attr,
	&lockout_hotplug_screen_on_core_5_gov_sys.attr,
	&lockout_hotplug_screen_on_core_6_gov_sys.attr,
	&lockout_hotplug_screen_on_core_7_gov_sys.attr,
	&lockout_hotplug_screen_off_core_1_gov_sys.attr,
	&lockout_hotplug_screen_off_core_2_gov_sys.attr,
	&lockout_hotplug_screen_off_core_3_gov_sys.attr,
	&lockout_hotplug_screen_off_core_4_gov_sys.attr,
	&lockout_hotplug_screen_off_core_5_gov_sys.attr,
	&lockout_hotplug_screen_off_core_6_gov_sys.attr,
	&lockout_hotplug_screen_off_core_7_gov_sys.attr,
	&lockout_changes_when_boosting_gov_sys.attr,
	&touch_boost_gpu_gov_sys.attr,
	&cpu_load_adder_at_max_gpu_gov_sys.attr,
	&cpu_load_adder_at_max_gpu_ignore_tb_gov_sys.attr,
	&boost_hold_cycles_gov_sys.attr,
	&disable_hotplug_gov_sys.attr,
	&disable_hotplug_chrg_gov_sys.attr,
	&disable_hotplug_media_gov_sys.attr,
	&disable_hotplug_bt_gov_sys.attr,
	&no_extra_cores_screen_off_gov_sys.attr,
	&ignore_nice_load_gov_sys.attr,
	&freq_step_raise_screen_on_gov_sys.attr,
	&freq_step_raise_screen_off_gov_sys.attr,
	&freq_step_lower_screen_on_gov_sys.attr,
	&freq_step_lower_screen_off_gov_sys.attr,
	&debug_enabled_gov_sys.attr,
	NULL
};

static struct attribute_group dbs_attr_group_gov_sys = {
	.attrs = dbs_attributes_gov_sys,
	.name = "ktoonservative",
};

static struct attribute *dbs_attributes_gov_pol[] = {
	&sampling_rate_min_gov_pol.attr,
	&sampling_rate_gov_pol.attr,
	&sampling_rate_screen_off_gov_pol.attr,
	&up_threshold_screen_on_gov_pol.attr,
	&up_threshold_screen_on_hotplug_1_gov_pol.attr,
	&up_threshold_screen_on_hotplug_2_gov_pol.attr,
	&up_threshold_screen_on_hotplug_3_gov_pol.attr,
	&up_threshold_screen_on_hotplug_4_gov_pol.attr,
	&up_threshold_screen_on_hotplug_5_gov_pol.attr,
	&up_threshold_screen_on_hotplug_6_gov_pol.attr,
	&up_threshold_screen_on_hotplug_7_gov_pol.attr,
	&up_threshold_screen_off_gov_pol.attr,
	&up_threshold_screen_off_hotplug_1_gov_pol.attr,
	&up_threshold_screen_off_hotplug_2_gov_pol.attr,
	&up_threshold_screen_off_hotplug_3_gov_pol.attr,
	&up_threshold_screen_off_hotplug_4_gov_pol.attr,
	&up_threshold_screen_off_hotplug_5_gov_pol.attr,
	&up_threshold_screen_off_hotplug_6_gov_pol.attr,
	&up_threshold_screen_off_hotplug_7_gov_pol.attr,
	&down_threshold_screen_on_gov_pol.attr,
	&down_threshold_screen_on_hotplug_1_gov_pol.attr,
	&down_threshold_screen_on_hotplug_2_gov_pol.attr,
	&down_threshold_screen_on_hotplug_3_gov_pol.attr,
	&down_threshold_screen_on_hotplug_4_gov_pol.attr,
	&down_threshold_screen_on_hotplug_5_gov_pol.attr,
	&down_threshold_screen_on_hotplug_6_gov_pol.attr,
	&down_threshold_screen_on_hotplug_7_gov_pol.attr,
	&down_threshold_screen_off_gov_pol.attr,
	&down_threshold_screen_off_hotplug_1_gov_pol.attr,
	&down_threshold_screen_off_hotplug_2_gov_pol.attr,
	&down_threshold_screen_off_hotplug_3_gov_pol.attr,
	&down_threshold_screen_off_hotplug_4_gov_pol.attr,
	&down_threshold_screen_off_hotplug_5_gov_pol.attr,
	&down_threshold_screen_off_hotplug_6_gov_pol.attr,
	&down_threshold_screen_off_hotplug_7_gov_pol.attr,
	&block_cycles_online_screen_on_gov_pol.attr,
	&block_cycles_offline_screen_on_gov_pol.attr,
	&block_cycles_raise_screen_on_gov_pol.attr,
	&block_cycles_online_screen_off_gov_pol.attr,
	&block_cycles_offline_screen_off_gov_pol.attr,
	&block_cycles_raise_screen_off_gov_pol.attr,
	&super_conservative_screen_on_gov_pol.attr,
	&super_conservative_screen_off_gov_pol.attr,
	&touch_boost_cpu_cl0_gov_pol.attr,
	&touch_boost_cpu_cl1_gov_pol.attr,
	&touch_boost_core_1_gov_pol.attr,
	&touch_boost_core_2_gov_pol.attr,
	&touch_boost_core_3_gov_pol.attr,
	&touch_boost_core_4_gov_pol.attr,
	&touch_boost_core_5_gov_pol.attr,
	&touch_boost_core_6_gov_pol.attr,
	&touch_boost_core_7_gov_pol.attr,
	&button_boost_screen_on_core_1_gov_pol.attr,
	&button_boost_screen_on_core_2_gov_pol.attr,
	&button_boost_screen_on_core_3_gov_pol.attr,
	&button_boost_screen_on_core_4_gov_pol.attr,
	&button_boost_screen_on_core_5_gov_pol.attr,
	&button_boost_screen_on_core_6_gov_pol.attr,
	&button_boost_screen_on_core_7_gov_pol.attr,
	&button_boost_screen_off_core_1_gov_pol.attr,
	&button_boost_screen_off_core_2_gov_pol.attr,
	&button_boost_screen_off_core_3_gov_pol.attr,
	&button_boost_screen_off_core_4_gov_pol.attr,
	&button_boost_screen_off_core_5_gov_pol.attr,
	&button_boost_screen_off_core_6_gov_pol.attr,
	&button_boost_screen_off_core_7_gov_pol.attr,
	&lockout_hotplug_screen_on_core_1_gov_pol.attr,
	&lockout_hotplug_screen_on_core_2_gov_pol.attr,
	&lockout_hotplug_screen_on_core_3_gov_pol.attr,
	&lockout_hotplug_screen_on_core_4_gov_pol.attr,
	&lockout_hotplug_screen_on_core_5_gov_pol.attr,
	&lockout_hotplug_screen_on_core_6_gov_pol.attr,
	&lockout_hotplug_screen_on_core_7_gov_pol.attr,
	&lockout_hotplug_screen_off_core_1_gov_pol.attr,
	&lockout_hotplug_screen_off_core_2_gov_pol.attr,
	&lockout_hotplug_screen_off_core_3_gov_pol.attr,
	&lockout_hotplug_screen_off_core_4_gov_pol.attr,
	&lockout_hotplug_screen_off_core_5_gov_pol.attr,
	&lockout_hotplug_screen_off_core_6_gov_pol.attr,
	&lockout_hotplug_screen_off_core_7_gov_pol.attr,
	&lockout_changes_when_boosting_gov_pol.attr,
	&touch_boost_gpu_gov_pol.attr,
	&cpu_load_adder_at_max_gpu_gov_pol.attr,
	&cpu_load_adder_at_max_gpu_ignore_tb_gov_pol.attr,
	&boost_hold_cycles_gov_pol.attr,
	&disable_hotplug_gov_pol.attr,
	&disable_hotplug_chrg_gov_pol.attr,
	&disable_hotplug_media_gov_pol.attr,
	&disable_hotplug_bt_gov_pol.attr,
	&no_extra_cores_screen_off_gov_pol.attr,
	&ignore_nice_load_gov_pol.attr,
	&freq_step_raise_screen_on_gov_pol.attr,
	&freq_step_raise_screen_off_gov_pol.attr,
	&freq_step_lower_screen_on_gov_pol.attr,
	&freq_step_lower_screen_off_gov_pol.attr,
	&debug_enabled_gov_pol.attr,
	NULL
};

static const char *ktoonservative_sysfs[] = {
	"sampling_rate_min",
	"sampling_rate",
	"sampling_rate_screen_off",
	"up_threshold_screen_on",
	"up_threshold_screen_on_hotplug_1",
	"up_threshold_screen_on_hotplug_2",
	"up_threshold_screen_on_hotplug_3",
	"up_threshold_screen_on_hotplug_4",
	"up_threshold_screen_on_hotplug_5",
	"up_threshold_screen_on_hotplug_6",
	"up_threshold_screen_on_hotplug_7",
	"up_threshold_screen_off",
	"up_threshold_screen_off_hotplug_1",
	"up_threshold_screen_off_hotplug_2",
	"up_threshold_screen_off_hotplug_3",
	"up_threshold_screen_off_hotplug_4",
	"up_threshold_screen_off_hotplug_5",
	"up_threshold_screen_off_hotplug_6",
	"up_threshold_screen_off_hotplug_7",
	"down_threshold_screen_on",
	"down_threshold_screen_on_hotplug_1",
	"down_threshold_screen_on_hotplug_2",
	"down_threshold_screen_on_hotplug_3",
	"down_threshold_screen_on_hotplug_4",
	"down_threshold_screen_on_hotplug_5",
	"down_threshold_screen_on_hotplug_6",
	"down_threshold_screen_on_hotplug_7",
	"down_threshold_screen_off",
	"down_threshold_screen_off_hotplug_1",
	"down_threshold_screen_off_hotplug_2",
	"down_threshold_screen_off_hotplug_3",
	"down_threshold_screen_off_hotplug_4",
	"down_threshold_screen_off_hotplug_5",
	"down_threshold_screen_off_hotplug_6",
	"down_threshold_screen_off_hotplug_7",
	"block_cycles_online_screen_on",
	"block_cycles_offline_screen_on",
	"block_cycles_raise_screen_on",
	"block_cycles_online_screen_off",
	"block_cycles_offline_screen_off",
	"block_cycles_raise_screen_off",
	"super_conservative_screen_on",
	"super_conservative_screen_off",
	"touch_boost_cpu_cl0",
	"touch_boost_cpu_cl1",
	"touch_boost_core_1",
	"touch_boost_core_2",
	"touch_boost_core_4",
	"touch_boost_core_5",
	"touch_boost_core_6",
	"touch_boost_core_7",
	"button_boost_screen_on_core_1",
	"button_boost_screen_on_core_2",
	"button_boost_screen_on_core_3",
	"button_boost_screen_on_core_4",
	"button_boost_screen_on_core_5",
	"button_boost_screen_on_core_6",
	"button_boost_screen_on_core_7",
	"button_boost_screen_off_core_1",
	"button_boost_screen_off_core_2",
	"button_boost_screen_off_core_3",
	"button_boost_screen_off_core_4",
	"button_boost_screen_off_core_5",
	"button_boost_screen_off_core_6",
	"button_boost_screen_off_core_7",
	"lockout_hotplug_screen_on_core_1",
	"lockout_hotplug_screen_on_core_2",
	"lockout_hotplug_screen_on_core_3",
	"lockout_hotplug_screen_on_core_4",
	"lockout_hotplug_screen_on_core_5",
	"lockout_hotplug_screen_on_core_6",
	"lockout_hotplug_screen_on_core_7",
	"lockout_hotplug_screen_off_core_1",
	"lockout_hotplug_screen_off_core_2",
	"lockout_hotplug_screen_off_core_3",
	"lockout_hotplug_screen_off_core_4",
	"lockout_hotplug_screen_off_core_5",
	"lockout_hotplug_screen_off_core_6",
	"lockout_hotplug_screen_off_core_7",
	"lockout_changes_when_boosting",
	"touch_boost_gpu",
	"cpu_load_adder_at_max_gpu",
	"cpu_load_adder_at_max_gpu_ignore_tb",
	"boost_hold_cycles",
	"disable_hotplug",
	"disable_hotplug_chrg",
	"disable_hotplug_media",
	"disable_hotplug_bt",
	"no_extra_cores_screen_off",
	"ignore_nice_load",
	"freq_step_raise_screen_on",
	"freq_step_raise_screen_off",
	"freq_step_lower_screen_on",
	"freq_step_lower_screen_off",
	"debug_enabled",
};

static struct attribute_group dbs_attr_group_gov_pol = {
	.attrs = dbs_attributes_gov_pol,
	.name = "ktoonservative",
};

static struct attribute_group *get_sysfs_attr(void)
{
	if (have_governor_per_policy())
		return &dbs_attr_group_gov_pol;
	else
		return &dbs_attr_group_gov_sys;
}

/************************** sysfs end ************************/

static bool check_freq_increase(struct cpufreq_ktoonservative_cpuinfo *this_dbs_info, struct cpufreq_policy *policy, unsigned int max_load)
{
	unsigned int freq_target;
	struct cpufreq_ktoonservative_tunables *tunables = policy->governor_data;
	if ((screen_is_on && max_load > tunables->up_threshold_screen_on) || (!screen_is_on && max_load > tunables->up_threshold_screen_off)) {
		if ((screen_is_on && this_dbs_info->Lblock_cycles_raise >= tunables->block_cycles_raise_screen_on) || (!screen_is_on && this_dbs_info->Lblock_cycles_raise >= tunables->block_cycles_raise_screen_off)) // || ((screen_is_on && dbs_tuners_ins.super_conservative_screen_on == 0) || call_in_progress) || ((!screen_is_on && dbs_tuners_ins.super_conservative_screen_off == 0) || call_in_progress))
		{
			if (screen_is_on)
				freq_target = (tunables->freq_step_raise_screen_on * policy->max) / 100;
			else
				freq_target = (tunables->freq_step_raise_screen_off * policy->max) / 100;

			/* max freq cannot be less than 100. But who knows.... */
			if (unlikely(freq_target == 0))
				freq_target = 5;

			this_dbs_info->requested_freq += freq_target;
			if (this_dbs_info->requested_freq > policy->max)
				this_dbs_info->requested_freq = policy->max;

			if ((!call_in_progress && screen_is_on && tunables->super_conservative_screen_on) || (!call_in_progress && !screen_is_on && tunables->super_conservative_screen_off))
				this_dbs_info->Lblock_cycles_raise = 0;
			return true;
		}
		if (this_dbs_info->Lblock_cycles_raise < 1000)
			this_dbs_info->Lblock_cycles_raise++;
	}
	else if ((!call_in_progress && screen_is_on && tunables->super_conservative_screen_on) || (!call_in_progress && !screen_is_on && tunables->super_conservative_screen_off))
		this_dbs_info->Lblock_cycles_raise = 0;

	return false;
}

static bool check_freq_decrease(struct cpufreq_ktoonservative_cpuinfo *this_dbs_info, struct cpufreq_policy *policy, unsigned int max_load)
{
	unsigned int freq_target;
	struct cpufreq_ktoonservative_tunables *tunables = policy->governor_data;
	if (((screen_is_on && max_load < (tunables->down_threshold_screen_on - 10)) || (!screen_is_on && max_load < (tunables->down_threshold_screen_off - 10))))
	{
		if (screen_is_on)
			freq_target = (tunables->freq_step_lower_screen_on * policy->max) / 100;
		else
			freq_target = (tunables->freq_step_lower_screen_off * policy->max) / 100;

		this_dbs_info->requested_freq -= freq_target;
		if (this_dbs_info->requested_freq < policy->min)
			this_dbs_info->requested_freq = policy->min;

		/* if we cannot reduce the frequency anymore, break out early */
		if (policy->cur == policy->min && this_dbs_info->requested_freq == policy->min)
		{
			this_dbs_info->Lblock_cycles_raise = 0;
			return false;
		}
		return true;
	}
	return false;
}

static void dbs_check_cpu(struct cpufreq_ktoonservative_cpuinfo *this_dbs_info)
{
	unsigned int load = 0;
	unsigned int max_load = 0;
	unsigned int freq_target;
	int cpu;
	bool had_load_but_counting = false;
	struct cpufreq_policy *policy;
	unsigned int j;
	bool retInc;
	bool retDec;
	int loopStart, loopStop, cpuLoop;
	struct cpufreq_ktoonservative_tunables *tunables;

	policy = this_dbs_info->policy;
	if (!policy || policy == NULL)
		return;
	tunables = policy->governor_data;
	if (!tunables || tunables == NULL)
		return;

	/*
	 * Every sampling_rate, we check, if current idle time is less
	 * than 20% (default), then we try to increase frequency
	 * Every sampling_rate, we check, if current
	 * idle time is more than 80%, then we try to decrease frequency
	 *
	 * Any frequency increase takes it to the maximum frequency.
	 * Frequency reduction happens at minimum steps of
	 * 5% (default) of maximum frequency
	 */

	/* Get Absolute Load */
	for_each_cpu(j, policy->cpus) {
		struct cpufreq_ktoonservative_cpuinfo *j_dbs_info;
		cputime64_t cur_wall_time, cur_idle_time;
		unsigned int idle_time, wall_time;
		j_dbs_info = &per_cpu(cpuinfo, j);
		cur_idle_time = get_cpu_idle_time(j, &cur_wall_time);
		wall_time = (unsigned int)
			(cur_wall_time - j_dbs_info->prev_cpu_wall);
		j_dbs_info->prev_cpu_wall = cur_wall_time;
		idle_time = (unsigned int)
			(cur_idle_time - j_dbs_info->prev_cpu_idle);
		j_dbs_info->prev_cpu_idle = cur_idle_time;
		if (tunables->ignore_nice_load) {
			u64 cur_nice;
			unsigned long cur_nice_jiffies;
			cur_nice = kcpustat_cpu(j).cpustat[CPUTIME_NICE] -
					 j_dbs_info->prev_cpu_nice;
			cur_nice_jiffies = (unsigned long)
					cputime64_to_jiffies64(cur_nice);
			j_dbs_info->prev_cpu_nice = kcpustat_cpu(j).cpustat[CPUTIME_NICE];
			idle_time += jiffies_to_usecs(cur_nice_jiffies);
		}
		if (unlikely(!wall_time || wall_time < idle_time))
			continue;
		load = 100 * (wall_time - idle_time) / wall_time;
		if (load > max_load)
			max_load = load;
		if (debug_is_enabled)
			pr_alert("CHECK LOAD : CPU=%d  LOAD=%d  Block Offline=%d  Block Online=%d\n", j, load, Lblock_cycles_offline[j], this_dbs_info->Lblock_cycles_online);
		cpu_load[j] = max_load;
	}
		
	//Check for block cycle overrides
	if (Lblock_cycles_offline_OVERRIDE[policy->cpu] != OVERRIDE_DISABLER)
	{
		Lblock_cycles_offline[policy->cpu] = Lblock_cycles_offline_OVERRIDE[policy->cpu];
		Lblock_cycles_offline_OVERRIDE[policy->cpu] = OVERRIDE_DISABLER;
	}
	if (Lblock_cycles_online_OVERRIDE[policy->cpu] != OVERRIDE_DISABLER)
	{
		this_dbs_info->Lblock_cycles_online = Lblock_cycles_online_OVERRIDE[policy->cpu];
		Lblock_cycles_online_OVERRIDE[policy->cpu] = OVERRIDE_DISABLER;
	}

	 //Adjust CPU load when GPU is maxed out
	if (tunables->cpu_load_adder_at_max_gpu > 0)
	{
		if ((!boostpulse_relayf || (boostpulse_relayf && !tunables->cpu_load_adder_at_max_gpu_ignore_tb)) && cur_gpu_step == gpu_max_override)
		{
			max_load += tunables->cpu_load_adder_at_max_gpu;
			if (max_load > 100)
				max_load = 100;
		}
	}
	
	if (policy->cpu == 0)
	{
		loopStart = 1;
		loopStop = 3;
	}
	else
	{
		loopStart = 5;
		loopStop = 7;
	}
			
	//Hotplugable CPU's only
	for (cpuLoop = loopStart; cpuLoop <= loopStop; cpuLoop++)
	{
		//Check for block cycle overrides
		if (Lblock_cycles_offline_OVERRIDE[cpuLoop] != OVERRIDE_DISABLER)
		{
			Lblock_cycles_offline[cpuLoop] = Lblock_cycles_offline_OVERRIDE[cpuLoop];
			Lblock_cycles_offline_OVERRIDE[cpuLoop] = OVERRIDE_DISABLER;
		}

		if (!boostpulse_relayf || (boostpulse_relayf && !tunables->lockout_changes_when_boosting))
		{
			//Use CPU0 load if we are low just to keep things evened out
			if (cpuLoop >= 1 && cpuLoop <= 3)
			{
				if (max_load < cpu_load[0])
					max_load = cpu_load[0];
			}
			else
			{
			if (max_load < cpu_load[4])
				max_load = cpu_load[4];
			}
			//Check to see if we can take this CPU offline
			if (max_load <= hotplug_cpu_enable_down[cpuLoop] && hotplug_cpu_lockout[cpuLoop] != 1 && !tunables->disable_hotplug && !disable_hotplug_chrg_override && !disable_hotplug_media_override && !disable_hotplug_bt_active)
			{
				//Make CPU's go offline in reverse order
				bool got_higher_online = false;
				//if (cpuLoop < loopStop)
				//{
				//	if (cpu_online(cpuLoop + 1))
				//		got_higher_online = true;
				//}
			
				if (!main_cpufreq_control[cpuLoop] && !hotplug_cpu_single_down[cpuLoop] && (!boostpulse_relayf || (boostpulse_relayf && !hotplug_cpu_boosted[cpuLoop])))
				{
					if (!got_higher_online && ((screen_is_on && Lblock_cycles_offline[cpuLoop] > tunables->block_cycles_offline_screen_on) || (!screen_is_on && Lblock_cycles_offline[cpuLoop] > tunables->block_cycles_offline_screen_off)))
					{
						set_core_flag_down(cpuLoop, 1);
						set_core_flag_up(cpuLoop, 0);
						queue_work_on(cpuLoop, dbs_wq, &hotplug_offline_work);
						Lblock_cycles_offline[cpuLoop] = 0;
						goto exitSecondaries;
					}
					if (Lblock_cycles_offline[cpuLoop] < 1000)
						Lblock_cycles_offline[cpuLoop]++;
				}
			}
			else
			{
				if (Lblock_cycles_offline[cpuLoop] > 0)
					Lblock_cycles_offline[cpuLoop]--;
			}
		}
	}
exitSecondaries:

	if (debug_is_enabled >= 2)
	{
		//pr_alert("LOAD=%d\n   CPUsonline=%d\n   CPUsonlineish=%d\n   CPU1flag=%d | %d | %d\n   CPU2flag=%d | %d | %d\n   CPU3flag=%d | %d | %d\n   KT Freq1=%d\n   KT Freq2=%d\n   KT Freq3=%d\n   Block Offline=%d\n"
		pr_alert("CPUsonline=%d\n   CPU0flag=%d | %d | %d\n   CPU1flag=%d | %d | %d\n   CPU2flag=%d | %d | %d\n   CPU3flag=%d | %d | %d\n   CPU4flag=%d | %d | %d\n   CPU5flag=%d | %d | %d\n   CPU6flag=%d | %d | %d\n   CPU7flag=%d | %d | %d\n"
			, tunables->usage_count
			, hotplug_cpu_single_up[0], hotplug_cpu_single_down[0], cpu_load[0]
			, hotplug_cpu_single_up[1], hotplug_cpu_single_down[1], cpu_load[1]
			, hotplug_cpu_single_up[2], hotplug_cpu_single_down[2], cpu_load[2]
			, hotplug_cpu_single_up[3], hotplug_cpu_single_down[3], cpu_load[3]
			, hotplug_cpu_single_up[4], hotplug_cpu_single_down[4], cpu_load[4]
			, hotplug_cpu_single_up[5], hotplug_cpu_single_down[5], cpu_load[5]
			, hotplug_cpu_single_up[6], hotplug_cpu_single_down[6], cpu_load[6]
			, hotplug_cpu_single_up[7], hotplug_cpu_single_down[7], cpu_load[7]);
	}
	
	//If we are in boost mode and user requests to lockout all changes during boost skip all frequency modification
	if (boostpulse_relayf && tunables->lockout_changes_when_boosting)
		goto skip_it_all;

	if ((screen_is_on && tunables->freq_step_raise_screen_on == 0) || (!screen_is_on && tunables->freq_step_raise_screen_off == 0))
		return;
	
	//Check cpu online status
	if (!tunables->no_extra_cores_screen_off || screen_is_on)
	{
		for (cpu = loopStart; cpu <= loopStop; cpu++)
		{
			//Remove up flag from cpu if it is already online
			if (cpu_online(cpu) && hotplug_cpu_single_up[cpu])
				set_core_flag_up(cpu, 0);

			if (max_load >= hotplug_cpu_enable_up[cpu] && (!cpu_online(cpu)) && hotplug_cpu_lockout[cpu] != 2)
			{
				if (!hotplug_cpu_single_up[cpu] && ((screen_is_on && this_dbs_info->Lblock_cycles_online >= tunables->block_cycles_online_screen_on) || (!screen_is_on && this_dbs_info->Lblock_cycles_online >= tunables->block_cycles_online_screen_off)))
				{
					set_core_flag_up(cpu, 1);
					if (debug_is_enabled)
						pr_alert("BOOST CORES %d - %d - %d - %d - %d - %d - %d - %d - %d\n", cpu, this_dbs_info->Lblock_cycles_online, hotplug_cpu_single_up[1], hotplug_cpu_single_up[2], hotplug_cpu_single_up[3], hotplug_cpu_single_up[4], hotplug_cpu_single_up[5], hotplug_cpu_single_up[6], hotplug_cpu_single_up[7]);
					set_core_flag_down(cpu, 0);
					hotplug_flag_on = true;
					this_dbs_info->Lblock_cycles_online = 0;
				}
				if (this_dbs_info->Lblock_cycles_online < 1000)
					this_dbs_info->Lblock_cycles_online++;
				had_load_but_counting = true;
				break;
			}
		}
	}
	/* Check to see if we set the hotplug_on flag to bring up more cores */
	if (hotplug_flag_on)
	{
		if (policy->cur > (policy->min * 2))
		{
			hotplug_flag_on = false;
			queue_work_on(policy->cpu, dbs_wq, &hotplug_online_work);
		}
		else
		{
			for (cpu = loopStart; cpu <= loopStop; cpu++)
				set_core_flag_up(cpu, 0);
		}
	}
	else if (!call_in_progress && ((screen_is_on && tunables->super_conservative_screen_on) || (!screen_is_on && tunables->super_conservative_screen_off)))
	{
		if (!had_load_but_counting)
			this_dbs_info->Lblock_cycles_online = 0;
	}
	
	/* Check for frequency increase */
	retInc = check_freq_increase(this_dbs_info, policy, max_load);
	/* Check for frequency decrease */
	retDec = check_freq_decrease(this_dbs_info, policy, max_load);
	if (!boostpulse_relayf && (retInc || retDec))
	{
		__cpufreq_driver_target(policy, this_dbs_info->requested_freq, CPUFREQ_RELATION_H);
		return;
	}
	
skip_it_all:
	//boost code
	if (boostpulse_relayf)
	{
		if (stored_sampling_rate != 0 && screen_is_on)
			tunables->sampling_rate = stored_sampling_rate;
		
		//Boost is complete
		if (boost_hold_cycles_cnt >= tunables->boost_hold_cycles)
		{
			boostpulse_relayf = false;
			boost_hold_cycles_cnt = 0;
			for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)
				hotplug_cpu_boosted[cpu] = 0;
			boost_the_gpu(tunables->touch_boost_gpu, false);
			//if (turned_off_super_conservative_screen_off)
			//{
			//	tunables->super_conservative_screen_off = 1;
			//	turned_off_super_conservative_screen_off = false;
			//}
			if (fake_screen_on)
			{
				//if (!screen_is_on)
				//	cpufreq_gov_suspend();
				fake_screen_on = false;
			}
			goto boostcomplete;
		}
		boost_hold_cycles_cnt++;
			
		if (tunables->lockout_changes_when_boosting)
			this_dbs_info->requested_freq = touch_boost_cpu_array[policy->cpu];
			
		if (touch_boost_cpu_array[policy->cpu] > this_dbs_info->requested_freq)
			this_dbs_info->requested_freq = touch_boost_cpu_array[policy->cpu];
		
		if (this_dbs_info->requested_freq != policy->cur)
			__cpufreq_driver_target(policy, this_dbs_info->requested_freq, CPUFREQ_RELATION_H);
boostcomplete:
		return;
	}

}

void set_core_flag_up(unsigned int cpu, unsigned int val)
{
	spin_lock(&cpufreq_up_lock);
	hotplug_cpu_single_up[cpu] = val;
	spin_unlock(&cpufreq_up_lock);
}

void set_core_flag_down(unsigned int cpu, unsigned int val)
{
	spin_lock(&cpufreq_down_lock);
	hotplug_cpu_single_down[cpu] = val;
	spin_unlock(&cpufreq_down_lock);
}

void check_boost_cores_up(unsigned int boostBools[])
{
	bool got_boost_core = false;
	int cpu;
	for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)
	{
		if (!hotplug_cpu_single_up[cpu] && !cpu_online(cpu) && (boostBools[cpu] || hotplug_cpu_lockout[cpu] == 1) && hotplug_cpu_lockout[cpu] != 2)
		{
			set_core_flag_up(cpu, 1);
			hotplug_cpu_boosted[cpu] = 1;
			got_boost_core = true;
		}
	}
	
	if (got_boost_core)
	{
		if (debug_is_enabled)
			pr_alert("CHECK BOOST CORES UP %d - %d - %d - %d - %d - %d - %d\n", hotplug_cpu_single_up[1], hotplug_cpu_single_up[2], hotplug_cpu_single_up[3], hotplug_cpu_single_up[4], hotplug_cpu_single_up[5], hotplug_cpu_single_up[6], hotplug_cpu_single_up[7]);
		queue_work_on(0, dbs_wq, &hotplug_online_work);
	}
}

void ktoonservative_screen_is_on(bool state, int cpu)
{
	bool need_to_queue_up = false;
	bool need_to_queue_down = false;
	unsigned int cpuloop;
	struct cpufreq_ktoonservative_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_ktoonservative_tunables *tunables;
	
	if (pcpu)
	{
		if (pcpu->policy)
		{
			tunables = pcpu->policy->governor_data;
			if (!tunables)
				return;
		}
		else
			return;
	}
	else
		return;
		
	if (state)
	{
		//Set hotplug options when screen is on
		hotplug_cpu_enable_up[1] = tunables->up_threshold_screen_on_hotplug_1;
		hotplug_cpu_enable_up[2] = tunables->up_threshold_screen_on_hotplug_2;
		hotplug_cpu_enable_up[3] = tunables->up_threshold_screen_on_hotplug_3;
		hotplug_cpu_enable_up[4] = tunables->up_threshold_screen_on_hotplug_4;
		hotplug_cpu_enable_up[5] = tunables->up_threshold_screen_on_hotplug_5;
		hotplug_cpu_enable_up[6] = tunables->up_threshold_screen_on_hotplug_6;
		hotplug_cpu_enable_up[7] = tunables->up_threshold_screen_on_hotplug_7;
		hotplug_cpu_enable_down[1] = tunables->down_threshold_screen_on_hotplug_1;
		hotplug_cpu_enable_down[2] = tunables->down_threshold_screen_on_hotplug_2;
		hotplug_cpu_enable_down[3] = tunables->down_threshold_screen_on_hotplug_3;
		hotplug_cpu_enable_down[4] = tunables->down_threshold_screen_on_hotplug_4;
		hotplug_cpu_enable_down[5] = tunables->down_threshold_screen_on_hotplug_5;
		hotplug_cpu_enable_down[6] = tunables->down_threshold_screen_on_hotplug_6;
		hotplug_cpu_enable_down[7] = tunables->down_threshold_screen_on_hotplug_7;
	
		//Set core lockout options when screen is on
		hotplug_cpu_lockout[1] = tunables->lockout_hotplug_screen_on_core_1;
		hotplug_cpu_lockout[2] = tunables->lockout_hotplug_screen_on_core_2;
		hotplug_cpu_lockout[3] = tunables->lockout_hotplug_screen_on_core_3;
		hotplug_cpu_lockout[4] = tunables->lockout_hotplug_screen_on_core_4;
		hotplug_cpu_lockout[5] = tunables->lockout_hotplug_screen_on_core_5;
		hotplug_cpu_lockout[6] = tunables->lockout_hotplug_screen_on_core_6;
		hotplug_cpu_lockout[7] = tunables->lockout_hotplug_screen_on_core_7;
		for (cpuloop = 1; cpuloop < CPUS_AVAILABLE; cpuloop++)
		{
			if (hotplug_cpu_lockout[cpuloop] == 1)
				set_core_flag_up(cpuloop, 1);
			if (hotplug_cpu_lockout[cpuloop] == 2)
				set_core_flag_down(cpuloop, 1);
		}
			
		if (stored_sampling_rate > 0)
			tunables->sampling_rate = stored_sampling_rate; //max(input, min_sampling_rate);
		ktoonservative_boostpulse(true);
		//Core #4 cheat when turning screen back on
		if (!cpu_online(4) && !hotplug_cpu_single_up[4])
		{
			set_core_flag_up(4, 1);
			set_core_flag_down(4, 0);
			queue_work_on(0, dbs_wq, &hotplug_online_work);
		}
	}
	else
	{
		//Set hotplug options when screen is off
		hotplug_cpu_enable_up[1] = tunables->up_threshold_screen_off_hotplug_1;
		hotplug_cpu_enable_up[2] = tunables->up_threshold_screen_off_hotplug_2;
		hotplug_cpu_enable_up[3] = tunables->up_threshold_screen_off_hotplug_3;
		hotplug_cpu_enable_up[4] = tunables->up_threshold_screen_off_hotplug_4;
		hotplug_cpu_enable_up[5] = tunables->up_threshold_screen_off_hotplug_5;
		hotplug_cpu_enable_up[6] = tunables->up_threshold_screen_off_hotplug_6;
		hotplug_cpu_enable_up[7] = tunables->up_threshold_screen_off_hotplug_7;
		hotplug_cpu_enable_down[1] = tunables->down_threshold_screen_off_hotplug_1;
		hotplug_cpu_enable_down[2] = tunables->down_threshold_screen_off_hotplug_2;
		hotplug_cpu_enable_down[3] = tunables->down_threshold_screen_off_hotplug_3;
		hotplug_cpu_enable_down[4] = tunables->down_threshold_screen_off_hotplug_4;
		hotplug_cpu_enable_down[5] = tunables->down_threshold_screen_off_hotplug_5;
		hotplug_cpu_enable_down[6] = tunables->down_threshold_screen_off_hotplug_6;
		hotplug_cpu_enable_down[7] = tunables->down_threshold_screen_off_hotplug_7;

		//Set core lockout options when screen is on
		hotplug_cpu_lockout[1] = tunables->lockout_hotplug_screen_off_core_1;
		hotplug_cpu_lockout[2] = tunables->lockout_hotplug_screen_off_core_2;
		hotplug_cpu_lockout[3] = tunables->lockout_hotplug_screen_off_core_3;
		hotplug_cpu_lockout[4] = tunables->lockout_hotplug_screen_off_core_4;
		hotplug_cpu_lockout[5] = tunables->lockout_hotplug_screen_off_core_5;
		hotplug_cpu_lockout[6] = tunables->lockout_hotplug_screen_off_core_6;
		hotplug_cpu_lockout[7] = tunables->lockout_hotplug_screen_off_core_7;
		for (cpuloop = 1; cpuloop < CPUS_AVAILABLE; cpuloop++)
		{
			if (hotplug_cpu_lockout[cpuloop] == 1 && (!tunables->no_extra_cores_screen_off))
			{
				set_core_flag_up(cpuloop, 1);
				need_to_queue_up = true;
			}
			if ((hotplug_cpu_lockout[cpuloop] == 2 || tunables->no_extra_cores_screen_off) && !main_cpufreq_control[cpuloop])
			{
				set_core_flag_down(cpuloop, 1);
				need_to_queue_down = true;
			}
		}
		if (need_to_queue_up)
			queue_work_on(0, dbs_wq, &hotplug_online_work);
		if (need_to_queue_down)
			queue_work_on(0, dbs_wq, &hotplug_offline_work);

		boost_the_gpu(tunables->touch_boost_gpu, false);
		stored_sampling_rate = tunables->sampling_rate;
		tunables->sampling_rate = tunables->sampling_rate_screen_off;
	}
}

void ktoonservative_boostpulse(bool boost_for_button)
{
	unsigned int cpu;
	struct cpufreq_ktoonservative_cpuinfo *pcpu = &per_cpu(cpuinfo, 0);
	struct cpufreq_ktoonservative_tunables *tunables =
		pcpu->policy->governor_data;
	if (!boostpulse_relayf)
	{
		if (tunables->touch_boost_gpu > 0)  // && screen_is_on
		{
			boost_the_gpu(tunables->touch_boost_gpu, true);
			boostpulse_relayf = true;
			boost_hold_cycles_cnt = 0;
		}
		
		if (boost_bools_touch_are_present || boost_bools_button_son_are_present || boost_bools_button_soff_are_present || tunables->touch_boost_cpu_cl0 || tunables->touch_boost_cpu_cl1)
		{
			if (boost_for_button)
			{
				if (screen_is_on)
					check_boost_cores_up(boost_bools_button_son);
				else
				{
					fake_screen_on = true;
					//if (tunables->super_conservative_screen_off)
					//{
					//	tunables->super_conservative_screen_off = 0;
					//	turned_off_super_conservative_screen_off = true;
					//}
					check_boost_cores_up(boost_bools_button_soff);
				}
			}
			else
				check_boost_cores_up(boost_bools_touch);
			boostpulse_relayf = true;
			boost_hold_cycles_cnt = 0;
		}
		if (screen_is_on)
		{
			for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)
			{
				if (Lblock_cycles_offline_OVERRIDE[cpu] > 0 || Lblock_cycles_offline_OVERRIDE[cpu] == OVERRIDE_DISABLER)
					Lblock_cycles_offline_OVERRIDE[cpu] = 0;
			}
		}
		else
		{
			for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)
			{
				if (Lblock_cycles_offline_OVERRIDE[cpu] > 0 || Lblock_cycles_offline_OVERRIDE[cpu] == OVERRIDE_DISABLER)
					Lblock_cycles_offline_OVERRIDE[cpu] = (tunables->block_cycles_offline_screen_on * -4);
			}
		}
		for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)
		{
			if (Lblock_cycles_online_OVERRIDE[cpu] > 0 || Lblock_cycles_online_OVERRIDE[cpu] == OVERRIDE_DISABLER)
				Lblock_cycles_online_OVERRIDE[cpu] = 0;
		}
		
		//tunables->sampling_rate = min_sampling_rate;
		if (debug_is_enabled)
			pr_info("BOOSTPULSE RELAY KT Screen On=%d  BoostT=%d  BoostBon=%d  BoostBoff=%d  BoostCL0=%d  BoostCL1=%d\n", screen_is_on, boost_bools_touch_are_present, boost_bools_button_son_are_present, boost_bools_button_soff_are_present, tunables->touch_boost_cpu_cl0, tunables->touch_boost_cpu_cl1);
	}
	else
	{
		boost_hold_cycles_cnt = 0;
		for (cpu = 0; cpu < CPUS_AVAILABLE; cpu++)
		{
			if (Lblock_cycles_offline_OVERRIDE[cpu] > 0 || Lblock_cycles_offline_OVERRIDE[cpu] == OVERRIDE_DISABLER)
				Lblock_cycles_offline_OVERRIDE[cpu] = 0;
		}
		if (debug_is_enabled)
			pr_info("BOOSTPULSE RELAY KT RESET VALS- %d\n", screen_is_on);
	}
}

static void __cpuinit hotplug_offline_work_fn(struct work_struct *work)
{
	int cpu;

	for (cpu = CPUS_AVAILABLE-1; cpu > 0; cpu--)
	{
		if (likely(cpu_online(cpu) && (cpu))) {
			if (hotplug_cpu_single_down[cpu] && !hotplug_cpu_single_up[cpu] && !main_cpufreq_control[cpu])
			{
				if (debug_is_enabled)
					pr_alert("BOOST CORES DOWN WORK FUNC %d - %d - %d - %d\n", cpu, hotplug_cpu_single_down[1], hotplug_cpu_single_down[2], hotplug_cpu_single_down[3]);
				cpu_down(cpu);
				set_core_flag_down(cpu, 0);
			}
		}
		if (hotplug_cpu_single_up[cpu])
			set_core_flag_up(cpu, 0);
	}
	hotplugInProgress = false;
}

static void __cpuinit hotplug_online_work_fn(struct work_struct *work)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (likely(!cpu_online(cpu) && (cpu))) {
			if (hotplug_cpu_single_up[cpu] && !hotplug_cpu_single_down[cpu])
			{
				if (debug_is_enabled)
					pr_alert("BOOST CORES UP WORK FUNC %d - %d - %d - %d - %d - %d - %d - %d\n", cpu, hotplug_cpu_single_up[1], hotplug_cpu_single_up[2], hotplug_cpu_single_up[3], hotplug_cpu_single_up[4], hotplug_cpu_single_up[5], hotplug_cpu_single_up[6], hotplug_cpu_single_up[7]);
				cpu_up(cpu);
				set_core_flag_up(cpu, 0);
			}
		}
		if (hotplug_cpu_single_down[cpu])
			set_core_flag_down(cpu, 0);
	}
	hotplugInProgress = false;
}

static void do_dbs_timer(struct work_struct *work)
{
	unsigned int cpu;
	int delay;
	struct cpufreq_ktoonservative_cpuinfo *dbs_info =
		container_of(work, struct cpufreq_ktoonservative_cpuinfo, work.work);
	struct cpufreq_ktoonservative_tunables *tunables;
	if (!dbs_info)
		return;
	if (!dbs_info->policy)
		return;
	if (!dbs_info->policy->governor_data)
		return;

	cpu = dbs_info->cpu;
	tunables = dbs_info->policy->governor_data;

	/* We want all CPUs to do sampling nearly on same jiffy */
	delay = usecs_to_jiffies(tunables->sampling_rate);

	delay -= jiffies % delay;

	mutex_lock(&dbs_info->timer_mutex);

	dbs_check_cpu(dbs_info);

	if (dbs_info->enable)
		schedule_delayed_work_on(cpu, &dbs_info->work, delay);
		//queue_delayed_work_on(cpu, dbs_wq, &dbs_info->work, delay);
	mutex_unlock(&dbs_info->timer_mutex);
}

static inline void dbs_timer_init(struct cpufreq_ktoonservative_cpuinfo *dbs_info)
{
	struct cpufreq_ktoonservative_tunables *tunables =
		dbs_info->policy->governor_data;
	/* We want all CPUs to do sampling nearly on same jiffy */
	int delay = usecs_to_jiffies(tunables->sampling_rate);
	delay -= jiffies % delay;

	dbs_info->enable = 1;
	//INIT_DELAYED_WORK_DEFERRABLE(&dbs_info->work, do_dbs_timer);
	//queue_delayed_work_on(dbs_info->cpu, dbs_wq, &dbs_info->work, delay);
	INIT_DELAYED_WORK(&dbs_info->work, do_dbs_timer);
	schedule_delayed_work_on(dbs_info->cpu, &dbs_info->work, delay);
}

static inline void dbs_timer_exit(struct cpufreq_ktoonservative_cpuinfo *dbs_info)
{
	dbs_info->enable = 0;
	cancel_delayed_work_sync(&dbs_info->work);
}

static void cpufreq_param_set_init(struct cpufreq_ktoonservative_tunables *tunables)
{
	tunables->sampling_rate = 35000;
	tunables->up_threshold_screen_on = 57;
	tunables->up_threshold_screen_on_hotplug_1 = 50;
	tunables->up_threshold_screen_on_hotplug_2 = 55;
	tunables->up_threshold_screen_on_hotplug_3 = 60;
	tunables->up_threshold_screen_on_hotplug_4 = 65;
	tunables->up_threshold_screen_on_hotplug_5 = 70;
	tunables->up_threshold_screen_on_hotplug_6 = 75;
	tunables->up_threshold_screen_on_hotplug_7 = 80;
	tunables->up_threshold_screen_off = 57;
	tunables->up_threshold_screen_off_hotplug_1 = 55;
	tunables->up_threshold_screen_off_hotplug_2 = 60;
	tunables->up_threshold_screen_off_hotplug_3 = 65;
	tunables->up_threshold_screen_off_hotplug_4 = 70;
	tunables->up_threshold_screen_off_hotplug_5 = 75;
	tunables->up_threshold_screen_off_hotplug_6 = 80;
	tunables->up_threshold_screen_off_hotplug_7 = 85;
	tunables->down_threshold_screen_on = 52;
	tunables->down_threshold_screen_on_hotplug_1 = 35;
	tunables->down_threshold_screen_on_hotplug_2 = 40;
	tunables->down_threshold_screen_on_hotplug_3 = 45;
	tunables->down_threshold_screen_on_hotplug_4 = 50;
	tunables->down_threshold_screen_on_hotplug_5 = 55;
	tunables->down_threshold_screen_on_hotplug_6 = 60;
	tunables->down_threshold_screen_on_hotplug_7 = 65;
	tunables->down_threshold_screen_off = 52;
	tunables->down_threshold_screen_off_hotplug_1 = 40;
	tunables->down_threshold_screen_off_hotplug_2 = 45;
	tunables->down_threshold_screen_off_hotplug_3 = 50;
	tunables->down_threshold_screen_off_hotplug_4 = 55;
	tunables->down_threshold_screen_off_hotplug_5 = 60;
	tunables->down_threshold_screen_off_hotplug_6 = 65;
	tunables->down_threshold_screen_off_hotplug_7 = 70;
	tunables->block_cycles_online_screen_on = 3;
	tunables->block_cycles_offline_screen_on = 11;
	tunables->block_cycles_raise_screen_on = 3;
	tunables->block_cycles_online_screen_off = 11;
	tunables->block_cycles_offline_screen_off =1;
	tunables->block_cycles_raise_screen_off = 11;
	tunables->super_conservative_screen_on = 0;
	tunables->super_conservative_screen_off = 0;
	tunables->touch_boost_cpu_cl0 = DEF_BOOST_CPU_CL0;
	tunables->touch_boost_cpu_cl1 = DEF_BOOST_CPU_CL1;
	tunables->touch_boost_core_1 = 1;
	tunables->touch_boost_core_2 = 1;
	tunables->touch_boost_core_3 = 0;
	tunables->touch_boost_core_4 = 0;
	tunables->touch_boost_core_5 = 0;
	tunables->touch_boost_core_6 = 0;
	tunables->touch_boost_core_7 = 0;
	tunables->button_boost_screen_on_core_1 = 1;
	tunables->button_boost_screen_on_core_2 = 1;
	tunables->button_boost_screen_on_core_3 = 0;
	tunables->button_boost_screen_on_core_4 = 0;
	tunables->button_boost_screen_on_core_5 = 0;
	tunables->button_boost_screen_on_core_6 = 0;
	tunables->button_boost_screen_on_core_7 = 0;
	tunables->button_boost_screen_off_core_1 = 1;
	tunables->button_boost_screen_off_core_2 = 1;
	tunables->button_boost_screen_off_core_3 = 0;
	tunables->button_boost_screen_off_core_4 = 1;
	tunables->button_boost_screen_off_core_5 = 0;
	tunables->button_boost_screen_off_core_6 = 0;
	tunables->button_boost_screen_off_core_7 = 0;
	tunables->lockout_hotplug_screen_on_core_1 = 0;
	tunables->lockout_hotplug_screen_on_core_2 = 0;
	tunables->lockout_hotplug_screen_on_core_3 = 0;
	tunables->lockout_hotplug_screen_on_core_4 = 0;
	tunables->lockout_hotplug_screen_on_core_5 = 0;
	tunables->lockout_hotplug_screen_on_core_6 = 0;
	tunables->lockout_hotplug_screen_on_core_7 = 0;
	tunables->lockout_hotplug_screen_off_core_1 = 0;
	tunables->lockout_hotplug_screen_off_core_2 = 0;
	tunables->lockout_hotplug_screen_off_core_3 = 0;
	tunables->lockout_hotplug_screen_off_core_4 = 0;
	tunables->lockout_hotplug_screen_off_core_5 = 0;
	tunables->lockout_hotplug_screen_off_core_6 = 0;
	tunables->lockout_hotplug_screen_off_core_7 = 0;
	tunables->lockout_changes_when_boosting = 0;
	tunables->touch_boost_gpu = DEF_BOOST_GPU;
	tunables->cpu_load_adder_at_max_gpu = 0;
	tunables->cpu_load_adder_at_max_gpu_ignore_tb = 0;
	tunables->boost_hold_cycles = DEF_BOOST_HOLD_CYCLES;
	tunables->disable_hotplug = DEF_DISABLE_hotplug;
	tunables->disable_hotplug_chrg = 0;
	tunables->disable_hotplug_media = 0;
	tunables->disable_hotplug_bt = 0;
	tunables->no_extra_cores_screen_off = 1;
	tunables->sampling_rate_min = 20000;
	tunables->sampling_rate = 35000;
	tunables->sampling_rate_screen_off = 40000;
	tunables->ignore_nice_load = 0;
	tunables->freq_step_raise_screen_on = 5;
	tunables->freq_step_raise_screen_off = 1;
	tunables->freq_step_lower_screen_on = 2;
	tunables->freq_step_lower_screen_off = 8;
	tunables->debug_enabled = 0;
}

static void change_sysfs_owner(struct cpufreq_policy *policy)
{
	char buf[NAME_MAX];
	mm_segment_t oldfs;
	int i;
	char *path = kobject_get_path(get_governor_parent_kobj(policy),
			GFP_KERNEL);

	oldfs = get_fs();
	set_fs(get_ds());

	for (i = 0; i < ARRAY_SIZE(ktoonservative_sysfs); i++) {
		snprintf(buf, sizeof(buf), "/sys%s/ktoonservative/%s", path,
				ktoonservative_sysfs[i]);
		sys_chown(buf, AID_SYSTEM, AID_SYSTEM);
	}

	set_fs(oldfs);
	kfree(path);
}

int findNewOnlineCore(int startCPU)
{
	int i;
	for (i = startCPU; i < startCPU + 4; i++)
	{
		if (kt_cpu_core_smp_status[i] == 0 && cpu_core_smp_status[i] == 1)
		{
			kt_cpu_core_smp_status[i] = cpu_core_smp_status[i];
			if (i == 0)
			{
				kt_cpu_core_smp_status[1] = cpu_core_smp_status[i];
				kt_cpu_core_smp_status[2] = cpu_core_smp_status[i];
				kt_cpu_core_smp_status[3] = cpu_core_smp_status[i];
			}
			else if (i == 4)
			{
				kt_cpu_core_smp_status[5] = cpu_core_smp_status[i];
				kt_cpu_core_smp_status[6] = cpu_core_smp_status[i];
				kt_cpu_core_smp_status[7] = cpu_core_smp_status[i];
			}
			return i;
		}
	}
	return -1;
}

int findNewOfflineCore(int startCPU)
{
	int i;
	int j;
	for (i = startCPU; i < startCPU + 4; i++)
	{
		if (kt_cpu_core_smp_status[i] == 1  && cpu_core_smp_status[i] == 0)
		{
			kt_cpu_core_smp_status[i] = cpu_core_smp_status[i];
			if (i == 0)
			{
				for (j = 1; j <= 3; j++)
					kt_cpu_core_smp_status[j] = cpu_core_smp_status[i];
			}
			else if (i == 4)
			{
				for (j = 5; j <= 7; j++)
					kt_cpu_core_smp_status[j] = cpu_core_smp_status[i];
			}
			return i;
		}
	}
	return -1;
}

static int cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	unsigned int cpu;
	struct cpufreq_ktoonservative_cpuinfo *pcpu;
	struct cpufreq_ktoonservative_tunables *tunables;
	unsigned int j, i;
	unsigned int latency;
	int rc;
	int theCore;
	int loopStart, loopStop;
	
	if (!policy)
		return -EINVAL;
		
	cpu = policy->cpu;
	if (cpu == 0)
	{
		loopStart = 0;
		loopStop = 3;
	}
	else if (cpu == 4)
	{
		loopStart = 4;
		loopStop = 7;
	}
		
	if (have_governor_per_policy())
		tunables = policy->governor_data;
	else
		tunables = common_tunables;
	WARN_ON(!tunables && (event != CPUFREQ_GOV_POLICY_INIT));

	switch (event) {
	case CPUFREQ_GOV_POLICY_INIT:
		if (have_governor_per_policy()) {
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_POLICY_INIT PER POLICY - CPU=%d\n", policy->cpu);
			WARN_ON(tunables);
		} else if (tunables) {
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_POLICY_INIT NOT PER POLICY - CPU=%d\n", policy->cpu);
			tunables->usage_count++;
			policy->governor_data = tunables;
			return 0;
		}

		tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
		if (!tunables) {
			pr_err("%s: POLICY_INIT: kzalloc failed\n", __func__);
			return -ENOMEM;
		}

		if (!tuned_parameters[policy->cpu])
			cpufreq_param_set_init(tunables);
		else
		{
			memcpy(tunables, tuned_parameters[policy->cpu], sizeof(*tunables));
			kfree(tuned_parameters[policy->cpu]);
		}
		tunables->usage_count = 1;
		cpus_online++;
		if (debug_is_enabled)
			pr_alert("KTOONSERVATIVE CPUFREQ_GOV_POLICY_INIT - CPU=%d Count=%d\n", policy->cpu, tunables->usage_count);

		/* update handle for get cpufreq_policy */
		tunables->policy = &policy->policy;

		spin_lock_init(&cpufreq_up_lock);
		spin_lock_init(&cpufreq_down_lock);
		/* policy latency is in nS. Convert it to uS first */
		latency = policy->cpuinfo.transition_latency / 1000;
		if (latency == 0)
			latency = 1;

		min_sampling_rate = (MIN_SAMPLING_RATE_RATIO * jiffies_to_usecs(10)) / 20;
		/* Bring kernel and HW constraints together */
		min_sampling_rate = max(min_sampling_rate, MIN_LATENCY_MULTIPLIER * latency);

		policy->governor_data = tunables;
		if (!have_governor_per_policy())
			common_tunables = tunables;

		rc = sysfs_create_group(get_governor_parent_kobj(policy),
				get_sysfs_attr());
		if (rc) {
			kfree(tunables);
			policy->governor_data = NULL;
			if (!have_governor_per_policy())
				common_tunables = NULL;
			return rc;
		}

		change_sysfs_owner(policy);

		//Initialize up/down flags		
		for (j = loopStart; j < loopStop; j++)
		{
			hotplug_cpu_single_up[j] = 0;
			hotplug_cpu_single_down[j] = 0;
		}

		if (!policy->governor->initialized) {
			cpufreq_register_notifier(&cpufreq_notifier_block,
					CPUFREQ_TRANSITION_NOTIFIER);
		}

		break;

	case CPUFREQ_GOV_POLICY_EXIT:
		if ((kt_cpu_core_smp_status[cpu] == 0 && cpu_core_smp_status[cpu] == 1) && cpu == 4 && tunables->usage_count)
		{
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_POLICY_EXIT UN-NEEDED CALL - CPU=%d Count=%d\n", policy->cpu, tunables->usage_count);
			return 0;
		}
		if (!--tunables->usage_count) {
			pcpu = &per_cpu(cpuinfo, cpu);
			if (pcpu->enable)
			{
				if (debug_is_enabled)
					pr_alert("KTOONSERVATIVE CPUFREQ_GOV_POLICY_EXIT NEEDS TO DESTROY TIMER - CPU=%d Count=%d\n", policy->cpu, tunables->usage_count);
				dbs_timer_exit(pcpu);
				mutex_destroy(&pcpu->timer_mutex);
			}

			//Initialize up/down flags and SMP status flags		
			for (j = loopStart; j < loopStop; j++)
			{
				kt_cpu_core_smp_status[j] = 0;
				hotplug_cpu_single_up[j] = 0;
				hotplug_cpu_single_down[j] = 0;
			}

			if (policy->governor->initialized == 1) {
				cpufreq_unregister_notifier(&cpufreq_notifier_block,
						CPUFREQ_TRANSITION_NOTIFIER);
			}
			cpus_online--;
			if (cpus_online == 0)
				ktoonservative_is_active = false;
		
			boost_the_gpu(tunables->touch_boost_gpu, false);

			sysfs_remove_group(get_governor_parent_kobj(policy),
					get_sysfs_attr());

			tuned_parameters[policy->cpu] = kzalloc(sizeof(*tunables), GFP_KERNEL);
			if (!tuned_parameters[policy->cpu]) {
				pr_err("%s: POLICY_EXIT: kzalloc failed\n", __func__);
				return -ENOMEM;
			}
			memcpy(tuned_parameters[policy->cpu], tunables, sizeof(*tunables));
			kfree(tunables);
			common_tunables = NULL;
		}
		if (debug_is_enabled)
			pr_alert("KTOONSERVATIVE CPUFREQ_GOV_POLICY_EXIT - CPU=%d Count=%d\n", policy->cpu, tunables->usage_count);

		policy->governor_data = NULL;
		break;
		
	case CPUFREQ_GOV_START:
		theCore = findNewOnlineCore(policy->cpu);
		ktoonservative_is_active = true;
		
		if ((!cpu_online(cpu)) || (!policy->cur) || theCore == -1)
			return 0;
			
		if (theCore != 0 && theCore != 4)
		{
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_START - IGNORE CPU=%d REAL_CPU=%d ENABLED=%d\n", policy->cpu, theCore, ktoonservative_is_active);
			pcpu = &per_cpu(cpuinfo, theCore);
			pcpu->Lblock_cycles_online = 0;
			Lblock_cycles_offline[theCore] = 0;
			pcpu->Lblock_cycles_raise = 0;
			Lblock_cycles_online_OVERRIDE[theCore] = OVERRIDE_DISABLER;
			Lblock_cycles_offline_OVERRIDE[theCore] = OVERRIDE_DISABLER;
			hotplug_cpu_single_up[theCore] = 0;
			hotplug_cpu_single_down[theCore] = 0;
			return 0;
		}

		mutex_lock(&dbs_mutex);
		
		if (cpu == 4) 
		{
			if (vfreq_lock)
			{
				char buf[NAME_MAX];
				snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu4/cpufreq/scaling_max_freq");
				sys_chmod(buf, 0444);
				snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq");
				sys_chmod(buf, 0444);
			}
		}
		for_each_cpu(j, policy->cpus)
		{
			struct cpufreq_policy *extra_policy;
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_START - CPU=%d REAL_CPU=%d Count=%d CPUSCount=%d ENABLED=%d\n", policy->cpu, theCore, tunables->usage_count, j, ktoonservative_is_active);
			pcpu = &per_cpu(cpuinfo, j);
			pcpu->policy = policy;
			pcpu->prev_cpu_idle = get_cpu_idle_time(j,
						&pcpu->prev_cpu_wall);
			if (tunables->ignore_nice_load)
				pcpu->prev_cpu_nice = kcpustat_cpu(j).cpustat[CPUTIME_NICE];

			pcpu->Lblock_cycles_online = 0;
			Lblock_cycles_offline[j] = 0;
			pcpu->Lblock_cycles_raise = 0;
			Lblock_cycles_online_OVERRIDE[j] = OVERRIDE_DISABLER;
			Lblock_cycles_offline_OVERRIDE[j] = OVERRIDE_DISABLER;
			hotplug_cpu_single_up[j] = 0;
			hotplug_cpu_single_down[j] = 0;

			pcpu->cpu = j;
			pcpu->down_skip = 0;
			pcpu->requested_freq = policy->cur;
		}
		pcpu = &per_cpu(cpuinfo, cpu);
		/*
		 * Start the timerschedule work, when this governor
		 * is used for first time
		 */
		if (!pcpu->enable)
		{
			mutex_init(&pcpu->timer_mutex);
			dbs_timer_init(pcpu);
		}

		mutex_unlock(&dbs_mutex);

		break;

	case CPUFREQ_GOV_STOP:
		theCore = findNewOfflineCore(policy->cpu);
		if (theCore == -1)
		{
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_STOP - CORE NOT FOUND!!!!! CPU=%d REAL_CPU=%d ENABLED=%d\n", policy->cpu, theCore, ktoonservative_is_active);
			return 0;
		}	
		if (theCore != 0 && theCore != 4)
		{
			if (debug_is_enabled)
				pr_alert("KTOONSERVATIVE CPUFREQ_GOV_STOP - IGNORE CPU=%d REAL_CPU=%d ENABLED=%d\n", policy->cpu, theCore, ktoonservative_is_active);
			cpu_load[theCore] = -1;
			hotplug_cpu_single_up[theCore] = 0;
			hotplug_cpu_single_down[theCore] = 0;
			return 0;
		}
		
		mutex_lock(&dbs_mutex);
		for_each_cpu(j, policy->cpus)
		{
			pcpu = &per_cpu(cpuinfo, j);
			cpu_load[j] = -1;
			hotplug_cpu_single_up[j] = 0;
			hotplug_cpu_single_down[j] = 0;
		}
		if (pcpu->enable)
		{
			pcpu = &per_cpu(cpuinfo, cpu);
			dbs_timer_exit(pcpu);
			mutex_destroy(&pcpu->timer_mutex);
		}
		if (debug_is_enabled)
			pr_alert("KTOONSERVATIVE CPUFREQ_GOV_STOP - CPU=%d REAL_CPU=%d ENABLED=%d\n", policy->cpu, theCore, ktoonservative_is_active);
		mutex_unlock(&dbs_mutex);

		break;

	case CPUFREQ_GOV_LIMITS:
		pcpu = &per_cpu(cpuinfo, cpu);
		mutex_lock(&pcpu->timer_mutex);
		if (policy->max < pcpu->policy->cur)
		{
			__cpufreq_driver_target(pcpu->policy, policy->max, CPUFREQ_RELATION_H);
		}
		else if (policy->min > pcpu->policy->cur)
		{
			__cpufreq_driver_target(pcpu->policy, policy->min, CPUFREQ_RELATION_L);
		}
		dbs_check_cpu(pcpu);
		mutex_unlock(&pcpu->timer_mutex);

		break;
	}
	return 0;
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_KTOONSERVATIVE
static
#endif
struct cpufreq_governor cpufreq_gov_ktoonservative = {
	.name			= "ktoonservative",
	.governor		= cpufreq_governor_dbs,
	.max_transition_latency	= TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};

static int __init cpufreq_gov_dbs_init(void)
{
	dbs_wq = alloc_workqueue("ktoonservative_dbs_wq", WQ_HIGHPRI | WQ_CPU_INTENSIVE, 0);
	if (!dbs_wq) {
		printk(KERN_ERR "Failed to create ktoonservative_dbs_wq workqueue\n");
		return -EFAULT;
	}

	INIT_WORK(&hotplug_offline_work, hotplug_offline_work_fn);
	INIT_WORK(&hotplug_online_work, hotplug_online_work_fn);
	mutex_init(&dbs_mutex);
	return cpufreq_register_governor(&cpufreq_gov_ktoonservative);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cancel_work_sync(&hotplug_offline_work);
	cancel_work_sync(&hotplug_online_work);
	cpufreq_unregister_governor(&cpufreq_gov_ktoonservative);
	destroy_workqueue(dbs_wq);
}

MODULE_AUTHOR("ktoonsez");
MODULE_DESCRIPTION("'cpufreq_ktoonservative' - A dynamic cpufreq governor for "
		"Low Latency Frequency Transition capable processors "
		"optimised for use in a battery environment");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_KTOONSERVATIVE
fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
