/*
 * Implement the manual drop-all-pagecache function
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/sysctl.h>
#include <linux/gfp.h>
#include <linux/fb.h>
#include <linux/delay.h>
#include "internal.h"

/* A global variable is a bit ugly, but it keeps the code simple */
int sysctl_drop_caches;

static void drop_pagecache_sb(struct super_block *sb, void *unused)
{
	struct inode *inode, *toput_inode = NULL;

	spin_lock(&inode_sb_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&inode_sb_list_lock);
		invalidate_mapping_pages(inode->i_mapping, 0, -1);
		iput(toput_inode);
		toput_inode = inode;
		spin_lock(&inode_sb_list_lock);
	}
	spin_unlock(&inode_sb_list_lock);
	iput(toput_inode);
}

static void drop_slab(void)
{
	int nr_objects;
	struct shrink_control shrink = {
		.gfp_mask = GFP_KERNEL,
	};

	nodes_setall(shrink.nodes_to_scan);
	do {
		nr_objects = shrink_slab(&shrink, 1000, 1000);
	} while (nr_objects > 10);
}

int drop_caches_sysctl_handler(ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret)
		return ret;
	if (write) {
		if (sysctl_drop_caches & 1)
			iterate_supers(drop_pagecache_sb, NULL);
		if (sysctl_drop_caches & 2)
			drop_slab();
	}
	return 0;
}

static void drop_caches_suspend(struct work_struct *work);
static DECLARE_WORK(drop_caches_suspend_work, drop_caches_suspend);
static void drop_caches_resume(struct work_struct *work);
static DECLARE_WORK(drop_caches_resume_work, drop_caches_resume);

static int Pdirty_background_ratio;
static unsigned long Pdirty_background_bytes;
static int Pvm_dirty_ratio;
static unsigned long Pvm_dirty_bytes;
static unsigned int Pdirty_expire_interval;

static void drop_caches_suspend(struct work_struct *work)
{
	/* sleep for 200ms */
	msleep(200);

	/* loosen writeback */
	Pdirty_background_ratio = dirty_background_ratio;
	Pdirty_background_bytes = dirty_background_bytes;
	Pvm_dirty_ratio = vm_dirty_ratio;
	Pvm_dirty_bytes = vm_dirty_bytes;
	Pdirty_expire_interval = dirty_expire_interval;

	dirty_background_ratio = 0;
	dirty_background_bytes = 1 * 1024 * 1024; /* 1MB */
	vm_dirty_ratio = 0;
	vm_dirty_bytes = 1 * 1024 * 1024; /* 1MB */
	dirty_expire_interval = 1 * 100; /* 1 second */

	/* sync */
	emergency_sync();
	/* echo "3" > /proc/sys/vm/drop_caches */
	iterate_supers(drop_pagecache_sb, NULL);
	drop_slab();
}
static void drop_caches_resume(struct work_struct *work)
{
	/* restore previous writeback tunables */
	dirty_background_ratio = Pdirty_background_ratio;
	dirty_background_bytes = Pdirty_background_bytes;
	vm_dirty_ratio = Pvm_dirty_ratio;
	vm_dirty_bytes = Pvm_dirty_bytes;
	dirty_expire_interval = Pdirty_expire_interval;
}

static int fb_notifier(struct notifier_block *self,
			unsigned long event, void *data)
{
	struct fb_event *evdata = (struct fb_event *)data;

	if ((event == FB_EVENT_BLANK) && evdata && evdata->data) {
		int blank = *(int *)evdata->data;

		if (blank == FB_BLANK_POWERDOWN) {
			schedule_work_on(0, &drop_caches_suspend_work);
		} else if (blank == FB_BLANK_UNBLANK) {
			schedule_work_on(0, &drop_caches_resume_work);
		}
		return NOTIFY_OK;
	}
	return NOTIFY_DONE;
}

static struct notifier_block fb_notifier_block = {
	.notifier_call = fb_notifier,
	.priority = -1,
};

static int __init drop_caches_init(void)
{
	fb_register_client(&fb_notifier_block);

	Pdirty_background_ratio = dirty_background_ratio;
	Pdirty_background_bytes = dirty_background_bytes;
	Pvm_dirty_ratio = vm_dirty_ratio;
	Pvm_dirty_bytes = vm_dirty_bytes;
	Pdirty_expire_interval = dirty_expire_interval;

	return 0;
}
late_initcall(drop_caches_init);
