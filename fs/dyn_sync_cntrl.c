/*
 * Dynamic sync control driver V2
 * 
 * by andip71 (alias Lord Boeffla)
 * 
 * All credits for original implemenation to faux123
 * 
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#ifdef CONFIG_POWERSUSPEND
#include <linux/powersuspend.h>
#endif
#ifdef CONFIG_STATE_NOTIFIER
#include <linux/state_notifier.h>
#endif
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/writeback.h>
#include <linux/dyn_sync_cntrl.h>

// fsync_mutex protects dyn_fsync_active during suspend / late resume transitions
static DEFINE_MUTEX(fsync_mutex);


// Declarations

#if defined(CONFIG_POWERSUSPEND) || defined(CONFIG_STATE_NOTIFIER)
bool suspend_active __read_mostly = false;
#endif
bool dyn_fsync_active __read_mostly = DYN_FSYNC_ACTIVE_DEFAULT;

#ifdef CONFIG_STATE_NOTIFIER
static struct notifier_block notif;
#endif

extern void sync_filesystems(int wait);

// Functions

static ssize_t dyn_fsync_active_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", (dyn_fsync_active ? 1 : 0));
}


static ssize_t dyn_fsync_active_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned int data;

	if(sscanf(buf, "%u\n", &data) == 1)
	{
		if (data == 1) 
		{
			pr_info("%s: dynamic fsync enabled\n", __FUNCTION__);
			dyn_fsync_active = true;
		}
		else if (data == 0) 
		{
			pr_info("%s: dynamic fsync disabled\n", __FUNCTION__);
			dyn_fsync_active = false;
		}
		else
			pr_info("%s: bad value: %u\n", __FUNCTION__, data);
	} 
	else
		pr_info("%s: unknown input!\n", __FUNCTION__);

	return count;
}


static ssize_t dyn_fsync_version_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "version: %u.%u\n",
		DYN_FSYNC_VERSION_MAJOR,
		DYN_FSYNC_VERSION_MINOR);
}

static ssize_t dyn_fsync_suspend_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "suspend active: %u\n", suspend_active);
}

static void dyn_fsync_force_flush(void)
{
	sync_filesystems(0);
	sync_filesystems(1);
}

#ifdef CONFIG_POWERSUSPEND
static void dyn_fsync_suspend(struct power_suspend *p)
{
	mutex_lock(&fsync_mutex);
	if (dyn_fsync_active) {
		suspend_active = true;
		dyn_fsync_force_flush();
	}
	mutex_unlock(&fsync_mutex);
}

static void dyn_fsync_resume(struct power_suspend *p)
{
	mutex_lock(&fsync_mutex);
	suspend_active = false;
	mutex_unlock(&fsync_mutex);
}

static struct power_suspend dyn_fsync_power_suspend_handler =
	{
		.suspend = dyn_fsync_suspend,
		.resume = dyn_fsync_resume,
	};
#endif

static int dyn_fsync_panic_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	suspend_active = false;
	dyn_fsync_force_flush();
//	pr_warn("dynamic fsync: panic - force flush!\n");

	return NOTIFY_OK;
}


static int dyn_fsync_notify_sys(struct notifier_block *this, unsigned long code,
				void *unused)
{
	if (code == SYS_DOWN || code == SYS_HALT) 
	{
		suspend_active = false;
		dyn_fsync_force_flush();
//		pr_warn("dynamic fsync: reboot - force flush!\n");
	}
	return NOTIFY_OK;
}


#ifdef CONFIG_STATE_NOTIFIER
static int state_notifier_callback(struct notifier_block *this,
					unsigned long event, void *data)
{
	switch (event) 
	{
		case STATE_NOTIFIER_ACTIVE:
			mutex_lock(&fsync_mutex);
			
			suspend_active = false;

			if (dyn_fsync_active) 
			{
				dyn_fsync_force_flush();
			}
			
			mutex_unlock(&fsync_mutex);
			break;
			
		case STATE_NOTIFIER_SUSPEND:
			mutex_lock(&fsync_mutex);
			suspend_active = true;
			mutex_unlock(&fsync_mutex);
			break;
			
		default:
			break;
	}

	return NOTIFY_OK;
}
#endif

// Module structures

static struct notifier_block dyn_fsync_notifier = 
{
	.notifier_call = dyn_fsync_notify_sys,
};

static struct kobj_attribute dyn_fsync_active_attribute = 
	__ATTR(Dyn_fsync_active, 0666,
		dyn_fsync_active_show,
		dyn_fsync_active_store);

static struct kobj_attribute dyn_fsync_version_attribute = 
	__ATTR(Dyn_fsync_version, 0444, dyn_fsync_version_show, NULL);

static struct kobj_attribute dyn_fsync_suspend_attribute =
	__ATTR(Dyn_fsync_suspend, 0444, dyn_fsync_suspend_show, NULL);

static struct attribute *dyn_fsync_active_attrs[] =
{
	&dyn_fsync_active_attribute.attr,
	&dyn_fsync_version_attribute.attr,
	&dyn_fsync_suspend_attribute.attr,
	NULL,
};

static struct attribute_group dyn_fsync_active_attr_group =
{
	.attrs = dyn_fsync_active_attrs,
};

static struct notifier_block dyn_fsync_panic_block = 
{
	.notifier_call  = dyn_fsync_panic_event,
	.priority       = INT_MAX,
};

static struct kobject *dyn_fsync_kobj;


// Module init/exit

static int dyn_fsync_init(void)
{
	int sysfs_result;

#ifdef CONFIG_POWERSUSPEND
	register_power_suspend(&dyn_fsync_power_suspend_handler);
#endif
	register_reboot_notifier(&dyn_fsync_notifier);
	
	atomic_notifier_chain_register(&panic_notifier_list,
		&dyn_fsync_panic_block);

	dyn_fsync_kobj = kobject_create_and_add("dyn_fsync", kernel_kobj);

	if (!dyn_fsync_kobj) {
		pr_err("%s dyn_fsync_kobj create failed!\n", __FUNCTION__);
		return -ENOMEM;
	}

	sysfs_result = sysfs_create_group(dyn_fsync_kobj,
			&dyn_fsync_active_attr_group);

	if (sysfs_result) {
		pr_err("%s dyn_fsync sysfs create failed!\n", __FUNCTION__);
		kobject_put(dyn_fsync_kobj);
	}

#ifdef CONFIG_STATE_NOTIFIER
	notif.notifier_call = state_notifier_callback;
	if (state_register_client(&notif)) {
		pr_err("%s: Failed to register State notifier callback\n", __func__);

		unregister_reboot_notifier(&dyn_fsync_notifier);

		atomic_notifier_chain_unregister(&panic_notifier_list,
			&dyn_fsync_panic_block);

		if (dyn_fsync_kobj != NULL)
			kobject_put(dyn_fsync_kobj);

		return -EFAULT;
	}
#endif

	pr_info("%s dynamic fsync initialisation complete\n", __FUNCTION__);

	return sysfs_result;
}


static void dyn_fsync_exit(void)
{
#ifdef CONFIG_POWERSUSPEND
	unregister_power_suspend(&dyn_fsync_power_suspend_handler);
#endif
	unregister_reboot_notifier(&dyn_fsync_notifier);

	atomic_notifier_chain_unregister(&panic_notifier_list,
		&dyn_fsync_panic_block);

	if (dyn_fsync_kobj != NULL)
		kobject_put(dyn_fsync_kobj);

	pr_info("%s dynamic fsync unregistration complete\n", __FUNCTION__);
}

module_init(dyn_fsync_init);
module_exit(dyn_fsync_exit);

MODULE_AUTHOR("andip71");
#ifdef CONFIG_POWERSUSPEND
MODULE_DESCRIPTION("dynamic fsync - automatic fs sync optimizaition using"
		"Power_suspend driver!");
#else
MODULE_DESCRIPTION("dynamic fsync - automatic fs sync optimizaition");
#endif
MODULE_LICENSE("GPL v2");
