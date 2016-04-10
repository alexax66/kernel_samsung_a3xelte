#include <linux/cpufreq_kt.h>
#include <linux/fb.h>
#include <linux/syscalls.h>
bool screen_is_on = true;

static int fb_state_change(struct notifier_block *nb,
		unsigned long val, void *data)
{
	struct fb_event *evdata = data;
	struct fb_info *info = evdata->info;
	unsigned int blank;
	
	if (val != FB_EVENT_BLANK &&
		val != FB_R_EARLY_EVENT_BLANK)
		return 0;
	/*
	 * If FBNODE is not zero, it is not primary display(LCD)
	 * and don't need to process these scheduling.
	 */
	if (info->node)
		return NOTIFY_OK;

	blank = *(int *)evdata->data;

	switch (blank) {
	case FB_BLANK_POWERDOWN:
		cpufreq_screen_is_on(false);
		//if (ktoonservative_is_active)
		//{
		//	pr_alert("KT GOT SCREEN OFF-0\n");
		//	ktoonservative_screen_is_on(false, 0);
		//	//pr_alert("KT GOT SCREEN OFF-4\n");
		//	//ktoonservative_screen_is_on(false, 4);
		//}
		//screen_is_on = false;
		break;
	case FB_BLANK_UNBLANK:
		//if (ktoonservative_is_active)
		//{
		//	pr_alert("KT GOT SCREEN ON-0\n");
		//	ktoonservative_screen_is_on(true, 0);
		//	//pr_alert("KT GOT SCREEN ON-4\n");
		//	//ktoonservative_screen_is_on(true, 4);
		//}
		//screen_is_on = true;
		cpufreq_screen_is_on(true);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}
static struct notifier_block fb_block = {
	.notifier_call = fb_state_change,
};

static int __init cpufreq_kt_init(void)
{
	fb_register_client(&fb_block);
	return 0;
}
late_initcall(cpufreq_kt_init);


