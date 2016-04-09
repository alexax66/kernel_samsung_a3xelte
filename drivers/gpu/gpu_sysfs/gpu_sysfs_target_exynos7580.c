#include 	"gpu_sysfs_header.h"

/* *
 * *********************************************************************
 * Path defines for all the sysfs files.
 * *********************************************************************
 * */
/*#define  	GPU_MIN_CLOCK			"/sys/devices/11400000.mali/" -- Not available directly from sysfs. */
/*#define  	GPU_MAX_CLOCK			"/sys/devices/11400000.mali/" -- Not available directly from sysfs. */
#define  	GPU_BUSY			"/sys/devices/11400000.mali/utilization"
#define  	GPU_VOL				"/sys/devices/11400000.mali/vol"
#define  	GPU_FREQ			"/sys/devices/11400000.mali/clock"
#define  	GPU_FREQ_TABLE			"/sys/devices/11400000.mali/dvfs_table"
#define  	GPU_GOVERNOR			"/sys/devices/14000000.mali/power_policy"
#define  	GPU_CORES_CONFIG		"/sys/devices/14000000.mali/core_mask"
#define  	GPU_TMU				"/sys/devices/14000000.mali/tmu"
#define  	GPU_MODEL			"/sys/devices/14000000.mali/uevent"
/*#define  	GPU_VERSION			"/sys/devices/14000000.mali/gpu_version"*/
/*#define  	GPU_MEM				"/sys/devices/14000000.mali/gpu_mem" -- Not available directly from sysfs. */
#define  	GPU_DVFS			"/sys/devices/14000000.mali/dvfs"
#define  	EXYNOS_SYSFS_GPU_FPS		"/sys/devices/platform/gpusysfs/fps"

/* *
 * *********************************************************************
 * Device ATTR functions. Will be called when read from sysfs.
 * *********************************************************************
 * */
extern unsigned int gpu_min_override;
extern unsigned int gpu_max_override;
extern unsigned int gpu_max_override_screen_off;

ssize_t gpu_min_clock_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int freq = 0;
	unsigned int ret;

	ret = sscanf(buf, "%u", &freq);
	if (ret != 1)
		return -EINVAL;
	
	gpu_min_override = freq;
	return count;
}

ssize_t gpu_min_clock_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", gpu_min_override);
}

ssize_t gpu_max_clock_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int freq = 0;
	unsigned int ret;

	ret = sscanf(buf, "%u", &freq);
	if (ret != 1)
		return -EINVAL;
	
	gpu_max_override = freq;
	return count;
}

ssize_t gpu_max_clock_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", gpu_max_override);
}

ssize_t gpu_max_clock_screen_off_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int freq = 0;
	unsigned int ret;

	ret = sscanf(buf, "%u", &freq);
	if (ret != 1)
		return -EINVAL;
	
	gpu_max_override_screen_off = freq;
	return count;
}

ssize_t gpu_max_clock_screen_off_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", gpu_max_override_screen_off);
}

ssize_t gpu_busy_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_32];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_BUSY, input_buffer, INPUT_BUFFER_SIZE_32);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_vol_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_32];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_VOL, input_buffer, INPUT_BUFFER_SIZE_32);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_freq_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_32];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_FREQ, input_buffer, INPUT_BUFFER_SIZE_32);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_freq_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
	if (open_file_and_write_buffer(GPU_GOVERNOR, "always_on", strlen("always_on")) == 0)
	{
		pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
		return 0;
	}

    pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
	if (open_file_and_write_buffer(GPU_DVFS, "0", strlen("0")) == 0)
	{
		pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
		return 0;
	}

    pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
	if (open_file_and_write_buffer(GPU_FREQ, buf, strlen(buf)) == 0)
	{
		pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
		return 0;
	}
	
	pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);

	/* Return success status. */
	return count;
}

ssize_t gpu_freq_table_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_128];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_FREQ_TABLE, input_buffer, INPUT_BUFFER_SIZE_128);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_governor_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_128];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_GOVERNOR, input_buffer, INPUT_BUFFER_SIZE_128);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_governor_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
	if (open_file_and_write_buffer(GPU_GOVERNOR, buf, strlen(buf)) == 0)
	{
		pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
		return 0;
	}
	
	pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);

	/* Return success status. */
	return count;
}

ssize_t gpu_available_governor_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_128];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_GOVERNOR, input_buffer, INPUT_BUFFER_SIZE_128);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_cores_config_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_32];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_CORES_CONFIG, input_buffer, INPUT_BUFFER_SIZE_32);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_tmu_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   	input_buffer[INPUT_BUFFER_SIZE_32];
	int		status = 0;	
	
	status = open_file_and_read_buffer(GPU_TMU, input_buffer, INPUT_BUFFER_SIZE_32);

	if (status == SRUK_TRUE)
	{
		return sprintf(buf, "%s", input_buffer);
	}
	else
	{
		return sprintf(buf, "-1");
	}
}

ssize_t gpu_model_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char   		 	input_buffer[INPUT_BUFFER_SIZE_128];
	char   		 	model_buffer[INPUT_BUFFER_SIZE_32];
	int				status = 0;	
	char 			*parse_pointer = input_buffer;
	int    			char_counter = 0, equal_char_counter = 0;
	
	status = open_file_and_read_buffer(GPU_MODEL, input_buffer, INPUT_BUFFER_SIZE_128);

	if (status != SRUK_TRUE)
	{
		return sprintf(buf, "-1");
	}

	/* ************************************ */
	/* Parse input to find gpu version.
	 * This is target specific. 
	 * The driver gives information in following
	 * format:
	 *    DRIVER=mali
	 *    OF_NAME=mali
	 *    OF_FULLNAME=/mali
	 *    OF_COMPATIBLE_0=arm,mali
	 *    OF_COMPATIBLE_N=1
	 *    MODALIAS=of:NmaliT<NULL>Carm,mali
	 * */
	/* ************************************ */
	while (*parse_pointer != '\0')
	{
		/* Look for '='. */
		if (*parse_pointer == '=')
		{
			equal_char_counter=char_counter;
			equal_char_counter=equal_char_counter+1; /* Point to next char. */
		}

		if ((*parse_pointer == '\n') || (*parse_pointer == '\r'))
		{
			break;
		}
				
		/* */
		parse_pointer++;
		char_counter++;
	}
	
	strncpy(model_buffer, input_buffer + equal_char_counter, (char_counter-equal_char_counter));
	
	/* Adding null terminator, in case if not there already. */
	if (*(model_buffer + (char_counter-equal_char_counter)) != '\0')
		*(model_buffer + (char_counter-equal_char_counter)) = '\0'; 
	
	/* Copy the model string to the output string.*/
	return sprintf(buf, "%s\n", model_buffer);
}

ssize_t gpu_version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "gpu_version -- Not available.\n");
}

ssize_t gpu_mem_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "gpu_mem -- Not available.\n");
}

char   	 global_fps_string[INPUT_BUFFER_SIZE_32];
ssize_t fps_show(struct device *dev, struct device_attribute *attr, char *buf)
{ 
	return sprintf(buf, "%s", global_fps_string);
}

ssize_t fps_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{ 
	pr_info("SRUK ----------- %s -- %d", __FUNCTION__, __LINE__);
    if (buf != NULL)
        sprintf(global_fps_string,"%s", buf);
    else
        sprintf(global_fps_string,"0"); 

	/* Return success status. */		
	return count;

}
