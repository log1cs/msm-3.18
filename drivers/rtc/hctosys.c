/* 2017-03-23: File changed by Sony Corporation */
/*
 * RTC subsystem, initialize system time on startup
 *
 * Copyright (C) 2005 Tower Technologies
 * Author: Alessandro Zummo <a.zummo@towertech.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/rtc.h>

#ifdef CONFIG_SNSC_BUILTIN_TIMESTAMP
#include <generated/compile.h>
#include <linux/kernel.h>
#endif

/* IMPORTANT: the RTC only stores whole seconds. It is arbitrary
 * whether it stores the most close value or the value with partial
 * seconds truncated. However, it is important that we use it to store
 * the truncated value. This is because otherwise it is necessary,
 * in an rtc sync function, to read both xtime.tv_sec and
 * xtime.tv_nsec. On some processors (i.e. ARM), an atomic read
 * of >32bits is not possible. So storing the most close value would
 * slow down the sync API. So here we have the truncated value and
 * the best guess is to add 0.5s.
 */

static int __init rtc_hctosys(void)
{
	int err = -ENODEV;
	struct rtc_time tm;
	struct timespec tv = {
		.tv_sec	 = 0,
		.tv_nsec = NSEC_PER_SEC >> 1,
	};

#ifdef CONFIG_SNSC_BUILTIN_TIMESTAMP
	unsigned long builtin_time_sec;
#endif
	struct rtc_device *rtc = rtc_class_open(CONFIG_RTC_HCTOSYS_DEVICE);

	if (rtc == NULL) {
		pr_err("%s: unable to open rtc device (%s)\n",
			__FILE__, CONFIG_RTC_HCTOSYS_DEVICE);
		goto err_open;
	}

	err = rtc_read_time(rtc, &tm);
	if (err) {
		dev_err(rtc->dev.parent,
			"hctosys: unable to read the hardware clock\n");
		goto err_read;

	}

	err = rtc_valid_tm(&tm);
	if (err) {
		dev_err(rtc->dev.parent,
			"hctosys: invalid date/time\n");
		goto err_invalid;
	}

	rtc_tm_to_time(&tm, &tv.tv_sec);

	err = do_settimeofday(&tv);

	dev_info(rtc->dev.parent,
		"setting system clock to "
		"%d-%02d-%02d %02d:%02d:%02d UTC (%u)\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		(unsigned int) tv.tv_sec);

err_invalid:
err_read:
	rtc_class_close(rtc);

err_open:

#ifdef CONFIG_SNSC_BUILTIN_TIMESTAMP
	err = kstrtol(SNSC_UTS_BUILTIN_TIME, 0, &builtin_time_sec);
	if (!err) {
		if (tv.tv_sec < builtin_time_sec) {
			tv.tv_sec = builtin_time_sec;
			rtc_time_to_tm(tv.tv_sec, &tm);
			err = do_settimeofday(&tv);
			pr_info("use built-in time and setting system clock to %d-%02d-%02d %02d:%02d:%02d UTC (%u)\n",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec,
				(unsigned int) tv.tv_sec);
#ifdef CONFIG_AL0_RTC_SYSTOHC
			/* Set the builtin_time_sec to HW clock */
			rtc_set_ntp_time(tv);
#endif
		}
	}
#endif
	rtc_hctosys_ret = err;

	return err;
}

late_initcall(rtc_hctosys);
