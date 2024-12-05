/* 2017-05-26: File added and changed by Sony Corporation */
#ifndef _SNSC_LINUX_MAJOR_H_
#define _SNSC_LINUX_MAJOR_H_

/*
 * This file has definitions for major device numbers on NSC Linux.
 *
 * Copyright 2005 Sony Corporation.
 */

/* major numbers for character devices */

/*
 * Removing the hardcoded major number with "0" as in API
 *__register_chrdev_region, if major == 0 this functions will dynamically
 * allocate a major and return its number.
 */
#define SNSC_TTYNULL_MAJOR            0    /* null console */

/* major numbers for block devices */

#endif /* _SNSC_LINUX_MAJOR_H_ */
