#ifndef __SOMC_WIFI_H__
#define __SOMC_WIFI_H__

extern int somc_wifi_init(struct platform_device *pdev);
extern void somc_wifi_deinit(struct platform_device *pdev);
extern struct wifi_platform_data somc_wifi_control;

#endif /* __SOMC_WIFI_H__ */
