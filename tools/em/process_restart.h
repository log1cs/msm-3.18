#ifdef CONFIG_SNSC_EM_PROCESS_RESTART
void em_process_status_dump(void);
int system_reboot_framework(void);
int em_system_reboot_register(void);
void em_system_reboot_unregister(void);
bool em_system_reboot_enabled(void);
#endif

