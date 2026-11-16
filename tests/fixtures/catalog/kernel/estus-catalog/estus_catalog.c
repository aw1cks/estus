#include <linux/module.h>
#include <linux/init.h>
static int value = 7;
module_param(value, int, 0644);
MODULE_PARM_DESC(value, "Harmless catalog fixture value");
static int __init catalog_init(void) { return 0; }
static void __exit catalog_exit(void) { }
module_init(catalog_init);
module_exit(catalog_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable Estus qualification fixture; no hooks or devices");
