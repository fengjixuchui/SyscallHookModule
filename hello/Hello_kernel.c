#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

static int __init modtest_module_init(void)
{
	printk(KERN_INFO "modtest is loaded\n");
	return 0;
}

static void __exit modtest_module_exit(void)
{
	printk(KERN_INFO "modtest is removed\n");
}

module_init(modtest_module_init);
module_exit(modtest_module_exit);
