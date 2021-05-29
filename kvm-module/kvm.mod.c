#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0xf8e3dbd2, "struct_module" },
	{ 0x6f0530cb, "alloc_pages_current" },
	{ 0x8425305, "debugfs_create_dir" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x496da090, "__next_cpu" },
	{ 0xdae1ffcf, "node_data" },
	{ 0x89892632, "malloc_sizes" },
	{ 0x429328d9, "_spin_lock" },
	{ 0xa464d8ff, "mutex_unlock" },
	{ 0x2fd1d81c, "vfree" },
	{ 0xda4008e6, "cond_resched" },
	{ 0xd5d609f5, "debugfs_create_u32" },
	{ 0x2a0e68ca, "__alloc_pages" },
	{ 0x9b5d2f6f, "misc_register" },
	{ 0xde0bdcff, "memset" },
	{ 0x9ac66700, "_cpu_pda" },
	{ 0xc16fe12d, "__memcpy" },
	{ 0x86cb9d9f, "__mutex_init" },
	{ 0xdd132261, "printk" },
	{ 0xbe499d81, "copy_to_user" },
	{ 0x59f73444, "debugfs_remove" },
	{ 0xd8eb2ab5, "mutex_lock" },
	{ 0xdfa38fb3, "__first_cpu" },
	{ 0x260f87da, "mem_section" },
	{ 0x521445b, "list_del" },
	{ 0x3980aac1, "unregister_reboot_notifier" },
	{ 0xc2689d0d, "cpu_online_map" },
	{ 0x4c503ced, "kmem_cache_alloc" },
	{ 0x3499d731, "__free_pages" },
	{ 0x14bfd1, "smp_call_function" },
	{ 0x1cc6719a, "register_reboot_notifier" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xef04d90c, "kmem_cache_zalloc" },
	{ 0x37a0cba, "kfree" },
	{ 0x46d33fe1, "list_add" },
	{ 0xbba1c14, "on_each_cpu" },
	{ 0x945bc6a7, "copy_from_user" },
	{ 0x2e75b744, "cpu_to_node" },
	{ 0x928c3f70, "misc_deregister" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EB1CA9E86FEA643A511AFF4");
