// SPDX-License-Identifier: GPL-2.0
/* Disposable lab fixture: synthetic configuration/EEPROM, never a PHY model. */
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/linkmode.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>

#define MODEL_DRIVER "estus_nic_model"
#define MODEL_EEPROM_LEN 512

static unsigned int eee_read_fault, eee_write_fault, module_fault, delay_ms;
static unsigned int voltage_raw = 33000;
static int temperature_raw = 6464;
static unsigned int eee_writes;

/* Parameter writers and callback readers synchronize without a device lifetime. */
static int model_uint_set(const char *value, const struct kernel_param *kp)
{
	unsigned int parsed, max;
	int ret = kstrtouint(value, 0, &parsed);

	if (ret)
		return ret;
	if (kp->arg == &delay_ms)
		max = 10000;
	else if (kp->arg == &voltage_raw)
		max = 65535;
	else if (kp->arg == &eee_read_fault)
		max = 2;
	else
		max = 3;
	if (parsed > max)
		return -ERANGE;
	WRITE_ONCE(*(unsigned int *)kp->arg, parsed);
	return 0;
}

static int model_uint_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n",
			 READ_ONCE(*(unsigned int *)kp->arg));
}

static int model_temp_set(const char *value, const struct kernel_param *kp)
{
	int parsed, ret = kstrtoint(value, 0, &parsed);

	if (ret)
		return ret;
	if (parsed < -32768 || parsed > 32767)
		return -ERANGE;
	WRITE_ONCE(*(int *)kp->arg, parsed);
	return 0;
}

static int model_temp_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", READ_ONCE(*(int *)kp->arg));
}

static const struct kernel_param_ops model_uint_ops = {
	.set = model_uint_set, .get = model_uint_get,
};
static const struct kernel_param_ops model_temp_ops = {
	.set = model_temp_set, .get = model_temp_get,
};
static const struct kernel_param_ops model_counter_ops = {
	.get = model_uint_get,
};
module_param_cb(eee_read_fault, &model_uint_ops, &eee_read_fault, 0600);
module_param_cb(eee_write_fault, &model_uint_ops, &eee_write_fault, 0600);
module_param_cb(module_fault, &model_uint_ops, &module_fault, 0600);
module_param_cb(delay_ms, &model_uint_ops, &delay_ms, 0600);
module_param_cb(voltage_raw, &model_uint_ops, &voltage_raw, 0600);
module_param_cb(temperature_raw, &model_temp_ops, &temperature_raw, 0600);
module_param_cb(eee_writes, &model_counter_ops, &eee_writes, 0444);
MODULE_PARM_DESC(eee_read_fault, "0 normal, 1 unsupported, 2 I/O error");
MODULE_PARM_DESC(eee_write_fault, "0 normal, 1 fail before, 2 ignore, 3 apply then fail");
MODULE_PARM_DESC(module_fault, "0 normal, 1 unsupported, 2 I/O error, 3 unknown identifier");
MODULE_PARM_DESC(delay_ms, "Read callback delay, bounded to 10000 ms");
MODULE_PARM_DESC(temperature_raw, "Synthetic signed SFF-8472 temperature (1/256 C)");
MODULE_PARM_DESC(voltage_raw, "Synthetic SFF-8472 voltage (100 uV)");
MODULE_PARM_DESC(eee_writes, "Actual setter callbacks, saturating at UINT_MAX");

struct model_priv {
	struct mutex lock;
	struct ethtool_keee eee;
};

static void model_read_delay(void)
{
	unsigned int delay = READ_ONCE(delay_ms);

	if (delay)
		msleep(delay);
}

static int model_fault(unsigned int fault)
{
	return fault == 1 ? -EOPNOTSUPP : fault == 2 ? -EIO : 0;
}

static void model_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strscpy(info->driver, MODEL_DRIVER, sizeof(info->driver));
	strscpy(info->version, "1-synthetic", sizeof(info->version));
	strscpy(info->bus_info, "platform:estus_nic_model", sizeof(info->bus_info));
}

static int model_get_eee(struct net_device *dev, struct ethtool_keee *eee)
{
	struct model_priv *priv = netdev_priv(dev);
	int ret;

	model_read_delay();
	ret = model_fault(READ_ONCE(eee_read_fault));
	if (ret)
		return ret;
	mutex_lock(&priv->lock);
	*eee = priv->eee;
	mutex_unlock(&priv->lock);
	return 0;
}

static int model_set_eee(struct net_device *dev, struct ethtool_keee *eee)
{
	struct model_priv *priv = netdev_priv(dev);
	unsigned int fault = READ_ONCE(eee_write_fault);
	int ret = 0;

	mutex_lock(&priv->lock);
	if (eee_writes != UINT_MAX)
		WRITE_ONCE(eee_writes, eee_writes + 1);
	if (eee->tx_lpi_timer > 1000000 ||
	    !linkmode_subset(eee->advertised, priv->eee.supported)) {
		ret = -EINVAL;
		goto out;
	}
	if (fault == 1) {
		ret = -EIO;
		goto out;
	}
	if (fault == 2)
		goto out;
	priv->eee.eee_enabled = eee->eee_enabled;
	priv->eee.tx_lpi_enabled = eee->tx_lpi_enabled;
	priv->eee.tx_lpi_timer = eee->tx_lpi_timer;
	linkmode_copy(priv->eee.advertised, eee->advertised);
	/* No physical link or peer negotiation exists, even when enabled. */
	priv->eee.eee_active = false;
	if (fault == 3)
		ret = -EIO;
out:
	mutex_unlock(&priv->lock);
	return ret;
}

static void model_be16(u8 *data, unsigned int offset, u16 value)
{
	data[offset] = value >> 8;
	data[offset + 1] = value;
}

static void model_checksum(u8 *data, unsigned int start, unsigned int end)
{
	unsigned int i;
	u8 sum = 0;

	for (i = start; i < end; i++)
		sum += data[i];
	data[end] = sum;
}

/* Built once before registration, immutable while callbacks can execute. */
static u8 model_eeprom_image[MODEL_EEPROM_LEN];

static void model_init_eeprom(void)
{
	u8 *data = model_eeprom_image;

	data[0] = 3;
	data[1] = 4;
	data[2] = 7; /* LC */
	data[6] = 1; /* Synthetic 1000BASE-SX identifier. */
	data[11] = 1; /* 8B/10B */
	data[12] = 13;
	memset(data + 20, ' ', 16);
	memcpy(data + 20, "ESTUS TEST", 10);
	memset(data + 40, ' ', 16);
	memcpy(data + 40, "SIM-SFP-1", 9);
	memcpy(data + 56, "1.0 ", 4);
	memcpy(data + 68, "SYNTHETIC-000001", 16);
	memcpy(data + 84, "260101  ", 8);
	data[92] = BIT(6) | BIT(5) | BIT(3); /* DDM, internal cal, RX average */
	data[94] = 1; /* SFF-8472 revision 9.3 */
	model_checksum(data, 0, 63);
	model_checksum(data, 64, 95);
	model_checksum(data + 256, 0, 95);
	model_be16(data, 256 + 100, 2000);
	model_be16(data, 256 + 102, 10000);
	model_be16(data, 256 + 104, 5000);
}

static void model_copy_eeprom(u8 *data, unsigned int offset, unsigned int length,
			      unsigned int fault)
{
	u16 temperature, voltage;
	u8 readings[4];
	unsigned int i, position;

	memcpy(data, model_eeprom_image + offset, length);
	if (fault == 3 && offset == 0)
		data[0] = 0xff;
	if (offset >= 356 || offset + length <= 352)
		return;
	temperature = (u16)READ_ONCE(temperature_raw);
	voltage = READ_ONCE(voltage_raw);
	readings[0] = temperature >> 8;
	readings[1] = temperature;
	readings[2] = voltage >> 8;
	readings[3] = voltage;
	for (i = 0; i < ARRAY_SIZE(readings); i++) {
		position = 256 + 96 + i;
		if (position >= offset && position - offset < length)
			data[position - offset] = readings[i];
	}
}

static int model_module_info(struct net_device *dev, struct ethtool_modinfo *info)
{
	int ret;

	model_read_delay();
	ret = model_fault(READ_ONCE(module_fault));
	if (ret)
		return ret;
	info->type = ETH_MODULE_SFF_8472;
	info->eeprom_len = MODEL_EEPROM_LEN;
	return 0;
}

static int model_module_eeprom(struct net_device *dev,
			       struct ethtool_eeprom *ee, u8 *data)
{
	unsigned int fault;
	int ret;

	if (!ee->len || ee->offset >= MODEL_EEPROM_LEN ||
	    ee->len > MODEL_EEPROM_LEN - ee->offset)
		return -EINVAL;
	model_read_delay();
	fault = READ_ONCE(module_fault);
	ret = model_fault(fault);
	if (ret)
		return ret;
	model_copy_eeprom(data, ee->offset, ee->len, fault);
	return 0;
}

static int model_module_page(struct net_device *dev,
			     const struct ethtool_module_eeprom *page,
			     struct netlink_ext_ack *extack)
{
	unsigned int fault, base;
	int ret;

	if (page->bank || page->page ||
	    (page->i2c_address != 0x50 && page->i2c_address != 0x51) ||
	    !page->length || page->offset >= 256 ||
	    page->length > 128 - (page->offset % 128))
		return -EINVAL;
	model_read_delay();
	fault = READ_ONCE(module_fault);
	ret = model_fault(fault);
	if (ret)
		return ret;
	base = page->i2c_address == 0x51 ? 256 : 0;
	model_copy_eeprom(page->data, base + page->offset, page->length, fault);
	return page->length;
}

static const struct ethtool_ops model_ethtool_ops = {
	.get_drvinfo = model_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_eee = model_get_eee,
	.set_eee = model_set_eee,
	.get_module_info = model_module_info,
	.get_module_eeprom = model_module_eeprom,
	.get_module_eeprom_by_page = model_module_page,
};

static netdev_tx_t model_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* A configuration fixture, not a data-plane or loopback implementation. */
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops model_netdev_ops = {
	.ndo_start_xmit = model_xmit,
};

static int model_probe(struct platform_device *pdev)
{
	static const u8 mac[ETH_ALEN] = { 0x52, 0x54, 0, 0x12, 0x34, 0x5a };
	struct net_device *dev;
	struct model_priv *priv;
	int ret;

	dev = alloc_netdev(sizeof(*priv), "model0", NET_NAME_USER, ether_setup);
	if (!dev)
		return -ENOMEM;
	SET_NETDEV_DEV(dev, &pdev->dev);
	dev->netdev_ops = &model_netdev_ops;
	dev->ethtool_ops = &model_ethtool_ops;
	eth_hw_addr_set(dev, mac);
	netif_carrier_off(dev);
	priv = netdev_priv(dev);
	mutex_init(&priv->lock);
	linkmode_set_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, priv->eee.supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, priv->eee.supported);
	linkmode_copy(priv->eee.advertised, priv->eee.supported);
	priv->eee.tx_lpi_enabled = true;
	priv->eee.tx_lpi_timer = 100;
	ret = register_netdev(dev);
	if (ret) {
		free_netdev(dev);
		return ret;
	}
	platform_set_drvdata(pdev, dev);
	return 0;
}

static void model_remove(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);

	unregister_netdev(dev);
	platform_set_drvdata(pdev, NULL);
	free_netdev(dev);
}

static struct platform_driver model_driver = {
	.remove = model_remove,
	.driver = { .name = MODEL_DRIVER },
};
static struct platform_device *model_device;

static int __init model_init(void)
{
	int ret;

	model_init_eeprom();
	model_device = platform_device_register_simple(MODEL_DRIVER, -1, NULL, 0);
	if (IS_ERR(model_device))
		return PTR_ERR(model_device);
	ret = platform_driver_probe(&model_driver, model_probe);
	if (ret)
		platform_device_unregister(model_device);
	return ret;
}

static void __exit model_exit(void)
{
	platform_device_unregister(model_device);
	platform_driver_unregister(&model_driver);
}

module_init(model_init);
module_exit(model_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Lab-only synthetic EEE and SFF-8472 test NIC; no negotiation");
MODULE_ALIAS("platform:" MODEL_DRIVER);
