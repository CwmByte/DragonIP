# DragonIP

**Contributors:** cwmbyte  
**Donate link:** https://cwmbyte.com/  
**Tags:** security, ip, privacy, admin, masking  
**Requires at least:** 5.0  
**Tested up to:** 6.8  
**Requires PHP:** 7.4  
**Stable tag:** 1.0  
**License:** GPLv2 or later  
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html  

Mask admin user IP addresses - both historical data and future activity

## Description

DragonIP protects administrator privacy by masking IP addresses throughout your WordPress installation. It can hide existing IP data and prevent future IP logging.

**What it does:**
* **Historical Masking** - Replace existing IP addresses with 127.0.0.1
* **Future Masking** - Automatically mask new IP addresses for ongoing activity
* **Smart Detection** - Works with comments, security plugins, and activity logs
* **Admin-Only** - Secure interface restricted to administrators

## Installation

1. Upload the `dragonip` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **Tools > DragonIP** in your admin panel

## Usage

### Historical IP Masking
1. Select the user to mask
2. Choose which areas to mask (use "Select All" for convenience)
3. Check the confirmation box
4. Click "Mask Historical IPs"

**⚠️ Warning**: This permanently overwrites existing IP addresses. **Backup your database first!**

### Future IP Masking
1. Select the target user
2. Click "Enable Future Masking" to activate
3. Click "Disable Future Masking" to turn it off

## What Gets Masked

**Historical masking covers:**
- Comments
- User meta data
- Wordfence logs
- Security plugins (Sucuri, MalCare, etc.)
- Activity logs

**Future masking covers:**
- New comments
- Login attempts
- General activity logging

## Important Notes

- **Always backup your database** before running historical IP masking
- Historical masking **permanently overwrites** existing IP addresses
- All masked IPs are changed to 127.0.0.1
- Only administrators can access the plugin
- Works with most WordPress security and logging plugins

## Changelog

**1.0**
* Initial release
* Historical IP masking functionality
* Future IP masking capability
* Support for major security plugins (Wordfence, Sucuri, MalCare, iThemes, etc.)
* Admin-only interface with confirmation requirements
* WordPress 5.0+ compatibility

## ⚠️ IMPORTANT DISCLAIMER

**DragonIP will PERMANENTLY OVERWRITE database data.** This plugin modifies existing IP addresses in your WordPress database and cannot be undone.

### 🛡️ BEFORE USING THIS PLUGIN:

1. **BACKUP YOUR DATABASE** - This is absolutely essential
2. **Test on a staging site first** - Never run on production without testing
3. **Understand the risks** - IP addresses will be permanently changed to 127.0.0.1

### 🚨 NO UNDO FUNCTION:

Once you run historical IP masking, the original IP addresses are **permanently lost**. There is no undo feature. Always backup first!

**Use at your own risk.**

---

DragonIP by [CwmByte](https://cwmbyte.com/)
