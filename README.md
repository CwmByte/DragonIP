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

DragonIP is a comprehensive WordPress plugin designed to protect administrator privacy by masking IP addresses throughout your WordPress installation. Whether you need to hide historical IP data or prevent future IP logging, DragonIP provides a complete solution.

**Key Features:**
* **Historical IP Masking** - Replace existing IP addresses in your database with 127.0.0.1
* **Future IP Masking** - Automatically mask new IP addresses for ongoing activity
* **Comprehensive Coverage** - Works with comments, user meta, security plugins, and activity logs
* **Smart Detection** - Automatically finds and processes IP data across multiple plugins
* **Admin-Only Access** - Secure interface restricted to administrators
* **Confirmation Required** - Safety measures for destructive operations

This plugin is ideal for WordPress administrators who need to protect their privacy by ensuring their real IP addresses are not stored in logs, comments, or other database records.

## What it does

DragonIP provides two main functions:

1. **Historical IP Masking** - Scans your database for existing IP addresses associated with admin users and replaces them with 127.0.0.1
2. **Future IP Masking** - Intercepts and masks new IP addresses for ongoing admin activity

## Features

- Change existing IP addresses to 127.0.0.1 for any admin user
- Automatically mask new IP addresses for future activity
- Set target user (defaults to current user)
- Covers comments, user meta, Wordfence logs, iThemes security, security plugins (Sucuri, MalCare, etc.), activity logs, and other log tables
- Dynamic detection of security plugin tables
- Protects user biographies from being overwritten
- Admin-only access with confirmation required for destructive operations
- Error handling for database issues
- Automatic setup on plugin activation
- "Select All" convenience feature

## Installation

<<<<<<< HEAD
1. Upload the `dragonip` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
=======
1. Upload the `DragonIP` folder to `/wp-content/plugins/`
2. Activate the plugin
>>>>>>> 415645646b9190569bd8a77aa41dff3d14c7a8b7
3. Go to **Tools > DragonIP** in your admin panel

## Usage

### Setup

The plugin automatically sets the current user as the target when activated. You can change this in the User Settings section.

### Historical IP Masking

1. Select the user to mask
2. Choose which areas to mask (use "Select All" for convenience, or choose specific areas)
3. Check the confirmation box
4. Click "Mask Historical IPs"

**Warning**: This permanently overwrites existing IP addresses. Backup your database first.

### Future IP Masking

1. Select the target user
2. Click "Enable Future Masking" to activate
3. Click "Disable Future Masking" to turn it off

## Configuration

### User Settings

The User Settings section shows:
- Current logged-in user
- Currently saved target user
- Dropdown to change the target user

Settings are saved automatically and preserved between sessions.

## Security

- Only administrators can access the plugin
- Only admin users can be selected as targets
- All forms use WordPress nonce verification
- Destructive operations require confirmation

## What Gets Masked

### Historical masking covers:
- Comments
- User meta data (IP-related only, protects biographies)
- Wordfence logs
- iThemes Security logs
- Security plugins (Sucuri, MalCare, All In One WP Security, Security Ninja, etc.)
- Activity logs
- Other log tables with IP columns

### Future masking covers:
- Server variables (`$_SERVER['REMOTE_ADDR']`, etc.)
- New comments
- Login attempts
- General activity logging

## Important Notes

- Always backup your database before running historical IP masking
- Historical masking permanently overwrites existing IP addresses
- All masked IPs are changed to 127.0.0.1
- Works with most WordPress security and logging plugins
- Historical masking may take time on large databases
- User biographies are protected from being overwritten
- Dynamic detection automatically finds security plugin tables

## Troubleshooting

**No users showing**: Make sure you're logged in as an administrator.

**Masking not working**: Check that the target user is correctly selected.

**Future masking inactive**: Verify the target user ID matches your current user ID.

**Database errors**: The plugin now handles null results gracefully - check WordPress error logs for other issues.

**Security plugins not detected**: The dynamic detection should find most security plugins automatically.

Check WordPress error logs and plugin compatibility if you have issues.

## Technical Details

<<<<<<< HEAD
**WordPress Hooks Used:**
- `admin_menu` - Adds admin menu page
- `admin_init` - Handles form processing
- `init` - Initializes IP masking functionality
- `wp_insert_comment` - Masks comment IPs
- `wp_login` - Masks login IPs
- `pre_comment_author_ip` - Filters comment IPs
- `register_activation_hook` - Sets up default options

**Database Tables Affected:**
- `wp_comments` - Comment IP addresses
- `wp_usermeta` - User meta IP data
- `wp_wfLogins`, `wp_wfHits` - Wordfence logs
- Security plugin tables (Sucuri, MalCare, iThemes, etc.)
- Custom log tables with IP columns

**WordPress Options Stored:**
- `dragon_ip_target_user` - Target user ID for masking
- `dragon_ip_future_enabled` - Future masking status

**Security Features:**
- Nonce verification for all forms
- Input sanitization and validation
- Output escaping for all displayed data
- Prepared SQL statements
- Admin-only access control

## Changelog

**1.0**
* Initial release
* Historical IP masking functionality
* Future IP masking capability
* Support for major security plugins (Wordfence, Sucuri, MalCare, iThemes, etc.)
* Dynamic table detection
* Admin-only interface with confirmation requirements
* Comprehensive input sanitization and output escaping
* WordPress 5.0+ compatibility
=======
**WordPress hooks used:**
- `admin_menu`, `admin_init`, `init`
- `wp_insert_comment`, `wp_login`
- `pre_comment_author_ip`
- `register_activation_hook`

**Database tables affected:**
- `wp_comments`, `wp_usermeta`
- `wp_wfLogins`, `wp_wfHits` (Wordfence)
- Custom log tables with IP columns

**Options stored:**
- `dragon_ip_target_user`
- `dragon_ip_future_enabled`
>>>>>>> 415645646b9190569bd8a77aa41dff3d14c7a8b7

## License

GPL2+ license. See plugin header for details.

## About CwmByte

[CwmByte](https://cwmbyte.com/) - Two decades of IT expertise, specializing in practical applications. Based in Cardiff.

---

## ⚠️ IMPORTANT DISCLAIMER

**DragonIP will PERMANENTLY OVERWRITE database data.** This plugin modifies existing IP addresses in your WordPress database and cannot be undone.

### 🛡️ BEFORE USING THIS PLUGIN:

1. **BACKUP YOUR DATABASE** - This is absolutely essential
2. **Test on a staging site first** - Never run on production without testing
3. **Verify your backup works** - Make sure you can restore if needed
4. **Understand the risks** - IP addresses will be permanently changed to 127.0.0.1

### 📋 WHAT GETS OVERWRITTEN:

- Comment IP addresses
- User meta IP data
- Security plugin logs (Wordfence, Sucuri, etc.)
- Activity logs and audit trails
- Any other IP-related database entries

### 🚨 NO UNDO FUNCTION:

Once you run historical IP masking, the original IP addresses are **permanently lost**. There is no undo feature. Always backup first!

**Use at your own risk. CwmByte is not responsible for data loss.**

---

DragonIP by [CwmByte](https://cwmbyte.com/)
