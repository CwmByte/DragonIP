<?php
/**
 * Plugin Name: DragonIP
 * Plugin URI: https://cwmbyte.com/
 * Description: Mask admin user IP addresses - both historical data and future activity
 * Version: 1.0
 * Author: CwmByte
 * License: GPL2+
 * Text Domain: dragonip
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class DragonIP {
    
    private $masked_ip = '127.0.0.1';
    private $admin_username = ''; // Will be set to current user by default
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'handle_masking'));
        
        // Set default user to current user if not set
        $this->set_default_user();
        
        // Hook into future IP logging
        add_action('init', array($this, 'init_ip_masking'));
    }
    
    private function set_default_user() {
        $current_user_id = get_current_user_id();
        if ($current_user_id && !get_option('dragon_ip_target_user', false)) {
            update_option('dragon_ip_target_user', $current_user_id);
        }
    }
    
    public function activate() {
        // Set default user on activation
        $current_user_id = get_current_user_id();
        if ($current_user_id) {
            update_option('dragon_ip_target_user', $current_user_id);
        }
        
        // Set default future masking to disabled
        if (!get_option('dragon_ip_future_enabled', false)) {
            update_option('dragon_ip_future_enabled', false);
        }
    }
    
    public function add_admin_menu() {
        add_management_page(
            'DragonIP',
            'DragonIP',
            'manage_options',
            'dragon-ip',
            array($this, 'admin_page')
        );
    }
    
    public function admin_page() {
        $current_user = wp_get_current_user();
        ?>
        <div class="wrap">
            <h1>🐉 DragonIP - IP Address Masker</h1>
            
            <div style="background: #e3f2fd; padding: 15px; margin: 20px 0; border-left: 4px solid #2196f3;">
                <h3>🎭 What This Does</h3>
                <p><strong>Historical:</strong> Changes existing IP addresses to 127.0.0.1</p>
                <p><strong>Future:</strong> Automatically masks new IP addresses</p>
            </div>
            
            <div style="background: #fff3e0; padding: 15px; margin: 20px 0; border-left: 4px solid #ff9800;">
                <h3>⚠️ Important</h3>
                <p>• Permanently overwrites IP addresses - backup database first!</p>
                <p>• Future masking stays active until disabled</p>
            </div>
            
            <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
                <h2>⚙️ User Settings</h2>
                <p>Configure which user's IP addresses should be masked</p>
                
                <form method="post" action="">
                    <?php wp_nonce_field('set_default_user', 'default_user_nonce'); ?>
                    <input type="hidden" name="action" value="set_default_user">
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row">Default User</th>
                            <td>
                                <?php 
                                $current_user = wp_get_current_user();
                                $current_user_id = get_current_user_id();
                                $saved_user_id = get_option('dragon_ip_target_user', $current_user_id);
                                $saved_user = get_user_by('id', $saved_user_id);
                                ?>
                                <p><strong>Current User:</strong> <?php echo esc_html($current_user->user_login); ?> (ID: <?php echo esc_html($current_user_id); ?>)</p>
                                <p><strong>Saved Target User:</strong> <?php echo $saved_user ? esc_html($saved_user->user_login) : 'None'; ?> (ID: <?php echo esc_html($saved_user_id); ?>)</p>
                                <p class="description">The default user is automatically set to the current logged-in user. You can change this below.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Set Target User</th>
                            <td>
                                <?php 
                                wp_dropdown_users(array(
                                    'name' => 'default_target_user_id',
                                    'show_option_none' => 'Select user to set as default...',
                                    'option_none_value' => '',
                                    'selected' => $saved_user_id,
                                    'role__in' => array('administrator') // Only show admins for safety
                                ));
                                ?>
                                <p class="description">This user will be used as the default target for IP masking operations</p>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <input type="submit" class="button-primary" value="💾 Save User Settings" />
                    </p>
                </form>
            </div>
            
            <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
                <h2>🔍 Historical IP Masking</h2>
                <p>Overwrite ALL existing IP addresses for the admin user with 127.0.0.1</p>
                
                <form method="post" action="">
                    <?php wp_nonce_field('mask_historical_action', 'mask_historical_nonce'); ?>
                    <input type="hidden" name="action" value="mask_historical">
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row">Target User</th>
                            <td>
                                <?php 
                                wp_dropdown_users(array(
                                    'name' => 'target_user_id',
                                    'show_option_none' => 'Select user to mask...',
                                    'option_none_value' => '',
                                    'selected' => get_option('dragon_ip_target_user', ''),
                                    'role__in' => array('administrator') // Only show admins for safety
                                ));
                                ?>
                                <p class="description">Select the user whose IP history should be masked to 127.0.0.1</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Areas to Mask</th>
                            <td>
                                <label><input type="checkbox" id="select_all_areas" onclick="toggleAllAreas()"> <strong>Select All</strong></label><br><br>
                                <label><input type="checkbox" name="mask_areas[]" value="comments" checked> Comments</label><br>
                                <label><input type="checkbox" name="mask_areas[]" value="usermeta" checked> User Meta Data</label><br>
                                <label><input type="checkbox" name="mask_areas[]" value="wordfence" checked> Wordfence Logs</label><br>
                                <label><input type="checkbox" name="mask_areas[]" value="ithemes" checked> iThemes Security</label><br>
                                <label><input type="checkbox" name="mask_areas[]" value="security_plugins" checked> Security Plugins (Sucuri, MalCare, etc.)</label><br>
                                <label><input type="checkbox" name="mask_areas[]" value="activity_logs" checked> Activity Logs</label><br>
                                <label><input type="checkbox" name="mask_areas[]" value="all_logs" checked> All Log Tables</label>
                                
                                <script>
                                function toggleAllAreas() {
                                    var selectAll = document.getElementById('select_all_areas');
                                    var checkboxes = document.querySelectorAll('input[name="mask_areas[]"]');
                                    
                                    for (var i = 0; i < checkboxes.length; i++) {
                                        checkboxes[i].checked = selectAll.checked;
                                    }
                                }
                                </script>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Confirmation</th>
                            <td>
                                <label><input type="checkbox" name="confirm_historical" required> 
                                I understand this will permanently overwrite existing IP addresses with 127.0.0.1</label>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <input type="submit" class="button-primary" value="🎭 Mask Historical IPs" 
                               onclick="return confirm('This will permanently change IP addresses to 127.0.0.1. Are you sure?');" />
                    </p>
                </form>
            </div>
            
            <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
                <h2>🚀 Future IP Masking</h2>
                <p>Automatically mask IP addresses for future admin activity</p>
                
                <form method="post" action="">
                    <?php wp_nonce_field('toggle_future_masking', 'future_masking_nonce'); ?>
                    <input type="hidden" name="action" value="toggle_future_masking">
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row">Current Status</th>
                            <td>
                                <?php 
                                $future_masking = get_option('dragon_ip_future_enabled', false);
                                $target_user = get_option('dragon_ip_target_user', '');
                                $user_info = $target_user ? get_user_by('id', $target_user) : null;
                                ?>
                                <strong style="color: <?php echo $future_masking ? '#4caf50' : '#f44336'; ?>">
                                    <?php echo $future_masking ? '✅ ACTIVE' : '❌ INACTIVE'; ?>
                                </strong>
                                <?php if ($user_info): ?>
                                    <p class="description">Target User: <?php echo esc_html($user_info->user_login); ?></p>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Target User</th>
                            <td>
                                <?php 
                                wp_dropdown_users(array(
                                    'name' => 'future_target_user_id',
                                    'show_option_none' => 'Select user to mask...',
                                    'option_none_value' => '',
                                    'selected' => get_option('dragon_ip_target_user', ''),
                                    'role__in' => array('administrator')
                                ));
                                ?>
                                <p class="description">This user's future IP addresses will be automatically masked to 127.0.0.1</p>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <?php if ($future_masking): ?>
                            <input type="submit" name="disable_future" class="button-secondary" value="🛑 Disable Future Masking" />
                        <?php else: ?>
                            <input type="submit" name="enable_future" class="button-primary" value="🚀 Enable Future Masking" />
                        <?php endif; ?>
                    </p>
                </form>
            </div>
            
            <?php 
            // Display messages from redirects - no nonce needed for display-only parameters
            // These are safe to display as they come from our own redirects with sanitized content
            if (isset($_GET['message'])): ?>
                <div class="notice notice-success">
                    <p><?php echo esc_html(sanitize_text_field(wp_unslash($_GET['message']))); ?></p>
                </div>
            <?php endif; ?>
            
            <?php if (isset($_GET['error'])): ?>
                <div class="notice notice-error">
                    <p><?php echo esc_html(sanitize_text_field(wp_unslash($_GET['error']))); ?></p>
                </div>
            <?php endif; ?>
            
            <div style="background: #f8f9fa; padding: 15px; margin: 20px 0; border: 1px solid #e9ecef; text-align: center; border-radius: 5px;">
                <p style="margin: 0; color: #6c757d; font-size: 14px;">
                    DragonIP by <a href="https://cwmbyte.com/" target="_blank" style="color: #007cba; text-decoration: none;">CwmByte</a> | 
                    <a href="https://cwmbyte.com/" target="_blank" style="color: #007cba; text-decoration: none;">Visit Our Website</a>
                </p>
            </div>
        </div>
        <?php
    }
    
    public function handle_masking() {
        if (!isset($_POST['action'])) {
            return;
        }
        
        $action = sanitize_text_field(wp_unslash($_POST['action']));
        
        if ($action === 'set_default_user') {
            if (!isset($_POST['default_user_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['default_user_nonce'])), 'set_default_user')) {
                wp_die('Security check failed');
            }
            $this->set_target_user();
        }
        
        if ($action === 'mask_historical') {
            if (!isset($_POST['mask_historical_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['mask_historical_nonce'])), 'mask_historical_action')) {
                wp_die('Security check failed');
            }
            $this->mask_historical_ips();
        }
        
        if ($action === 'toggle_future_masking') {
            if (!isset($_POST['future_masking_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['future_masking_nonce'])), 'toggle_future_masking')) {
                wp_die('Security check failed');
            }
            $this->toggle_future_masking();
        }
    }
    
    private function set_target_user() {
        // Note: This method is called from handle_masking() which already verifies nonces
        if (!isset($_POST['default_target_user_id'])) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Please select a target user.')));
            exit;
        }
        
        $target_user_id = intval(sanitize_text_field(wp_unslash($_POST['default_target_user_id'])));
        
        if (empty($target_user_id)) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Please select a target user.')));
            exit;
        }
        
        $user = get_user_by('id', $target_user_id);
        if (!$user) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Invalid user selected.')));
            exit;
        }
        
        update_option('dragon_ip_target_user', $target_user_id);
        $message = "💾 Target user set to: {$user->user_login} (ID: {$target_user_id})";
        wp_redirect(admin_url('tools.php?page=dragon-ip&message=' . urlencode($message)));
        exit;
    }
    
    private function mask_historical_ips() {
        // Note: This method is called from handle_masking() which already verifies nonces
        if (!isset($_POST['target_user_id']) || !isset($_POST['confirm_historical'])) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Please select a user and confirm the action.')));
            exit;
        }
        
        $user_id = intval(sanitize_text_field(wp_unslash($_POST['target_user_id'])));
        $mask_areas = isset($_POST['mask_areas']) ? array_map('sanitize_text_field', wp_unslash($_POST['mask_areas'])) : array();
        
        $user = get_user_by('id', $user_id);
        if (!$user) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Invalid user selected.')));
            exit;
        }
        
        global $wpdb;
        $results = array();
        $username = $user->user_login;
        $user_email = $user->user_email;
        
        // Comments
        if (in_array('comments', $mask_areas)) {
            $count = $wpdb->query($wpdb->prepare(
                "UPDATE {$wpdb->comments} SET comment_author_IP = %s WHERE user_id = %d",
                $this->masked_ip, $user_id
            ));
            if ($user_email) {
                $count += $wpdb->query($wpdb->prepare(
                    "UPDATE {$wpdb->comments} SET comment_author_IP = %s WHERE comment_author_email = %s",
                    $this->masked_ip, $user_email
                ));
            }
            $results[] = "Comments: {$count} IPs masked";
        }
        
        // User Meta
        if (in_array('usermeta', $mask_areas)) {
            // Find all IP-related meta keys (exclude biography and other non-IP fields)
            $ip_metas = $wpdb->get_results($wpdb->prepare(
                "SELECT umeta_id, meta_key FROM {$wpdb->usermeta} 
                WHERE user_id = %d 
                AND (
                    meta_key LIKE %s OR 
                    meta_key LIKE %s OR
                    meta_key = 'last_login_ip' OR
                    meta_key = 'login_ip' OR
                    meta_key = 'user_ip' OR
                    meta_key = 'registration_ip'
                )
                AND meta_key NOT IN ('description', 'biography', 'user_description')
                AND meta_key NOT LIKE %s
                AND meta_key NOT LIKE %s",
                $user_id,
                '%_ip%',
                '%ip_%',
                '%bio%',
                '%description%'
            ));
            
            if ($ip_metas && is_array($ip_metas)) {
                foreach ($ip_metas as $meta) {
                    $wpdb->update(
                        $wpdb->usermeta,
                        array('meta_value' => $this->masked_ip),
                        array('umeta_id' => $meta->umeta_id)
                    );
                }
                $results[] = "User Meta: " . count($ip_metas) . " IP entries masked";
            } else {
                $results[] = "User Meta: 0 IP entries masked";
            }
        }
        
        // Wordfence
        if (in_array('wordfence', $mask_areas)) {
            $wf_count = 0;
            if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}wfLogins'")) {
                $wf_count += $wpdb->query($wpdb->prepare(
                    "UPDATE {$wpdb->prefix}wfLogins SET IP = INET_ATON(%s) WHERE userID = %d",
                    $this->masked_ip, $user_id
                ));
            }
            if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}wfHits'")) {
                $wf_count += $wpdb->query($wpdb->prepare(
                    "UPDATE {$wpdb->prefix}wfHits SET IP = INET_ATON(%s) WHERE userID = %d",
                    $this->masked_ip, $user_id
                ));
            }
            $results[] = "Wordfence: {$wf_count} entries masked";
        }
        
        // Security Plugins (Sucuri, MalCare, All In One WP Security, Security Ninja, etc.)
        if (in_array('security_plugins', $mask_areas)) {
            $security_tables = $wpdb->get_results($wpdb->prepare("
                SELECT TABLE_NAME, COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME LIKE %s
                AND (COLUMN_NAME LIKE %s OR COLUMN_NAME LIKE %s)
                AND TABLE_NAME NOT LIKE %s
                AND (
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s OR
                    TABLE_NAME LIKE %s
                )
            ", 
                $wpdb->prefix . '%',
                '%ip%',
                '%IP%',
                '%wf%',
                '%sucuri%',
                '%malcare%',
                '%aiowps%',
                '%security_ninja%',
                '%audit%',
                '%login%',
                '%firewall%',
                '%security%'
            ), ARRAY_A);
            
            $security_count = 0;
            foreach ($security_tables as $table_info) {
                $table_name = $table_info['TABLE_NAME'];
                $column_name = $table_info['COLUMN_NAME'];
                
                // Check if table has user_id column
                $has_user_id = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, 'user_id'));
                if ($has_user_id) {
                    $security_count += $wpdb->query($wpdb->prepare(
                        "UPDATE %s SET %s = %s WHERE user_id = %d",
                        $table_name, $column_name, $this->masked_ip, $user_id
                    ));
                }
                
                // Also check for username columns
                $has_username = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, '%username%'));
                if ($has_username) {
                    $username_col = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, '%username%'));
                    $security_count += $wpdb->query($wpdb->prepare(
                        "UPDATE %s SET %s = %s WHERE %s = %s",
                        $table_name, $column_name, $this->masked_ip, $username_col, $username
                    ));
                }
                
                // Check for email columns
                $has_email = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, '%email%'));
                if ($has_email && $user_email) {
                    $email_col = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, '%email%'));
                    $security_count += $wpdb->query($wpdb->prepare(
                        "UPDATE %s SET %s = %s WHERE %s = %s",
                        $table_name, $column_name, $this->masked_ip, $email_col, $user_email
                    ));
                }
            }
            $table_count = ($security_tables && is_array($security_tables)) ? count($security_tables) : 0;
            $results[] = "Security Plugins: {$security_count} IP entries masked across " . $table_count . " tables";
        }
        
        // All log tables - find any table with IP columns
        if (in_array('all_logs', $mask_areas)) {
            $tables_with_ip = $wpdb->get_results($wpdb->prepare("
                SELECT TABLE_NAME, COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME LIKE %s
                AND (COLUMN_NAME LIKE %s OR COLUMN_NAME LIKE %s)
                AND TABLE_NAME NOT LIKE %s
            ", 
                $wpdb->prefix . '%',
                '%ip%',
                '%IP%',
                '%wf%'
            ), ARRAY_A);
            
            $log_count = 0;
            foreach ($tables_with_ip as $table_info) {
                $table_name = $table_info['TABLE_NAME'];
                $column_name = $table_info['COLUMN_NAME'];
                
                // Check if table has user_id column
                $has_user_id = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, 'user_id'));
                if ($has_user_id) {
                    $log_count += $wpdb->query($wpdb->prepare(
                        "UPDATE %s SET %s = %s WHERE user_id = %d",
                        $table_name, $column_name, $this->masked_ip, $user_id
                    ));
                }
                
                // Also check for username columns
                $has_username = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, '%username%'));
                if ($has_username) {
                    $username_col = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM %s LIKE %s", $table_name, '%username%'));
                    $log_count += $wpdb->query($wpdb->prepare(
                        "UPDATE %s SET %s = %s WHERE %s = %s",
                        $table_name, $column_name, $this->masked_ip, $username_col, $username
                    ));
                }
            }
            $table_count = ($tables_with_ip && is_array($tables_with_ip)) ? count($tables_with_ip) : 0;
            $results[] = "Log Tables: {$log_count} IP entries masked across " . $table_count . " tables";
        }
        
        // Save the target user for future masking
        update_option('dragon_ip_target_user', $user_id);
        
        $message = "🎭 Historical IP masking completed for '{$username}'. " . implode(' | ', $results);
        wp_redirect(admin_url('tools.php?page=dragon-ip&message=' . urlencode($message)));
        exit;
    }
    
    private function toggle_future_masking() {
        // Note: This method is called from handle_masking() which already verifies nonces
        if (!isset($_POST['future_target_user_id'])) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Please select a target user.')));
            exit;
        }
        
        $target_user_id = intval(sanitize_text_field(wp_unslash($_POST['future_target_user_id'])));
        
        if (empty($target_user_id)) {
            wp_redirect(admin_url('tools.php?page=dragon-ip&error=' . urlencode('Please select a target user.')));
            exit;
        }
        
        if (isset($_POST['enable_future'])) {
            update_option('dragon_ip_future_enabled', true);
            update_option('dragon_ip_target_user', $target_user_id);
            $message = "🚀 Future IP masking ENABLED for user ID: {$target_user_id}";
        } else {
            update_option('dragon_ip_future_enabled', false);
            $message = "🛑 Future IP masking DISABLED";
        }
        
        wp_redirect(admin_url('tools.php?page=dragon-ip&message=' . urlencode($message)));
        exit;
    }
    
    public function init_ip_masking() {
        if (!get_option('dragon_ip_future_enabled', false)) {
            return;
        }
        
        $target_user_id = get_option('dragon_ip_target_user', 0);
        if (!$target_user_id || get_current_user_id() !== intval($target_user_id)) {
            return;
        }
        
        // Hook into various WordPress actions that log IPs
        add_action('wp_insert_comment', array($this, 'mask_comment_ip'), 10, 2);
        add_action('wp_login', array($this, 'mask_login_ip'), 10, 2);
        add_filter('pre_comment_author_ip', array($this, 'filter_comment_ip'));
        
        // Override $_SERVER variables for this user
        add_action('init', array($this, 'override_server_ip'), 1);
    }
    
    public function override_server_ip() {
        if (!get_option('dragon_ip_future_enabled', false)) {
            return;
        }
        
        $target_user_id = get_option('dragon_ip_target_user', 0);
        if (!$target_user_id || get_current_user_id() !== intval($target_user_id)) {
            return;
        }
        
        // Override common IP server variables
        $_SERVER['REMOTE_ADDR'] = $this->masked_ip;
        $_SERVER['HTTP_X_FORWARDED_FOR'] = $this->masked_ip;
        $_SERVER['HTTP_X_REAL_IP'] = $this->masked_ip;
        $_SERVER['HTTP_CLIENT_IP'] = $this->masked_ip;
    }
    
    public function mask_comment_ip($comment_id, $comment_obj) {
        $target_user_id = get_option('dragon_ip_target_user', 0);
        
        if ($comment_obj && isset($comment_obj->user_id) && $comment_obj->user_id == $target_user_id) {
            global $wpdb;
            $wpdb->update(
                $wpdb->comments,
                array('comment_author_IP' => $this->masked_ip),
                array('comment_ID' => $comment_id)
            );
        }
    }
    
    public function filter_comment_ip($ip) {
        $target_user_id = get_option('dragon_ip_target_user', 0);
        
        if ($target_user_id && get_current_user_id() === intval($target_user_id)) {
            return $this->masked_ip;
        }
        
        return $ip;
    }
    
    public function mask_login_ip($user_login, $user) {
        $target_user_id = get_option('dragon_ip_target_user', 0);
        
        if ($target_user_id && $user->ID === intval($target_user_id)) {
            // This will help with any login logging that happens after this hook
            $_SERVER['REMOTE_ADDR'] = $this->masked_ip;
        }
    }
}

// Initialize DragonIP
$dragon_ip = new DragonIP();

// Register activation hook
register_activation_hook(__FILE__, array($dragon_ip, 'activate'));
?>