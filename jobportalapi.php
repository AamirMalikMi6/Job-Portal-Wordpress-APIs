<?php
/*
 * Plugin Name:       Job Portal API
 * Description:       Plugin to create the API
 * Version:           1.0.0
 * Requires at least: 5.2
 * Requires PHP:      7.2
 * Author:            Aamir
 * License:           GPL v2 or later
 * Text Domain:       jobportalapi
 */


if (!defined('ABSPATH')) {
    exit;
}


define('JP_PLUGIN_VERSION', '1.0.0');
define('JP_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('JP_PLUGIN_URL', plugins_url('', __FILE__));

// Now include files

// Main plugin class
if (!class_exists('jobportalapi_main')) {
    class jobportalapi_main
    {
        public function __construct()
        {
            require_once JP_PLUGIN_PATH . 'includes/jobportalapi_plugin.php';

            $this->load_plugin();
            $this->register_hooks();
        }

        public function load_plugin()
        {
            JobPortalAPI_Plugin::jobportalapi_init();
        }

        public function register_hooks()
        {
            // Register activation hook
            register_activation_hook(__FILE__, [$this, 'add_custom_roles']);

            // Admin columns
            add_filter('manage_application_posts_columns', [$this, 'add_application_status_column']);
            add_action('manage_application_posts_custom_column', [$this, 'show_application_status_column'], 10, 2);
        }

        /**
         * Add custom user roles on plugin activation.
         */
        public function add_custom_roles()
        {
            add_role('employee', 'Employee', [
                'read' => true,
                'edit_posts' => false,
            ]);

            add_role('company', 'Company', [
                'read' => true,
                'edit_posts' => true,
                'upload_files' => true,
            ]);
        }

        /**
         * Add custom column to Application admin table.
         */
        public function add_application_status_column($columns)
        {
            $columns['application_status'] = __('Application Status', 'jobportalapi');
            return $columns;
        }

        /**
         * Display custom column content for Application post type.
         */
        public function show_application_status_column($column, $post_id)
        {
            if ($column === 'application_status') {
                $status = get_field('application_status', $post_id); // ACF field
                echo esc_html($status);
            }
        }

    }
}

// Initialize the plugin
new jobportalapi_main();
