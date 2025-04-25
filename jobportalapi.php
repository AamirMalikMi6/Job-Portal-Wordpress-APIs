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


            
            register_activation_hook(__FILE__, 'jobportalapi_add_custom_roles');

            function jobportalapi_add_custom_roles()
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
        }

        public function load_plugin()
        {
            jobportalapi_plugin::jobportalapi_init();
        }


    }
}

// Initialize the plugin
new jobportalapi_main();
