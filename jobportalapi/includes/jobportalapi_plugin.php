<?php
if (!defined('ABSPATH')) exit;

require_once JP_PLUGIN_PATH . 'includes/admin/jobportalapi_endpoints.php';

if (!class_exists('jobportalapi_plugin')) { 
    class jobportalapi_plugin
    {
        public static function jobportalapi_init()
        {
            self::jobportalapi_endpoints();
        }

        public static function jobportalapi_endpoints()
        {
            jobportalapi_endpoints::jobportalapi_init_endpoints();
        }
    }
}
