<?php
// if file is being called directly or not in the wordpress
if (! defined('ABSPATH')) exit; // Exit if accessed directly
/*
 * Package: jobportalapi
 * @subpackage jobportalapi/admin 
 * @since 1.0.0
 * @author Aamir
 */
require_once JP_PLUGIN_PATH . 'includes/admin/jobportalapi_create_endpoints.php';

if (!class_exists('jobportalapi_endpoints')) {
    class jobportalapi_endpoints
    {
        public static function jobportalapi_init_endpoints()
        {
            add_action('rest_api_init', array(__CLASS__, 'jobportalapi_register_endpoints'));
        }
        public static function jobportalapi_register_endpoints()
        {
            jobportalapi_create_endpoints::jobportalapi_init_endpoints();
            remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
            add_filter('rest_pre_serve_request', function ($value) {
                header("Access-Control-Allow-Origin: https://jobportal.arshadwpdev.com");
                // header("Access-Control-Allow-Origin: http://localhost:5173");
                header("Access-Control-Allow-Credentials: true");
                return $value;
            });
        }
    }
}
