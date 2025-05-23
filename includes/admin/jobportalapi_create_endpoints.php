<?php
// if file is being called directly or not in the wordpress
if (!defined('ABSPATH'))
    exit; // Exit if accessed directly
/*
 * Package: jobportalapi
 * @subpackage jobportalapi/admin 
 * @since 1.0.0
 * @author Aamir
 */

require_once JP_PLUGIN_PATH . 'includes/admin/jobportalapi_endpoint_callbacks.php';

if (!class_exists('jobportalapi_create_endpoints')) {
    class jobportalapi_create_endpoints
    {
        public static function jobportalapi_init_endpoints()
        {
            register_rest_route('jobportalapi/v1', '/jobs', array(
                'methods' => 'GET',
                'callback' => array('jobportalapi_endpoints_callbacks', 'get_jobs'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));

            // 🔥 New endpoints for single job and company
            register_rest_route('jobportalapi/v1', '/job', array(
                'methods' => 'GET',
                'callback' => array('jobportalapi_endpoints_callbacks', 'get_single_job'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));


            // Create a new Job
            register_rest_route('jobportalapi/v1', '/job', array(
                'methods' => 'POST',
                'callback' => array('jobportalapi_endpoints_callbacks', 'create_job'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));

            //update or put job
            register_rest_route('jobportalapi/v1', '/job', array(
                'methods' => 'PUT',
                'callback' => array('jobportalapi_endpoints_callbacks', 'update_job'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));

            //delete job 
            register_rest_route('jobportalapi/v1', '/job', array(
                'methods' => 'DELETE',
                'callback' => array('jobportalapi_endpoints_callbacks', 'delete_job'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));

            //register and login users 
            register_rest_route('jobportalapi/v1', '/register', [
                'methods' => 'POST',
                'callback' => array('jobportalapi_endpoints_callbacks', 'jobportalapi_register_user'),
                // 'permission_callback' => '__return_true' // No authentication required for registration
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            register_rest_route('jobportalapi/v1', '/login', [
                'methods' => 'POST',
                'callback' => array('jobportalapi_endpoints_callbacks', 'jobportalapi_login_user'),
                // 'permission_callback' => '__return_true' // No authentication required for login
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);


            register_rest_route('jobportalapi/v1', '/validate', [
                'methods' => 'GET',
                'callback' => ['jobportalapi_endpoints_callbacks', 'jobportalapi_validate_user_session'],
                'permission_callback' => '__return_true',
            ]);


            register_rest_route('jobportalapi/v1', '/logout', [
                'methods' => 'POST',
                'callback' => ['jobportalapi_endpoints_callbacks', 'user_logout'],
                'permission_callback' => '__return_true',
            ]);

            register_rest_route('jobportalapi/v1', '/update-user', [
                'methods' => 'PUT',
                'callback' => ['jobportalapi_endpoints_callbacks', 'jobportalapi_update_user'],
                // 'permission_callback' => '__return_true', // Or validate token if you want secure
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);


            register_rest_route('jobportalapi/v1', '/get-user', [
                'methods' => 'GET',
                'callback' => ['jobportalapi_endpoints_callbacks', 'jobportalapi_get_user'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            register_rest_route('jobportalapi/v1', '/companies', array(
                'methods' => 'GET',
                'callback' => array('jobportalapi_endpoints_callbacks', 'get_companies'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));

            register_rest_route('jobportalapi/v1', '/company', array(
                'methods' => 'GET',
                'callback' => array('jobportalapi_endpoints_callbacks', 'get_single_company'),
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ));


            register_rest_route('jobportalapi/v1', '/get-all-users', [
                'methods' => 'GET',
                'callback' => ['jobportalapi_endpoints_callbacks', 'jobportalapi_get_all_users'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);


            //apply job
            register_rest_route('jobportalapi/v1', '/apply-job', [
                'methods' => 'POST',
                'callback' => ['jobportalapi_endpoints_callbacks', 'apply_job'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            register_rest_route('jobportalapi/v1', '/get-applications', [
                'methods' => 'GET',
                'callback' => ['jobportalapi_endpoints_callbacks', 'get_user_applications'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);










            // Update application status (for employers)
            register_rest_route('jobportalapi/v1', '/update-application-status', [
                'methods' => 'PUT',
                'callback' => ['jobportalapi_endpoints_callbacks', 'update_application_status'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            // Get applications for a specific job (for employers)
            register_rest_route('jobportalapi/v1', '/job-applications', [
                'methods' => 'GET',
                'callback' => ['jobportalapi_endpoints_callbacks', 'get_job_applications'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            // Update an existing application (for applicants)
            register_rest_route('jobportalapi/v1', '/update-application', [
                'methods' => 'PUT',
                'callback' => ['jobportalapi_endpoints_callbacks', 'update_application'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            // Withdraw an application (for applicants)
            register_rest_route('jobportalapi/v1', '/withdraw-application', [
                'methods' => 'PUT',
                'callback' => ['jobportalapi_endpoints_callbacks', 'withdraw_application'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            // Get application statistics (for employers)
            register_rest_route('jobportalapi/v1', '/application-statistics', [
                'methods' => 'GET',
                'callback' => ['jobportalapi_endpoints_callbacks', 'get_application_statistics'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);

            // Schedule interview (for employers)
            register_rest_route('jobportalapi/v1', '/schedule-interview', [
                'methods' => 'POST',
                'callback' => ['jobportalapi_endpoints_callbacks', 'schedule_interview'],
                'permission_callback' => array('jobportalapi_create_endpoints', 'set_authentication_token')
            ]);
        }

        // Permission callback to check API Key or JWT Token
        public static function set_authentication_token(WP_REST_Request $request)
        {
            $auth_header = $request->get_header('Authorization'); // Extract Authorization header

            // If no authorization is provided
            if (empty($auth_header)) {
                return new WP_Error('rest_forbidden', 'Missing API key or token', ['status' => 403]);
            }

            // Check if it's a Bearer token authentication attempt
            if (strpos($auth_header, 'Bearer ') === 0) {
                $token = str_replace('Bearer ', '', $auth_header);

                // First check if it's the static API key
                if ($token === 'abc_125!dcdfvvfdvxssabbb_dcdsv') {
                    return true;
                }

                // Otherwise validate as JWT token
                $validation_result = jobportalapi_endpoints_callbacks::jobportalapi_validate_token($token);

                if (!$validation_result) {
                    return new WP_Error('rest_forbidden', 'Invalid or expired token', ['status' => 403]);
                }

                // ✨ Set the authenticated user!
                wp_set_current_user($validation_result['user_id']);

                // Add user data to the request
                $request->set_param('user_id', $validation_result['user_id']);
                return true;
            }

            return new WP_Error('rest_forbidden', 'Invalid authorization format', ['status' => 403]);
        }
    }
}