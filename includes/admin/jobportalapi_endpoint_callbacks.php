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

if (!class_exists('jobportalapi_endpoints_callbacks')) {
    class jobportalapi_endpoints_callbacks
    {


        // This function will return list of 'job' custom posts
        public static function get_jobs(WP_REST_Request $request)
        {
            $filter_by_company = $request->get_param('filter_by_company');
        
            $query_args = [
                'post_type' => 'job',
                'post_status' => 'publish',
                'numberposts' => -1,
            ];
        
            // Apply company filter if requested
            if (!empty($filter_by_company)) {
                // If it's numeric, treat it as a specific company user ID
                if (is_numeric($filter_by_company)) {
                    $query_args['author'] = intval($filter_by_company);
                } else {
                    // If it's a truthy string like "true" or "1", filter by company role
                    $company_users = get_users([
                        'role' => 'company',
                        'fields' => ['ID'],
                    ]);
                    if (!empty($company_users)) {
                        $company_user_ids = wp_list_pluck($company_users, 'ID');
                        $query_args['author__in'] = $company_user_ids;
                    } else {
                        return rest_ensure_response([
                            'success' => true,
                            'status' => 200,
                            'message' => 'No company users found.',
                            'data' => [],
                        ]);
                    }
                }
            }
        
            // Run the query with all filters applied
            $query = new WP_Query($query_args);
            $total_jobs = $query->found_posts;
            
            // Get the posts from our query
            $jobs = $query->posts;
        
            if (empty($jobs)) {
                return rest_ensure_response([
                    'success' => true,
                    'status' => 200,
                    'message' => 'No jobs found.',
                    'data' => [],
                ]);
            }
        
            $response = array_map([self::class, 'prepare_job_response'], $jobs);
        
            return rest_ensure_response([
                'success' => true,
                'status' => 200,
                'message' => 'Successful.',
                'total_jobs' => $total_jobs,
                'data' => $response,
            ]);
        }



        public static function get_companies(WP_REST_Request $request)
        {
            $args = [
                'role' => 'company', // Only fetch users with 'company' role
                'number' => -1,        // Get all
            ];

            $user_query = new WP_User_Query($args);
            $users = $user_query->get_results();

            if (empty($users)) {
                return rest_ensure_response([]);
            }

            $response = [];

            foreach ($users as $user) {
                $user_acf_id = 'user_' . $user->ID;
                $logo = get_field('company_logo', 'user_' . $user->ID);

                $acf_fields = [
                    'company_title' => get_field('company_title', $user_acf_id),
                    'company_website' => get_field('company_website', $user_acf_id),
                    'company_location' => get_field('company_location', $user_acf_id),
                    'company_contact_number' => get_field('company_contact_number', $user_acf_id),
                    'company_email' => get_field('company_email', $user_acf_id),
                    'company_founded_year' => get_field('company_founded_year', $user_acf_id),
                    'company_total_employees' => get_field('company_total_employees', $user_acf_id),
                    'company_revenue_generates' => get_field('company_revenue_generates', $user_acf_id),
                    'about_company' => get_field('about_company', $user_acf_id),
                    'logo' => is_array($logo) ? ($logo['url'] ?? '') : '',
                ];

                $response[] = [
                    'id' => $user->ID,
                    'user_login' => $user->user_login,
                    'user_email' => $user->user_email,
                    'first_name' => get_user_meta($user->ID, 'first_name', true),
                    'last_name' => get_user_meta($user->ID, 'last_name', true),
                    'slug' => $user->user_nicename,
                    'acf_fields' => $acf_fields,
                ];
            }

            return rest_ensure_response($response);
        }


        public static function prepare_job_response($job)
        {
            if (!$job instanceof WP_Post) {
                $job = get_post($job);
            }

            if (empty($job) || $job->post_type !== 'job') {
                return null;
            }

            $company_user_id = $job->post_author;
            $company_data = self::prepare_company_data($company_user_id);

            return [
                'id' => $job->ID,
                'slug' => $job->post_name,
                'title' => get_the_title($job->ID),
                'featured_image' => get_the_post_thumbnail_url($job->ID, 'full') ?: '',
                'job_location' => get_field('job_location', $job->ID) ?: '',
                'job_type' => get_field('job_type', $job->ID) ?: '',
                'salary_range' => get_field('salary_range', $job->ID) ?: '',
                'required_experience' => get_field('required_experience', $job->ID) ?: '',
                'job_description' => get_field('job_description', $job->ID) ?: '',
                'requirements' => get_field('requirements', $job->ID) ?: '',
                'company' => $company_data,
                'created_date' => get_the_date('Y-m-d H:i:s', $job->ID),
            ];
        }

        private static function prepare_company_data($user_id)
        {
            if (!is_numeric($user_id)) {
                return null;
            }

            $user = get_userdata($user_id);

            if ($user && in_array('company', (array) $user->roles)) {
                $logo = get_field('company_logo', 'user_' . $user->ID);
                return [
                    'id' => $user->ID,
                    'name' => $user->display_name,
                    'email' => $user->user_email,
                    'username' => $user->user_login,
                    'slug' => $user->user_nicename,
                    'company_location' => get_field('company_location', 'user_' . $user->ID) ?: '',
                    'logo' => is_array($logo) ? ($logo['url'] ?? '') : '',
                ];
            }

            return null;
        }






        public static function get_single_job(WP_REST_Request $request)
        {
            $id = $request->get_param('id');
            $slug = $request->get_param('slug');

            if ($id) {
                $job = get_post($id);
            } elseif ($slug) {
                $job = get_page_by_path($slug, OBJECT, 'job');
            } else {
                return new WP_Error('invalid_request', 'ID or Slug is required.', array('status' => 400));
            }

            if (empty($job) || $job->post_type !== 'job') {
                return new WP_Error('not_found', 'Job not found.', array('status' => 404));
            }

            $response = self::prepare_job_response($job);

            return rest_ensure_response([
                'success' => true,
                'status' => 200,
                'message' => 'Successful.',
                'data' => $response, // ✅ Now it's properly keyed
            ]);
        }


        public static function create_job(WP_REST_Request $request)
        {
            $title = $request->get_param('title');
            $job_description = $request->get_param('job_description');
            $job_location = $request->get_param('job_location');
            $job_type = $request->get_param('job_type');
            $salary_range = $request->get_param('salary_range');
            $required_experience = $request->get_param('required_experience');
            $requirements = $request->get_param('requirements');
            $user_id = $request->get_param('user_id'); // Expected user ID of job author

            // Validate title
            if (empty($title)) {
                return new WP_Error('missing_title', 'Title is required.', array('status' => 400));
            }

            // Validate company IDs
            if (empty($user_id)) {
                return new WP_Error('missing_company', 'At least one company is required.', array('status' => 400));
            }

            $user = get_userdata($user_id);
            // var_dump($user->ID);
            if (!$user) {
                return new WP_Error('invalid_user', 'Author user does not exist.', ['status' => 400]);
            }

            // Optional: Restrict allowed roles
            if (!in_array('company', $user->roles) && !in_array('administrator', $user->roles)) {
                return new WP_Error('unauthorized_role', 'Only company or admin users can create jobs.', ['status' => 403]);
            }

            // Create the job post
            $post_id = wp_insert_post([
                'post_type' => 'job',
                'post_title' => sanitize_text_field($title),
                'post_status' => 'publish',
                'post_author' => $user->ID,
            ]);

            if (is_wp_error($post_id)) {
                return $post_id;
            }

            // Update ACF fields
            update_field('job_location', sanitize_text_field($job_location ?? ''), $post_id);
            update_field('job_type', sanitize_text_field($job_type ?? ''), $post_id);
            update_field('salary_range', sanitize_text_field($salary_range ?? ''), $post_id);
            update_field('job_description', sanitize_text_field($job_description ?? ''), $post_id);
            update_field('required_experience', sanitize_text_field($required_experience ?? ''), $post_id);
            update_field('requirements', sanitize_textarea_field($requirements ?? ''), $post_id);


            $slug = get_post_field('post_name', $post_id);

            return rest_ensure_response([
                'success' => true,
                'id' => $post_id,
                'user_id' => $user->ID,
                'slug' => $slug,
                'message' => 'Create successfully.',
            ]);
        }


        public static function get_single_company(WP_REST_Request $request)
        {
            $user_id = $request->get_param('user_id');

            if (empty($user_id) || !is_numeric($user_id)) {
                return new WP_Error('invalid_user_id', 'Invalid or missing user ID.', ['status' => 400]);
            }

            $user = get_user_by('id', $user_id);

            if (!$user || !in_array('company', $user->roles)) {
                return new WP_Error('not_company', 'User not found or not a company.', ['status' => 404]);
            }

            $user_acf_id = 'user_' . $user->ID;
            $logo = get_field('company_logo', 'user_' . $user->ID);

            $acf_fields = [
                'company_title' => get_field('company_title', $user_acf_id),
                'company_website' => get_field('company_website', $user_acf_id),
                'company_location' => get_field('company_location', $user_acf_id),
                'company_contact_number' => get_field('company_contact_number', $user_acf_id),
                'company_email' => get_field('company_email', $user_acf_id),
                'company_founded_year' => get_field('company_founded_year', $user_acf_id),
                'company_total_employees' => get_field('company_total_employees', $user_acf_id),
                'company_revenue_generates' => get_field('company_revenue_generates', $user_acf_id),
                'about_company' => get_field('about_company', $user_acf_id),
                'logo' => is_array($logo) ? ($logo['url'] ?? '') : '',
            ];

            $response = [
                'id' => $user->ID,
                'user_login' => $user->user_login,
                'user_email' => $user->user_email,
                'first_name' => get_user_meta($user->ID, 'first_name', true),
                'last_name' => get_user_meta($user->ID, 'last_name', true),
                'slug' => $user->user_nicename,
                'acf_fields' => $acf_fields,
            ];

            return rest_ensure_response($response);
        }



        public static function update_job(WP_REST_Request $request)
        {
            // Get parameters from the request
            $id = $request->get_param('id');
            $title = $request->get_param('title');
            $job_description = $request->get_param('job_description');
            $job_location = $request->get_param('job_location');
            $job_type = $request->get_param('job_type');
            $salary_range = $request->get_param('salary_range');
            $required_experience = $request->get_param('required_experience');
            $requirements = $request->get_param('requirements');
            $user_id = $request->get_param('user_id'); // Expected user ID of job author


            // Get the existing job post by ID
            $job = get_post($id);
            if (empty($job) || $job->post_type !== 'job') {
                return new WP_Error('not_found', 'Job not found.', array('status' => 404));
            }

            // Check if the current user is the author or has administrator capability
            $current_user_id = get_current_user_id();
            if ($job->post_author != $current_user_id && !current_user_can('administrator')) {
                return new WP_Error('unauthorized', 'You are not allowed to update this job.', array('status' => 403));
            }

            $user = get_userdata($user_id);
            if (!$user) {
                return new WP_Error('invalid_user', 'Author user does not exist.', ['status' => 400]);
            }

            if ($job->post_author != $user->ID && !current_user_can('administrator')) {
                return new WP_Error('unauthorized', 'You are not allowed to update this job.', array('status' => 403));
            }

            // Update the job post
            wp_update_post([
                'ID' => $id,
                'post_title' => sanitize_text_field($title),
            ]);

            // Update ACF fields
            update_field('job_location', sanitize_text_field($job_location ?? ''), $id);
            update_field('job_type', sanitize_text_field($job_type ?? ''), $id);
            update_field('salary_range', sanitize_text_field($salary_range ?? ''), $id);
            update_field('job_description', sanitize_text_field($job_description ?? ''), $id);
            update_field('required_experience', sanitize_text_field($required_experience ?? ''), $id);
            update_field('requirements', sanitize_textarea_field($requirements ?? ''), $id);

            return rest_ensure_response([
                'success' => true,
                'id' => $id,
                'message' => 'Update successfully.',
            ]);
        }



        public static function delete_job(WP_REST_Request $request)
        {
            $id = $request->get_param('id');

            if (empty($id)) {
                return new WP_Error('missing_id', 'Job ID is required.', array('status' => 400));
            }

            $job = get_post($id);
            if (empty($job) || $job->post_type !== 'job') {
                return new WP_Error('not_found', 'Job not found.', array('status' => 404));
            }

            // Delete the job post
            wp_delete_post($id, true); // true means force delete

            return rest_ensure_response([
                'success' => true,
                'id' => $id,
                'message' => 'Delete successfully.',
            ]);
        }



        // register and login function with token genrated 
        // ✅ Generate Token

        // Generate JWT Token using the defined secret key from wp-config.php
        public static function jobportalapi_generate_token($user_id)
        {
            $issued_at = time();
            $expiration = $issued_at + WEEK_IN_SECONDS;  // Token expires in 1 week

            $payload = [
                'iat' => $issued_at,  // Issued at time
                'exp' => $expiration, // Expiration time
                'user_id' => $user_id, // User ID
            ];

            $header = ['alg' => 'HS256', 'typ' => 'JWT']; // JWT Header
            $base64UrlHeader = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=');
            $base64UrlPayload = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');
            $signature = hash_hmac('sha256', "$base64UrlHeader.$base64UrlPayload", JWT_AUTH_SECRET_KEY, true); // Using wp-config.php constant
            $base64UrlSignature = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

            return "$base64UrlHeader.$base64UrlPayload.$base64UrlSignature";  // Return the JWT token
        }

        public static function jobportalapi_validate_token($token)
        {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return false;
            }

            [$header, $payload, $signature] = $parts;
            $expected_sig = rtrim(strtr(base64_encode(
                hash_hmac('sha256', "$header.$payload", JWT_AUTH_SECRET_KEY, true) // Using wp-config.php constant
            ), '+/', '-_'), '=');

            if (!hash_equals($signature, $expected_sig)) {
                return false;
            }

            $payload_data = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
            if (!isset($payload_data['exp']) || time() > $payload_data['exp']) {
                return false;  // Token has expired
            }

            // Check if user exists
            if (!get_user_by('ID', $payload_data['user_id'])) {
                return false;
            }

            return $payload_data;  // Return payload data if valid
        }


        public static function jobportalapi_register_user(WP_REST_Request $request)
        {
            // Add CORS headers
            header("Access-Control-Allow-Origin: https://jobportal.arshadwpdev.com");
                        // header("Access-Control-Allow-Origin: http://localhost:5173");
            header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
            header("Access-Control-Allow-Headers: Content-Type, Authorization");
            header("Access-Control-Allow-Credentials: true");

            // Handle preflight OPTIONS request
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                status_header(200);
                exit();
            }
            $username = sanitize_user($request->get_param('username'));
            $email = sanitize_email($request->get_param('email'));
            $password = $request->get_param('password');
            $role = sanitize_text_field($request->get_param('role'));

            // Get company related fields
            $company_name = sanitize_text_field($request->get_param('company_name') ?? '');
            $company_website = esc_url_raw($request->get_param('company_website') ?? '');
            $company_location = sanitize_text_field($request->get_param('company_location') ?? '');
            $company_contact_number = sanitize_text_field($request->get_param('company_contact_number') ?? '');
            $company_email = sanitize_email($request->get_param('company_email') ?? $email);
            $company_founded_year = sanitize_text_field($request->get_param('company_founded_year') ?? '');
            $company_total_employees = sanitize_text_field($request->get_param('company_total_employees') ?? '');
            $company_revenue_generates = sanitize_text_field($request->get_param('company_revenue_generates') ?? '');
            $about_company = sanitize_textarea_field($request->get_param('about_company') ?? '');
            $featured_image_id = $request->get_param('featured_image_id');

            // Validate required fields
            if (empty($username) || empty($email) || empty($password)) {
                return new WP_Error('missing_fields', 'Username, email and password are required.', ['status' => 400]);
            }

            // Check if the username or email already exists
            if (username_exists($username) || email_exists($email)) {
                return new WP_Error('user_exists', 'Username or Email already exists.', ['status' => 400]);
            }

            // Set default role if not provided or invalid
            if (empty($role) || !in_array($role, ['employee', 'company', 'administrator'])) {
                $role = 'employee'; // Default role
            }

            // If role is company, validate required company fields
            if ($role === 'company') {
                if (empty($company_name) || empty($company_location) || empty($about_company) || empty($featured_image_id)) {
                    return new WP_Error(
                        'missing_company_fields',
                        'Company Name, Company location, about company and Company Logo are required for company role.',
                        ['status' => 400]
                    );
                }
            }

            // Create the user
            $user_id = wp_create_user($username, $password, $email);
            if (is_wp_error($user_id)) {
                return $user_id;  // Return error if user creation fails
            }

            // Assign the role to the user
            $user = new WP_User($user_id);
            $user->set_role($role);

            // If the role is 'company', save company information to user meta
            if ($role === 'company') {

                // If you're using ACF for user fields, you can also use update_field
                // This assumes you've created these fields for the user using ACF
                if (function_exists('update_field')) {
                    update_field('company_title', $company_name, 'user_' . $user_id);
                    update_field('company_website', $company_website, 'user_' . $user_id);
                    update_field('company_location', $company_location, 'user_' . $user_id);
                    update_field('company_contact_number', $company_contact_number, 'user_' . $user_id);
                    update_field('company_email', $company_email, 'user_' . $user_id);
                    update_field('company_founded_year', $company_founded_year, 'user_' . $user_id);
                    update_field('company_total_employees', $company_total_employees, 'user_' . $user_id);
                    update_field('company_revenue_generates', $company_revenue_generates, 'user_' . $user_id);
                    update_field('about_company', $about_company, 'user_' . $user_id);

                    // Save featured image if provided
                    if (!empty($featured_image_id) && get_post_type($featured_image_id) === 'attachment') {
                        update_field('company_logo', $featured_image_id, 'user_' . $user_id);
                    }
                }
            }

            // Generate token
            $token = self::jobportalapi_generate_token($user_id);

            setcookie(
                'jobportal_token',
                $token,
                [
                    'expires' => time() + WEEK_IN_SECONDS,
                    'path' => '/',
                    'domain' => '', // Leave empty to use current domain
                    'secure' => true,
                    'httponly' => true, // Change to true for security
                    'samesite' => 'None' // This should be correct for cross-site requests
                ]
            );

            $response = [
                'success' => true,
                'user_id' => $user_id,
                'username' => $username,
                'email' => $email,
                'role' => $role,
                'token' => $token,
                'message' => 'Create User successfully.',
            ];

            // Add company information to the response if applicable
            if ($role === 'company') {
                $response['company_details'] = [
                    'company_name' => $company_name,
                    'company_website' => $company_website,
                    'company_location' => $company_location,
                    'company_email' => $company_email
                ];
            }

            return rest_ensure_response($response);
        }

        public static function jobportalapi_login_user(WP_REST_Request $request)
        {
            $username = $request->get_param('username');
            $password = $request->get_param('password');

            // Check if the username field is actually an email
            if (is_email($username)) {
                $user = get_user_by('email', $username);
                if ($user) {
                    $username = $user->user_login;
                }
            }

            // Authenticate the user
            $user = wp_authenticate($username, $password);
            if (is_wp_error($user)) {
                return new WP_Error('invalid_login', 'Invalid username or password.', ['status' => 403]);
            }

            // Generate a JWT token for the authenticated user
            $token = self::jobportalapi_generate_token($user->ID);

            setcookie(
                'jobportal_token',
                $token,
                [
                    'expires' => time() + WEEK_IN_SECONDS,
                    'path' => '/',
                    'domain' => '', // Leave empty to use current domain
                    // 'secure' => is_ssl(),
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None', // or 'Strict' based on your frontend
                ]
            );

            // Get user's role
            $user_roles = $user->roles;
            $primary_role = !empty($user_roles) ? $user_roles[0] : 'subscriber';

            return rest_ensure_response([
                'success' => true,
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'role' => $primary_role,
                'token' => $token,
                'message' => 'Login successfully.',
            ]);
        }


        public static function jobportalapi_validate_user_session(WP_REST_Request $request)
        {
            // Allow requests from your frontend domain
            header("Access-Control-Allow-Origin: https://jobportal.arshadwpdev.com");
            // header("Access-Control-Allow-Origin: http://localhost:5173");
            header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
            header("Access-Control-Allow-Headers: Content-Type, Authorization");
            header("Access-Control-Allow-Credentials: true");

            // Handle preflight OPTIONS request
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                status_header(200);
                exit();
            }

            // Try reading the JWT from the HTTP-only cookie
            $token = $_COOKIE['jobportal_token'] ?? null;

            if (!$token) {
                return new WP_Error('no_token', 'User not authenticated.', ['status' => 403, 'cookies' => $_COOKIE]);
            }

            $validation = self::jobportalapi_validate_token($token);
            if (!$validation) {
                return new WP_Error('invalid_token', 'Token is invalid or expired.', ['status' => 403]);
            }

            $user = get_user_by('ID', $validation['user_id']);

            return rest_ensure_response([
                'success' => true,
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'role' => $user->roles[0] ?? 'subscriber',
                'message' => 'Session validated successfully.',
                'cookie' => $_COOKIE
            ]);
        }

        public static function user_logout()
        {
            setcookie(
                'jobportal_token',
                '',
                [
                    'expires' => time() - WEEK_IN_SECONDS,
                    'path' => '/',
                    'domain' => '', // Leave empty to use current domain
                    // 'secure' => is_ssl(),
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None', // or 'Strict' based on your frontend
                ]
            );
            return rest_ensure_response([
                'success' => true,
                'message' => 'Logged out successfully.',
                'cookie' => $_COOKIE
            ]);
        }


        //update user 
        public static function jobportalapi_update_user(WP_REST_Request $request)
        {
            // Authenticate user
            $current_user_id = get_current_user_id();

            if (!$current_user_id) {
                return new WP_Error('unauthorized', 'User not logged in.', ['status' => 401]);
            }

            // Target user to update (default: current user)
            $target_user_id = $request->get_param('user_id') ?: $current_user_id;

            // Get target user object
            $target_user = get_userdata($target_user_id);
            if (!$target_user) {
                return new WP_Error('invalid_user', 'Target user not found.', ['status' => 404]);
            }

            // Check if current user is allowed to update
            $is_admin = current_user_can('administrator');
            if ($current_user_id !== (int) $target_user_id && !$is_admin) {
                return new WP_Error('forbidden', 'You are not allowed to update this user.', ['status' => 403]);
            }

            // Check if the target user has 'company' role
            if (!in_array('company', $target_user->roles) && !$is_admin) {
                return new WP_Error('forbidden', 'Target user does not have the required role.', ['status' => 403]);
            }

            // Fetch fields to update
            $company_name = sanitize_text_field($request->get_param('company_name'));
            $company_website = esc_url_raw($request->get_param('company_website'));
            $company_location = sanitize_text_field($request->get_param('company_location'));
            $company_contact_number = sanitize_text_field($request->get_param('company_contact_number'));
            $company_email = sanitize_email($request->get_param('company_email'));
            $company_founded_year = sanitize_text_field($request->get_param('company_founded_year'));
            $company_total_employees = sanitize_text_field($request->get_param('company_total_employees'));
            $company_revenue_generates = sanitize_text_field($request->get_param('company_revenue_generates'));
            $about_company = sanitize_textarea_field($request->get_param('about_company'));
            $featured_image_id = $request->get_param('featured_image_id');

            $fields = [
                'company_title' => $company_name,
                'company_website' => $company_website,
                'company_location' => $company_location,
                'company_contact_number' => $company_contact_number,
                'company_email' => $company_email,
                'company_founded_year' => $company_founded_year,
                'company_total_employees' => $company_total_employees,
                'company_revenue_generates' => $company_revenue_generates,
                'about_company' => $about_company,
            ];

            // Update ACF fields
            if (function_exists('update_field')) {
                $user_acf_id = 'user_' . $target_user_id;

                foreach ($fields as $field_key => $field_value) {
                    if (!empty($field_value)) {
                        update_field($field_key, $field_value, $user_acf_id);
                    }
                }

                if (!empty($featured_image_id) && get_post_type($featured_image_id) === 'attachment') {
                    update_field('company_logo', $featured_image_id, $user_acf_id);
                }
            }

            // Update native WP fields
            if (!empty($company_name)) {
                wp_update_user([
                    'ID' => $target_user_id,
                    'first_name' => $company_name,
                ]);
            }

            return rest_ensure_response([
                'success' => true,
                'message' => 'Profile updated successfully.',
            ]);
        }


        public static function jobportalapi_get_user(WP_REST_Request $request)
        {
            // Authenticate user
            $current_user_id = get_current_user_id();

            if (!$current_user_id) {
                return new WP_Error('unauthorized', 'User not logged in.', ['status' => 401]);
            }

            // Get WordPress user data
            $user = get_userdata($current_user_id);

            if (!$user) {
                return new WP_Error('invalid_user', 'Invalid user.', ['status' => 400]);
            }

            // Get ACF fields
            $user_acf_id = 'user_' . $current_user_id;
            $logo = get_field('company_logo', 'user_' . $current_user_id);

            $acf_fields = [
                'company_title' => get_field('company_title', $user_acf_id),
                'company_website' => get_field('company_website', $user_acf_id),
                'company_location' => get_field('company_location', $user_acf_id),
                'company_contact_number' => get_field('company_contact_number', $user_acf_id),
                'company_email' => get_field('company_email', $user_acf_id),
                'company_founded_year' => get_field('company_founded_year', $user_acf_id),
                'company_total_employees' => get_field('company_total_employees', $user_acf_id),
                'company_revenue_generates' => get_field('company_revenue_generates', $user_acf_id),
                'about_company' => get_field('about_company', $user_acf_id),
                'logo' => is_array($logo) ? ($logo['url'] ?? '') : '',
            ];

            // Combine WordPress + ACF data
            $user_data = [
                'id' => $user->ID,
                'user_login' => $user->user_login,
                'user_email' => $user->user_email,
                'first_name' => get_user_meta($user->ID, 'first_name', true),
                'last_name' => get_user_meta($user->ID, 'last_name', true),
                'slug' => $user->user_nicename,
                'acf_fields' => $acf_fields,
            ];

            return rest_ensure_response([
                'success' => true,
                'data' => $user_data,
            ]);
        }


        //get all users with acf fields 
        public static function jobportalapi_get_all_users(WP_REST_Request $request)
        {
            // Optional: You can add role filter if you want
            $args = [
                'role__in' => ['employee', 'administrator', 'company'], // Add roles you want (or remove this line for all roles)
                'number' => -1, // Get all users
            ];

            $user_query = new WP_User_Query($args);
            $users = $user_query->get_results();
            // var_dump($users);

            if (empty($users)) {
                return rest_ensure_response([
                    'success' => true,
                    'data' => [],
                    'message' => 'No users found.',
                ]);
            }

            $user_list = [];

            foreach ($users as $user) {
                // Check if the user has the 'company' role
                if (in_array('company', $user->roles)) {
                    $user_acf_id = 'user_' . $user->ID;
                    $logo = get_field('company_logo', 'user_' . $user->ID);

                    $acf_fields = [
                        'company_title' => get_field('company_title', $user_acf_id),
                        'company_website' => get_field('company_website', $user_acf_id),
                        'company_location' => get_field('company_location', $user_acf_id),
                        'company_contact_number' => get_field('company_contact_number', $user_acf_id),
                        'company_email' => get_field('company_email', $user_acf_id),
                        'company_founded_year' => get_field('company_founded_year', $user_acf_id),
                        'company_total_employees' => get_field('company_total_employees', $user_acf_id),
                        'company_revenue_generates' => get_field('company_revenue_generates', $user_acf_id),
                        'about_company' => get_field('about_company', $user_acf_id),
                        'logo' => is_array($logo) ? ($logo['url'] ?? '') : '',
                    ];

                    // Get user's role
                    $user_roles = $user->roles;
                    $primary_role = !empty($user_roles) ? $user_roles[0] : 'subscriber';

                    $user_list[] = [
                        'id' => $user->ID,
                        'role' => $primary_role,
                        'user_login' => $user->user_login,
                        'user_email' => $user->user_email,
                        'first_name' => get_user_meta($user->ID, 'first_name', true),
                        'last_name' => get_user_meta($user->ID, 'last_name', true),
                        'slug' => $user->user_nicename,
                        'acf_fields' => $acf_fields,
                    ];
                } else {

                    $user_roles = $user->roles;
                    $primary_role = !empty($user_roles) ? $user_roles[0] : 'subscriber';
                    // If user does not have the 'company' role, just show basic info
                    $user_list[] = [
                        'id' => $user->ID,
                        'role' => $primary_role,
                        'user_login' => $user->user_login,
                        'user_email' => $user->user_email,
                        'first_name' => get_user_meta($user->ID, 'first_name', true),
                        'last_name' => get_user_meta($user->ID, 'last_name', true),
                        'slug' => $user->user_nicename,
                        'acf_fields' => null, // No ACF fields for non-company users
                    ];
                }
            }

            return rest_ensure_response([
                'success' => true,
                'data' => $user_list,
            ]);
        }




        // apply job
        public static function apply_job(WP_REST_Request $request)
        {
            $user_id = get_current_user_id();
            $job_id = absint($request->get_param('job_id'));

            if (!$user_id) {
                return new WP_Error('not_logged_in', 'You must be logged in to apply for a job.', ['status' => 401]);
            }

            if (empty($job_id)) {
                return new WP_Error('missing_job_id', 'Job ID is required.', ['status' => 400]);
            }

            $job = get_post($job_id);
            if (empty($job) || $job->post_type !== 'job') {
                return new WP_Error('invalid_job_id', 'Invalid Job ID.', ['status' => 400]);
            }

            // Check if the user has already applied for this job
            $existing_application = get_posts([
                'post_type' => 'application',
                'meta_query' => [
                    'relation' => 'AND',
                    [
                        'key' => 'applicant_user_id', // ACF field key
                        'value' => $user_id,
                    ],
                    [
                        'key' => 'applied_job_id', // ACF field key
                        'value' => $job_id,
                    ],
                ],
                'fields' => 'ids',
                'numberposts' => 1,
            ]);

            if (!empty($existing_application)) {
                return new WP_Error('already_applied', 'You have already applied for this job.', ['status' => 409]);
            }

            // Sanitize and collect application data from the request
            $applicant_name = sanitize_text_field($request->get_param('applicant_name'));
            $applicant_email = sanitize_email($request->get_param('applicant_email'));
            $applicant_phone = sanitize_text_field($request->get_param('applicant_phone'));
            $applicant_gender = sanitize_text_field($request->get_param('applicant_gender'));
            $applicant_experience = sanitize_text_field($request->get_param('applicant_experience'));
            $location = sanitize_text_field($request->get_param('location'));
            $current_salary = sanitize_text_field($request->get_param('current_salary'));
            $expected_salary = sanitize_text_field($request->get_param('expected_salary'));
            $cover_letter = sanitize_textarea_field($request->get_param('cover_letter'));

            // Create the application post
            $application_post_id = wp_insert_post([
                'post_type' => 'application',
                'post_title' => sprintf('%s - Application for %s', $applicant_name, get_the_title($job_id)),
                'post_status' => 'publish',
            ]);

            if ($application_post_id) {
                // Store application details using ACF functions
                update_field('applicant_name', $applicant_name, $application_post_id);
                update_field('applicant_email', $applicant_email, $application_post_id);
                update_field('applicant_phone', $applicant_phone, $application_post_id);
                update_field('applicant_gender', $applicant_gender, $application_post_id);
                update_field('applicant_experience', $applicant_experience, $application_post_id);
                update_field('location', $location, $application_post_id);
                update_field('current_salary', $current_salary, $application_post_id);
                update_field('expected_salary', $expected_salary, $application_post_id);
                update_field('cover_letter', $cover_letter, $application_post_id);
                update_field('applied_job_id', $job_id, $application_post_id);
                update_field('applicant_user_id', $user_id, $application_post_id);
                update_field('apply_date', current_time('Y-m-d H:i:s'), $application_post_id); // ACF expects this format

                // Update user meta to track applied job IDs
                $applications = get_user_meta($user_id, 'job_applications', true);
                $applications = is_array($applications) ? $applications : [];
                update_user_meta($user_id, 'job_applications', array_unique(array_merge($applications, [$job_id])));

                return rest_ensure_response([
                    'success' => true,
                    'message' => 'Application submitted successfully.',
                ]);
            } else {
                return new WP_Error('application_failed', 'Failed to submit application.', ['status' => 500]);
            }
        }



        // get all applications 
        public static function get_user_applications(WP_REST_Request $request)
        {
            $user_id = get_current_user_id();

            if (!$user_id) {
                return new WP_Error('not_logged_in', 'You must be logged in to view your applications.', ['status' => 401]);
            }

            $applications_posts = get_posts([
                'post_type' => 'application',
                'meta_query' => [
                    [
                        'key' => 'applicant_user_id', // ACF field key
                        'value' => $user_id,
                    ],
                ],
                'numberposts' => -1,
            ]);

            $applications = [];

            foreach ($applications_posts as $application_post) {
                $job_id = get_field('applied_job_id', $application_post->ID); // Use ACF function
                $job = get_post($job_id);

                if ($job && $job->post_type === 'job') {
                    $applications[] = [
                        'application_id' => $application_post->ID,
                        'job_id' => $job->ID,
                        'job_title' => get_the_title($job->ID),
                        'status' => get_field('application_status', $application_post->ID) ?: 'pending',
                        'job_slug' => $job->post_name,
                        'apply_date' => get_field('apply_date', $application_post->ID), // Use ACF function
                        'application_details' => [
                            'applicant_name' => get_field('applicant_name', $application_post->ID), // Use ACF function
                            'applicant_email' => get_field('applicant_email', $application_post->ID), // Use ACF function
                            'applicant_phone' => get_field('applicant_phone', $application_post->ID),
                            'applicant_gender' => get_field('applicant_gender', $application_post->ID),
                            'applicant_experience' => get_field('applicant_experience', $application_post->ID),
                            'location' => get_field('location', $application_post->ID),
                            'current_salary' => get_field('current_salary', $application_post->ID),
                            'expected_salary' => get_field('expected_salary', $application_post->ID),
                            'cover_letter' => get_field('cover_letter', $application_post->ID),
                            // Add other ACF fields you want to include
                        ],
                        'status_history' => get_field('status_history', $application_post->ID) ?: []
                    ];
                }
            }

            return rest_ensure_response($applications);
        }






        /**
         * Update application status
         * 
         * @param WP_REST_Request $request
         * @return WP_REST_Response
         */
        public static function update_application_status(WP_REST_Request $request)
        {
            $application_id = absint($request->get_param('application_id'));
            $new_status = sanitize_text_field($request->get_param('status'));

            // Validate application exists
            $application = get_post($application_id);
            if (empty($application) || $application->post_type !== 'application') {
                return new WP_Error('invalid_application', 'Application not found.', ['status' => 404]);
            }

            // Get the job ID and job author
            $job_id = get_field('applied_job_id', $application_id);
            $job = get_post($job_id);

            if (empty($job)) {
                return new WP_Error('invalid_job', 'Associated job not found.', ['status' => 404]);
            }

            // Check if current user is the job owner/author or admin
            $current_user_id = get_current_user_id();
            if ($job->post_author != $current_user_id && !current_user_can('administrator')) {
                return new WP_Error('unauthorized', 'You are not authorized to update this application.', ['status' => 403]);
            }

            // Valid application statuses
            $valid_statuses = ['pending', 'reviewed', 'shortlisted', 'interviewed', 'offered', 'hired', 'rejected'];

            if (!in_array($new_status, $valid_statuses)) {
                return new WP_Error('invalid_status', 'Invalid application status.', ['status' => 400]);
            }

            // Update the application status
            update_field('application_status', $new_status, $application_id);

            // Add status change to application history
            $history = get_field('status_history', $application_id) ?: [];
            $history[] = [
                'status' => $new_status,
                'changed_by' => $current_user_id,
                'changed_at' => current_time('mysql'),
                'notes' => sanitize_textarea_field($request->get_param('notes') ?: '')
            ];
            update_field('status_history', $history, $application_id);

            // Notify the applicant of the status change
            self::send_application_status_notification($application_id, $new_status);

            return rest_ensure_response([
                'success' => true,
                'message' => 'Application status updated successfully.',
                'new_status' => $new_status
            ]);
        }

        /**
         * Get applications for a specific job
         * 
         * @param WP_REST_Request $request
         * @return WP_REST_Response
         */
        public static function get_job_applications(WP_REST_Request $request)
        {
            $job_id = absint($request->get_param('job_id'));

            // Validate job exists
            $job = get_post($job_id);
            if (empty($job) || $job->post_type !== 'job') {
                return new WP_Error('invalid_job', 'Job not found.', ['status' => 404]);
            }

            // Check if current user is the job owner/author or admin
            $current_user_id = get_current_user_id();
            if ($job->post_author != $current_user_id && !current_user_can('administrator')) {
                return new WP_Error('unauthorized', 'You are not authorized to view applications for this job.', ['status' => 403]);
            }

            // Get all applications for this job
            $applications_posts = get_posts([
                'post_type' => 'application',
                'meta_query' => [
                    [
                        'key' => 'applied_job_id',
                        'value' => $job_id,
                    ],
                ],
                'numberposts' => -1,
            ]);

            $applications = [];

            foreach ($applications_posts as $application_post) {
                $applicant_id = get_field('applicant_user_id', $application_post->ID);
                $applicant = get_userdata($applicant_id);

                $applications[] = [
                    'application_id' => $application_post->ID,
                    'job_id' => $job_id,
                    'applicant_id' => $applicant_id,
                    'applicant_username' => $applicant ? $applicant->user_login : 'Unknown',
                    'status' => get_field('application_status', $application_post->ID) ?: 'pending',
                    'apply_date' => get_field('apply_date', $application_post->ID),
                    'application_details' => [
                        'applicant_name' => get_field('applicant_name', $application_post->ID),
                        'applicant_email' => get_field('applicant_email', $application_post->ID),
                        'applicant_phone' => get_field('applicant_phone', $application_post->ID),
                        'applicant_gender' => get_field('applicant_gender', $application_post->ID),
                        'applicant_experience' => get_field('applicant_experience', $application_post->ID),
                        'location' => get_field('location', $application_post->ID),
                        'current_salary' => get_field('current_salary', $application_post->ID),
                        'expected_salary' => get_field('expected_salary', $application_post->ID),
                        'cover_letter' => get_field('cover_letter', $application_post->ID),
                    ],
                    'status_history' => get_field('status_history', $application_post->ID) ?: []
                ];
            }

            return rest_ensure_response([
                'success' => true,
                'data' => $applications
            ]);
        }

        /**
         * Send notification when application status changes
         * 
         * @param int $application_id
         * @param string $new_status
         * @return bool
         */
        private static function send_application_status_notification($application_id, $new_status)
        {
            $application = get_post($application_id);
            if (!$application) {
                return false;
            }

            $applicant_email = get_field('applicant_email', $application_id);
            $applicant_name = get_field('applicant_name', $application_id);
            $job_id = get_field('applied_job_id', $application_id);
            $job_title = get_the_title($job_id);

            $subject = "Update on Your Application for {$job_title}";

            // Format status message
            $status_messages = [
                'pending' => 'Your application is currently pending review.',
                'reviewed' => 'Your application has been reviewed.',
                'shortlisted' => 'Congratulations! Your application has been shortlisted.',
                'interviewed' => 'Thank you for your interview. We\'re processing your application.',
                'offered' => 'Congratulations! You have received a job offer.',
                'hired' => 'Congratulations! You have been hired for this position.',
                'rejected' => 'Thank you for your interest. We have decided to pursue other candidates at this time.'
            ];

            $status_message = isset($status_messages[$new_status]) ? $status_messages[$new_status] : 'Your application status has been updated.';

            $message = "Dear {$applicant_name},\n\n";
            $message .= "Your application for the position of {$job_title} has been updated.\n\n";
            $message .= "Current Status: " . ucfirst($new_status) . "\n\n";
            $message .= $status_message . "\n\n";
            $message .= "Thank you for your interest in our company.\n\n";
            $message .= "Best regards,\n";
            $message .= get_bloginfo('name');

            $headers = ['Content-Type: text/plain; charset=UTF-8'];

            return wp_mail($applicant_email, $subject, $message, $headers);
        }

        /**
         * Update an existing application
         * 
         * @param WP_REST_Request $request
         * @return WP_REST_Response
         */
        public static function update_application(WP_REST_Request $request)
        {
            $user_id = get_current_user_id();
            $application_id = absint($request->get_param('application_id'));

            if (!$user_id) {
                return new WP_Error('not_logged_in', 'You must be logged in to update your application.', ['status' => 401]);
            }

            // Check if application exists and belongs to current user
            $application = get_post($application_id);
            if (empty($application) || $application->post_type !== 'application') {
                return new WP_Error('invalid_application', 'Application not found.', ['status' => 404]);
            }

            $applicant_user_id = get_field('applicant_user_id', $application_id);
            if ($applicant_user_id != $user_id) {
                return new WP_Error('unauthorized', 'You are not authorized to update this application.', ['status' => 403]);
            }

            // Get job status to check if application can be updated
            $job_id = get_field('applied_job_id', $application_id);
            $application_status = get_field('application_status', $application_id) ?: 'pending';

            // Don't allow updates if already in later stages
            $non_editable_statuses = ['interviewed', 'offered', 'hired', 'rejected'];
            if (in_array($application_status, $non_editable_statuses)) {
                return new WP_Error('application_locked', 'This application cannot be edited in its current status.', ['status' => 403]);
            }

            // Sanitize and collect updated application data
            $fields_to_update = [
                'applicant_name' => sanitize_text_field($request->get_param('applicant_name')),
                'applicant_email' => sanitize_email($request->get_param('applicant_email')),
                'applicant_phone' => sanitize_text_field($request->get_param('applicant_phone')),
                'applicant_gender' => sanitize_text_field($request->get_param('applicant_gender')),
                'applicant_experience' => sanitize_text_field($request->get_param('applicant_experience')),
                'location' => sanitize_text_field($request->get_param('location')),
                'current_salary' => sanitize_text_field($request->get_param('current_salary')),
                'expected_salary' => sanitize_text_field($request->get_param('expected_salary')),
                'cover_letter' => sanitize_textarea_field($request->get_param('cover_letter')),
            ];

            // Update only provided fields
            foreach ($fields_to_update as $field => $value) {
                if (!empty($value)) {
                    update_field($field, $value, $application_id);
                }
            }

            // Add edit history
            $edit_history = get_field('edit_history', $application_id) ?: [];
            $edit_history[] = [
                'edit_by' => $user_id,
                'edit_at' => current_time('mysql'),
                'fields_updated' => implode(', ', array_keys($fields_to_update)) // convert to comma-separated string
            ];
            update_field('edit_history', $edit_history, $application_id);

            // Maybe update application title to reflect any name changes
            if (!empty($fields_to_update['applicant_name'])) {
                wp_update_post([
                    'ID' => $application_id,
                    'post_title' => sprintf('%s - Application for %s', $fields_to_update['applicant_name'], get_the_title($job_id)),
                ]);
            }

            return rest_ensure_response([
                'success' => true,
                'message' => 'Application updated successfully.'
            ]);
        }

        /**
         * Withdraw an application
         * 
         * @param WP_REST_Request $request
         * @return WP_REST_Response
         */
        public static function withdraw_application(WP_REST_Request $request)
        {
            $user_id = get_current_user_id();
            $application_id = absint($request->get_param('application_id'));

            if (!$user_id) {
                return new WP_Error('not_logged_in', 'You must be logged in to withdraw your application.', ['status' => 401]);
            }

            // Check if application exists and belongs to current user
            $application = get_post($application_id);
            if (empty($application) || $application->post_type !== 'application') {
                return new WP_Error('invalid_application', 'Application not found.', ['status' => 404]);
            }

            $applicant_user_id = get_field('applicant_user_id', $application_id);
            if ($applicant_user_id != $user_id) {
                return new WP_Error('unauthorized', 'You are not authorized to withdraw this application.', ['status' => 403]);
            }

            // Update application status to 'withdrawn'
            update_field('application_status', 'withdrawn', $application_id);

            // Add to status history
            $history = get_field('status_history', $application_id) ?: [];
            $history[] = [
                'status' => 'withdrawn',
                'changed_by' => $user_id,
                'changed_at' => current_time('mysql'),
                'notes' => sanitize_textarea_field($request->get_param('withdrawal_reason') ?: 'Application withdrawn by applicant')
            ];
            update_field('status_history', $history, $application_id);

            // Notify employer
            $job_id = get_field('applied_job_id', $application_id);
            $job = get_post($job_id);
            $company_user_id = $job->post_author;
            $company_user = get_userdata($company_user_id);
            $company_email = $company_user ? $company_user->user_email : null;

            if ($company_email) {
                $applicant_name = get_field('applicant_name', $application_id);
                $job_title = get_the_title($job_id);

                $subject = "Application Withdrawn for {$job_title}";
                $message = "Hello,\n\n";
                $message .= "This is to inform you that {$applicant_name} has withdrawn their application for the position of {$job_title}.\n\n";
                if ($request->get_param('withdrawal_reason')) {
                    $message .= "Reason provided: " . sanitize_textarea_field($request->get_param('withdrawal_reason')) . "\n\n";
                }
                $message .= "Best regards,\n";
                $message .= get_bloginfo('name');

                $headers = ['Content-Type: text/plain; charset=UTF-8'];
                wp_mail($company_email, $subject, $message, $headers);
            }

            return rest_ensure_response([
                'success' => true,
                'message' => 'Application withdrawn successfully.'
            ]);
        }

        /**
         * Get application statistics for employers
         * 
         * @param WP_REST_Request $request
         * @return WP_REST_Response
         */
        public static function get_application_statistics(WP_REST_Request $request)
        {
            $current_user_id = get_current_user_id();

            if (!$current_user_id) {
                return new WP_Error('not_logged_in', 'You must be logged in to view statistics.', ['status' => 401]);
            }

            // Make sure user is company or admin
            $user = get_userdata($current_user_id);
            if (!in_array('company', $user->roles) && !in_array('administrator', $user->roles)) {
                return new WP_Error('unauthorized_role', 'Only company or admin users can view these statistics.', ['status' => 403]);
            }

            // Get all jobs posted by this user
            $jobs = get_posts([
                'post_type' => 'job',
                'author' => $current_user_id,
                'numberposts' => -1,
                'fields' => 'ids'
            ]);

            if (empty($jobs)) {
                return rest_ensure_response([
                    'success' => true,
                    'data' => [
                        'total_jobs' => 0,
                        'total_applications' => 0,
                        'applications_by_status' => [],
                        'applications_by_job' => []
                    ]
                ]);
            }

            // Get all applications for these jobs
            $applications = get_posts([
                'post_type' => 'application',
                'meta_query' => [
                    [
                        'key' => 'applied_job_id',
                        'value' => $jobs,
                        'compare' => 'IN'
                    ]
                ],
                'numberposts' => -1
            ]);

            // Prepare statistics
            $total_applications = count($applications);
            $applications_by_status = [];
            $applications_by_job = [];

            // Initialize status counters
            $statuses = ['pending', 'reviewed', 'shortlisted', 'interviewed', 'offered', 'hired', 'rejected', 'withdrawn'];
            foreach ($statuses as $status) {
                $applications_by_status[$status] = 0;
            }

            // Initialize job counters
            foreach ($jobs as $job_id) {
                $applications_by_job[$job_id] = [
                    'job_title' => get_the_title($job_id),
                    'total_applications' => 0,
                    'statuses' => array_fill_keys($statuses, 0)
                ];
            }

            // Count applications
            foreach ($applications as $application) {
                $job_id = get_field('applied_job_id', $application->ID);
                $status = get_field('application_status', $application->ID) ?: 'pending';

                // Count by status
                if (isset($applications_by_status[$status])) {
                    $applications_by_status[$status]++;
                }

                // Count by job
                if (isset($applications_by_job[$job_id])) {
                    $applications_by_job[$job_id]['total_applications']++;
                    if (isset($applications_by_job[$job_id]['statuses'][$status])) {
                        $applications_by_job[$job_id]['statuses'][$status]++;
                    }
                }
            }

            // Sort jobs by application count (highest first)
            uasort($applications_by_job, function ($a, $b) {
                return $b['total_applications'] - $a['total_applications'];
            });

            return rest_ensure_response([
                'success' => true,
                'data' => [
                    'total_jobs' => count($jobs),
                    'total_applications' => $total_applications,
                    'applications_by_status' => $applications_by_status,
                    'applications_by_job' => $applications_by_job
                ]
            ]);
        }

        /**
         * Schedule interview for an application
         * 
         * @param WP_REST_Request $request
         * @return WP_REST_Response
         */
        public static function schedule_interview(WP_REST_Request $request)
        {
            $application_id = absint($request->get_param('application_id'));
            $interview_date = sanitize_text_field($request->get_param('interview_date')); // Expected format: Y-m-d H:i:s
            $interview_type = sanitize_text_field($request->get_param('interview_type')); // in-person, phone, video
            $interview_location = sanitize_text_field($request->get_param('interview_location')); // For in-person or video link
            $interview_notes = sanitize_textarea_field($request->get_param('interview_notes'));

            // Validate application exists
            $application = get_post($application_id);
            if (empty($application) || $application->post_type !== 'application') {
                return new WP_Error('invalid_application', 'Application not found.', ['status' => 404]);
            }

            // Get the job ID and job author
            $job_id = get_field('applied_job_id', $application_id);
            $job = get_post($job_id);

            if (empty($job)) {
                return new WP_Error('invalid_job', 'Associated job not found.', ['status' => 404]);
            }

            // Check if current user is the job owner/author or admin
            $current_user_id = get_current_user_id();
            if ($job->post_author != $current_user_id && !current_user_can('administrator')) {
                return new WP_Error('unauthorized', 'You are not authorized to schedule interviews for this application.', ['status' => 403]);
            }

            // Validate interview date
            if (empty($interview_date) || strtotime($interview_date) === false) {
                return new WP_Error('invalid_date', 'Please provide a valid interview date and time.', ['status' => 400]);
            }

            // Validate interview type
            $valid_types = ['in-person', 'phone', 'video'];
            if (empty($interview_type) || !in_array($interview_type, $valid_types)) {
                return new WP_Error('invalid_type', 'Please provide a valid interview type (in-person, phone, or video).', ['status' => 400]);
            }

            // Create or update interview data
            $interview_data = [
                'date' => $interview_date,
                'type' => $interview_type,
                'location' => $interview_location,
                'notes' => $interview_notes,
                'scheduled_by' => $current_user_id,
                'scheduled_at' => current_time('mysql')

            ];

            // Update the interview data
            update_field('interview_details', $interview_data, $application_id);
            // Update application status to 'interview_scheduled'
            update_field('application_status', 'interview_scheduled', $application_id);

            // Add status change to application history
            $history = get_field('status_history', $application_id) ?: [];
            $history[] = [
                'status' => 'interview_scheduled',
                'changed_by' => $current_user_id,
                'changed_at' => current_time('mysql'),
                'notes' => "Interview scheduled for " . $interview_date
            ];
            update_field('status_history', $history, $application_id);

            // Send notification to applicant
            $applicant_email = get_field('applicant_email', $application_id);
            $applicant_name = get_field('applicant_name', $application_id);
            $job_title = get_the_title($job_id);

            $subject = "Interview Scheduled for {$job_title}";
            $message = "Dear {$applicant_name},\n\n";
            $message .= "We're pleased to invite you for an interview for the position of {$job_title}.\n\n";
            $message .= "Interview Details:\n";
            $message .= "Date and Time: " . $interview_date . "\n";
            $message .= "Type: " . ucfirst($interview_type) . "\n";

            if ($interview_type === 'in-person' && !empty($interview_location)) {
                $message .= "Location: " . $interview_location . "\n\n";
            } elseif ($interview_type === 'video' && !empty($interview_location)) {
                $message .= "Video Link: " . $interview_location . "\n\n";
            }

            if (!empty($interview_notes)) {
                $message .= "Additional Information:\n" . $interview_notes . "\n\n";
            }

            $message .= "Please confirm your availability by replying to this email.\n\n";
            $message .= "Best regards,\n";
            $message .= get_bloginfo('name');

            $headers = ['Content-Type: text/plain; charset=UTF-8'];
            wp_mail($applicant_email, $subject, $message, $headers);

            return rest_ensure_response([
                'success' => true,
                'message' => 'Interview scheduled successfully.'
            ]);
        }
    }
}
