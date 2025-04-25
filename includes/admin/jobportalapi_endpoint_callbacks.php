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
            $jobs = get_posts([
                'post_type' => 'job',
                'post_status' => 'publish',
                'numberposts' => -1,
            ]);

            if (empty($jobs)) {
                return rest_ensure_response([]);
            }

            $response = [];

            foreach ($jobs as $job) {
                $company_field = get_field('company', $job->ID);
                $company_data = self::prepare_company_data($company_field);
                $post = get_post($job->ID);

                $response[] = [
                    'id' => $job->ID,
                    'slug' => $post->post_name,
                    'title' => get_the_title($job->ID),
                    'featured_image' => get_the_post_thumbnail_url($job->ID, 'full') ?: '',
                    'job_location' => get_field('job_location', $job->ID) ?: '',
                    'job_type' => get_field('job_type', $job->ID) ?: '',
                    'salary_range' => get_field('salary_range', $job->ID) ?: '',
                    'required_experience' => get_field('required_experience', $job->ID) ?: '',
                    'job_description' => get_field('job_description', $job->ID) ?: '',
                    'requirements' => get_field('requirements', $job->ID) ?: '',
                    'company' => $company_data,
                    'created_date' => get_the_date('Y-m-d H:i:s', $job->ID), // <-- Added line
                    // 'link' => get_permalink($job->ID),
                ];
            }

            return rest_ensure_response($response);
        }

        public static function get_companies(WP_REST_Request $request)
        {
            $companies = get_posts([
                'post_type' => 'company',
                'post_status' => 'publish',
                'numberposts' => -1,
            ]);

            if (empty($companies)) {
                return rest_ensure_response([]);
            }

            $response = [];

            foreach ($companies as $company) {
                $post = get_post($company->ID);
                $response[] = [
                    'id' => $company->ID,
                    'slug' => $post->post_name,
                    'title' => get_the_title($company->ID),
                    'featured_image' => get_the_post_thumbnail_url($company->ID, 'full') ?: '',
                    'company_website' => get_field('company_website', $company->ID) ?: '',
                    'company_location' => get_field('company_location', $company->ID) ?: '',
                    'company_contact_number' => get_field('company_contact_number', $company->ID) ?: '',
                    'company_email' => get_field('company_email', $company->ID) ?: '',
                    'company_founded_year' => get_field('company_founded_year', $company->ID) ?: '',
                    'company_total_employees' => get_field('company_total_employees', $company->ID) ?: '',
                    'company_revenue_generates' => get_field('company_revenue_generates', $company->ID) ?: '',
                    'about_company' => get_field('about_company', $company->ID) ?: '',
                    'created_date' => get_the_date('Y-m-d H:i:s', $company->ID), // <-- Added line
                    // 'link' => get_permalink($company->ID),
                ];
            }

            return rest_ensure_response($response);
        }

        private static function prepare_company_data($company_field)
        {
            if (empty($company_field)) {
                return null;
            }

            // Use the first company if it's an array, otherwise just use it directly
            $company = is_array($company_field) ? $company_field[0] : $company_field;

            if ($company instanceof WP_Post) {
                $post = get_post($company->ID);
                return [
                    'id' => $company->ID,
                    'name' => get_the_title($company->ID),
                    'slug' => $post->post_name,
                    'company_location' => get_field('company_location', $company->ID) ?: '',
                    // 'link' => get_permalink($company->ID),
                    'logo' => get_the_post_thumbnail_url($company->ID, 'full') ?: '',
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

            $company_field = get_field('company', $job->ID);
            $company_data = self::prepare_company_data($company_field);

            $response = [
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
                'created_date' => get_the_date('Y-m-d H:i:s', $job->ID), // <-- Added line
            ];

            return rest_ensure_response($response);
        }

        public static function get_single_company(WP_REST_Request $request)
        {
            $id = $request->get_param('id');
            $slug = $request->get_param('slug');

            if ($id) {
                $company = get_post($id);
            } elseif ($slug) {
                $company = get_page_by_path($slug, OBJECT, 'company');
            } else {
                return new WP_Error('invalid_request', 'ID or Slug is required.', array('status' => 400));
            }

            if (empty($company) || $company->post_type !== 'company') {
                return new WP_Error('not_found', 'Company not found.', array('status' => 404));
            }

            // Fetch jobs related to the company
            $related_jobs = get_posts([
                'post_type' => 'job',
                'post_status' => 'publish',
                'meta_query' => [
                    [
                        'key' => 'company', // Assuming the ACF field for the company is 'company'
                        'value' => $company->ID,
                        'compare' => 'LIKE',
                    ]
                ],
                'numberposts' => -1,
            ]);

            // Prepare the response for the company
            $response = [
                'id' => $company->ID,
                'slug' => $company->post_name,
                'title' => get_the_title($company->ID),
                'featured_image' => get_the_post_thumbnail_url($company->ID, 'full') ?: '',
                'company_website' => get_field('company_website', $company->ID) ?: '',
                'company_location' => get_field('company_location', $company->ID) ?: '',
                'company_contact_number' => get_field('company_contact_number', $company->ID) ?: '',
                'company_email' => get_field('company_email', $company->ID) ?: '',
                'company_founded_year' => get_field('company_founded_year', $company->ID) ?: '',
                'company_total_employees' => get_field('company_total_employees', $company->ID) ?: '',
                'company_revenue_generates' => get_field('company_revenue_generates', $company->ID) ?: '',
                'about_company' => get_field('about_company', $company->ID) ?: '',
                'created_date' => get_the_date('Y-m-d H:i:s', $company->ID),
            ];

            // Prepare the related jobs without including the company data
            $related_jobs_data = [];
            foreach ($related_jobs as $job) {
                $post = get_post($job->ID);
                $related_jobs_data[] = [
                    'id' => $job->ID,
                    'slug' => $post->post_name,
                    'title' => get_the_title($job->ID),
                    'featured_image' => get_the_post_thumbnail_url($job->ID, 'full') ?: '',
                    'job_location' => get_field('job_location', $job->ID) ?: '',
                    'job_type' => get_field('job_type', $job->ID) ?: '',
                    'salary_range' => get_field('salary_range', $job->ID) ?: '',
                    'required_experience' => get_field('required_experience', $job->ID) ?: '',
                    'job_description' => get_field('job_description', $job->ID) ?: '',
                    'requirements' => get_field('requirements', $job->ID) ?: '',
                    'created_date' => get_the_date('Y-m-d H:i:s', $job->ID), // Optional: Add created date for jobs
                ];
            }

            // Add the related jobs to the company response
            $response['related_jobs'] = $related_jobs_data;

            return rest_ensure_response($response);
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
            $company_ids = $request->get_param('company_id'); // Can be array or single value

            // Validate title
            if (empty($title)) {
                return new WP_Error('missing_title', 'Title is required.', array('status' => 400));
            }

            // Normalize to array
            if (empty($company_ids)) {
                return new WP_Error('missing_company', 'At least one company is required.', array('status' => 400));
            }
            if (!is_array($company_ids)) {
                $company_ids = [$company_ids];
            }

            // Create the job post
            $post_id = wp_insert_post([
                'post_type' => 'job',
                'post_title' => sanitize_text_field($title),
                'post_status' => 'publish',
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

            // Update the "company" field with multiple companies
            $valid_company_ids = array_map('intval', $company_ids); // Sanitize IDs
            update_field('company', $valid_company_ids, $post_id);  // Save array of IDs

            return rest_ensure_response(['success' => true, 'id' => $post_id]);
        }


        public static function create_company(WP_REST_Request $request)
        {
            // Get parameters from the request
            $title = $request->get_param('title');
            $company_website = $request->get_param('company_website');
            $company_contact_number = $request->get_param('company_contact_number');
            $company_email = $request->get_param('company_email');
            $company_founded_year = $request->get_param('company_founded_year');
            $company_total_employees = $request->get_param('company_total_employees');
            $company_revenue_generates = $request->get_param('company_revenue_generates');
            $company_location = $request->get_param('company_location');
            $about_company = $request->get_param('about_company');
            $featured_image_id = $request->get_param('featured_image_id'); // <-- NEW

            // Validate the title (required)
            if (empty($title)) {
                return new WP_Error('missing_title', 'Company title is required.', array('status' => 400));
            }

            // Create the company post
            $post_id = wp_insert_post([
                'post_type' => 'company',
                'post_title' => sanitize_text_field($title),
                'post_status' => 'publish',
            ]);

            if (is_wp_error($post_id)) {
                return $post_id;
            }

            // Update ACF fields
            update_field('company_website', esc_url_raw($company_website ?? ''), $post_id);
            update_field('company_location', sanitize_text_field($company_location ?? ''), $post_id);
            update_field('about_company', sanitize_textarea_field($about_company ?? ''), $post_id);
            update_field('company_contact_number', sanitize_textarea_field($company_contact_number ?? ''), $post_id);
            update_field('company_email', sanitize_textarea_field($company_email ?? ''), $post_id);
            update_field('company_founded_year', sanitize_textarea_field($company_founded_year ?? ''), $post_id);
            update_field('company_total_employees', sanitize_textarea_field($company_total_employees ?? ''), $post_id);
            update_field('company_revenue_generates', sanitize_textarea_field($company_revenue_generates ?? ''), $post_id);

            // Set featured image if media ID is provided
            if (!empty($featured_image_id) && get_post_type($featured_image_id) === 'attachment') {
                set_post_thumbnail($post_id, intval($featured_image_id));
            }

            return rest_ensure_response(['success' => true, 'id' => $post_id]);
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
            $company_ids = $request->get_param('company_id');


            // Get the existing job post by ID
            $job = get_post($id);
            if (empty($job) || $job->post_type !== 'job') {
                return new WP_Error('not_found', 'Job not found.', array('status' => 404));
            }

            if (!is_array($company_ids)) {
                $company_ids = [$company_ids];
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

            // If company IDs are passed, update the company relationship
            if (!empty($company_ids)) {
                if (!is_array($company_ids)) {
                    $company_ids = [$company_ids];
                }
                $valid_company_ids = array_map('intval', $company_ids); // Sanitize IDs
                update_field('company', $valid_company_ids, $id);  // Save array of IDs
            }

            return rest_ensure_response(['success' => true, 'id' => $id]);
        }


        public static function update_company(WP_REST_Request $request)
        {
            // Get parameters from the request
            $id = $request->get_param('id');
            $title = $request->get_param('title');
            $company_website = $request->get_param('company_website');
            $company_contact_number = $request->get_param('company_contact_number');
            $company_email = $request->get_param('company_email');
            $company_founded_year = $request->get_param('company_founded_year');
            $company_total_employees = $request->get_param('company_total_employees');
            $company_revenue_generates = $request->get_param('company_revenue_generates');
            $company_location = $request->get_param('company_location');
            $about_company = $request->get_param('about_company');


            // Get the existing job post by ID
            $company = get_post($id);
            if (empty($company) || $company->post_type !== 'company') {
                return new WP_Error('not_found', 'company not found.', array('status' => 404));
            }

            // Update the job post
            wp_update_post([
                'ID' => $id,
                'post_title' => sanitize_text_field($title),
            ]);

            // Update ACF fields
            update_field('company_website', sanitize_text_field($company_website ?? ''), $id);
            update_field('company_location', sanitize_text_field($company_location ?? ''), $id);
            update_field('about_company', sanitize_text_field($about_company ?? ''), $id);
            update_field('company_contact_number', sanitize_textarea_field($company_contact_number ?? ''), $id);
            update_field('company_email', sanitize_textarea_field($company_email ?? ''), $id);
            update_field('company_founded_year', sanitize_textarea_field($company_founded_year ?? ''), $id);
            update_field('company_total_employees', sanitize_textarea_field($company_total_employees ?? ''), $id);
            update_field('company_revenue_generates', sanitize_textarea_field($company_revenue_generates ?? ''), $id);

            return rest_ensure_response(['success' => true, 'id' => $id]);
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

            return rest_ensure_response(['success' => true, 'id' => $id]);
        }


        public static function delete_company(WP_REST_Request $request)
        {
            $id = $request->get_param('id');

            if (empty($id)) {
                return new WP_Error('missing_id', 'Company ID is required.', array('status' => 400));
            }

            $company = get_post($id);
            if (empty($company) || $company->post_type !== 'company') {
                return new WP_Error('not_found', 'Company not found.', array('status' => 404));
            }

            // Delete the company post
            wp_delete_post($id, true); // true means force delete

            return rest_ensure_response(['success' => true, 'id' => $id]);
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

            return $payload_data;  // Return payload data if valid
        }

        public static function jobportalapi_register_user(WP_REST_Request $request)
        {
            $username = sanitize_user($request->get_param('username'));
            $email = sanitize_email($request->get_param('email'));
            $password = $request->get_param('password');
            $role = sanitize_text_field($request->get_param('role'));

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

            // Create the user
            $user_id = wp_create_user($username, $password, $email);
            if (is_wp_error($user_id)) {
                return $user_id;  // Return error if user creation fails
            }

            // Assign the role to the user
            $user = new WP_User($user_id);
            $user->set_role($role);

            // Generate token
            $token = self::jobportalapi_generate_token($user_id);

            return rest_ensure_response([
                'success' => true,
                'user_id' => $user_id,
                'username' => $username,
                'email' => $email,
                'role' => $role,
                'token' => $token
            ]);
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

            // Get user's role
            $user_roles = $user->roles;
            $primary_role = !empty($user_roles) ? $user_roles[0] : 'subscriber';

            return rest_ensure_response([
                'success' => true,
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'role' => $primary_role,
                'token' => $token
            ]);
        }
    }
}
