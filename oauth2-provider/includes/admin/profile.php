<?php
/**
 * Addes the Ability for User Generated Access Tokens
 * @updated 4.3.0
 * @author Justin Greer <justin@dash10.digital>
 */

add_action( 'show_user_profile', 'wp_oauth_profile_oauth_info' );
add_action( 'edit_user_profile', 'wp_oauth_profile_oauth_info' );
function wp_oauth_profile_oauth_info( $user ) {

	// Only a user can do this of thier own free will.
	if ( $user->data->ID != get_current_user_id() ) {
		return;
	}
	?>
<br />
<h3>OAuth2 Authentication / Application Password</h3>
<p>OAuth2 Application Passwords work a bit differently than normal applications passwords. OAuth2 Passwords work
    with the OAuth2 resource server specific to OAuth2.Read more about <a href="https://wp-oauth.com"
       target="_blank">OAuth2 Application
        Passwords</a>.</p>
<div>
    <?php if ( is_null( wo_ap_et_access_token_for_user() ) ) : ?>
    <table class="form-table">
        <tr>
            <p class="submit">
                <input type="submit" name="generate_token" id="submit" class="button" value="Generate Token">
                <input type="hidden" name="generate_token_nonce"
                       value="<?php echo esc_attr( wp_create_nonce( 'generate_token' ) ); ?>" />
            </p>
        </tr>
    </table>
    <?php else : ?>
    <?php $user_token = wo_ap_et_access_token_for_user(); ?>
    <table class="form-table">
        <tr>
            <th>Access Token</th>
            <td>
                <?php echo esc_html( $user_token->access_token ); ?> <br /> <br />
                <input type="submit" name="generate_token" id="regenerate" class="button button-secondary"
                       value="Regenerate Token">
                <input type="hidden" name="generate_token_nonce"
                       value="<?php echo esc_attr( wp_create_nonce( 'generate_token' ) ); ?>" />
                | <a href="#" id="revoke-token" data-nonce="<?php echo esc_attr( wp_create_nonce( 'wo_remove_self_generated_token' ) ); ?>">Revoke Token</a>
            </td>
        </tr>
    </table>

    <?php endif; ?>

</div>
<?php
}

add_action( 'user_profile_update_errors', 'wo_user_profile_update_token_gen', 10, 3 );
function wo_user_profile_update_token_gen( $errors, $update, $user ) {
	if ( ! empty( $_POST['generate_token'] ) && is_user_logged_in() && wp_verify_nonce( $_POST['generate_token_nonce'], 'generate_token' ) ) {

		$client_id = wo_ap_create_user_generated_client_id();
		if ( empty( $client_id ) ) {
			return;
		}

		$access_token = wp_ap_generate_access_token();

		/*
		 * Set the expire time to 99 years from now
		 *
		 * @todo Make this an option in the settings for the admin. Allow them to modify this.
		 */
		$expires = date( 'Y-m-d H:i:s', strtotime( date( 'Y-m-d H:i:s', time() ) . ' + 10 year' ) );

		/*
		 * Set the access token for the user generated client. generated clients only allow for basic scope.
		 */
		wo_ap_token_gen_set_access_token( $access_token, $client_id, get_current_user_id(), $expires, 'basic' );
	}
}

/**
 * @param $access_token
 * @param $client_id
 * @param $user_id
 * @param $expires
 * @param null $scope
 *
 * @return bool|int
 */
function wo_ap_token_gen_set_access_token( $access_token, $client_id, $user_id, $expires, $scope = null ) {
	global $wpdb;

	$user_id = absint( $user_id );

	/*
	 * Delete old token(s) to limit security issues
	 */
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->prefix}oauth_access_tokens WHERE user_id = %d AND ap_generated = 1",
			$user_id
		)
	);

	/*
	 * Insert the new token info
	 */
	$insert = $wpdb->insert(
		"{$wpdb->prefix}oauth_access_tokens",
		array(
			'access_token' => $access_token,
			'client_id' => $client_id,
			'user_id' => $user_id,
			'expires' => $expires,
			'scope' => 'basic',
			'ap_generated' => '1',
		)
	);

	// Return Results
	return $insert;
}

/**
 * Create or reuse the current user's internal user-generated OAuth client.
 *
 * Uses wp_insert_post() intentionally so any logged-in user can create their own
 * user_generated_{uid} client even though wo_client CPT caps require manage_options.
 * Meta values are plugin-controlled only — never taken from request input.
 *
 * @return string|false Client ID, or false on failure.
 */
function wo_ap_create_user_generated_client_id() {
	if ( ! is_user_logged_in() ) {
		return false;
	}

	$user_id     = get_current_user_id();
	$client_title = 'user_generated_' . $user_id;

	$existing = get_posts(
		array(
			'post_type'              => 'wo_client',
			'post_status'            => 'any',
			'title'                  => $client_title,
			'posts_per_page'         => 1,
			'no_found_rows'          => true,
			'update_post_meta_cache' => true,
			'update_post_term_cache' => false,
		)
	);

	if ( ! empty( $existing ) ) {
		return get_post_meta( $existing[0]->ID, 'client_id', true );
	}

	$client_id     = wo_gen_key();
	$client_secret = wo_gen_key();

	$client_post = array(
		'post_title'     => $client_title,
		'post_content'   => ' ',
		'post_status'    => 'publish',
		'post_author'    => $user_id,
		'post_type'      => 'wo_client',
		'comment_status' => 'closed',
		'meta_input'     => array(
			'client_id'     => $client_id,
			'client_secret' => $client_secret,
			'grant_types'   => array( 'authorization_code' ),
			'redirect_uri'  => '',
			'user_id'       => $user_id,
			'scope'         => 'basic',
		),
	);

	$inserted = wp_insert_post( $client_post, true );
	if ( is_wp_error( $inserted ) || ! $inserted ) {
		return false;
	}

	return $client_id;
}

function wp_ap_generate_access_token() {
	$token_length = wo_setting( 'token_length' );

	return strtolower( wp_generate_password( $token_length, false, $extra_special_chars = false ) );
}

function wo_ap_et_access_token_for_user() {
	global $wpdb;

	$current_user = get_current_user_id();
	$check = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}oauth_access_tokens WHERE user_id = %d", array( $current_user ) ) );

	return $check;
}
