<?php
/**
 * Plugin Name: WP OAuth Server - CE
 * Plugin URI: http://wp-oauth.com
 * Version: 4.5.0
 * Description: Full OAuth2 Server for WordPress. User Authorization Management Systems For WordPress.
 * Author: WP OAuth Server
 * Author URI: http://wp-oauth.com
 * Text Domain: wp-oauth
 * 
 * @package WP OAuth Server
 */

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

if ( ! defined( 'WPOAUTH_FILE' ) ) {
	define( 'WPOAUTH_FILE', __FILE__ );
}

if ( ! defined( 'WPOAUTH_VERSION' ) ) {
	define( 'WPOAUTH_VERSION', '4.5.0' );
}

// localize
add_action( 'plugins_loaded', 'wo_load_textdomain', 99 );
function wo_load_textdomain() {
	load_plugin_textdomain( 'wp-oauth', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
}

/**
 * 5.4 Strict Mode Temp Patch
 *
 * Since PHP 5.4, WP will through notices due to the way WP calls statically
 */
function wpoauth_server_register_files( $suffix ) {
	wp_register_script( 'wo_admin_select2', plugins_url( '/assets/js/select2.min.js', __FILE__ ), array( 'jquery' ) );
	wp_register_style( 'wo_admin_select2', plugins_url( '/assets/css/select2.min.css', __FILE__ ) );
	wp_register_script( 'wo_admin_chosen', plugins_url( '/assets/js/chosen.js', __FILE__ ), array( 'jquery' ) );
	wp_register_style( 'wo_admin', plugins_url( '/assets/css/admin.css', __FILE__ ) );
	wp_register_script( 'wo_admin', plugins_url( '/assets/js/admin.js', __FILE__ ), array(
		'jquery-ui-tabs',
		'jquery',
	) );

	// Only register and call select2 on on the page needed.
	if ( $suffix == 'toplevel_page_wo_manage_clients'
		|| $suffix == 'admin_page_wo_edit_client'
		|| $suffix == 'oauth-server_page_wo_settings'
		|| $suffix == 'admin_page_wo_add_client'
	) {
		wp_enqueue_script( 'wo_admin_select2' );
		wp_enqueue_script( 'wo_admin_chosen' );
		wp_enqueue_style( 'wo_admin_select2' );
		wp_enqueue_script( 'wo_admin' );
		wp_enqueue_style( 'wo_admin' );
	}

	if ( $suffix == 'profile.php' ) {
		wp_enqueue_script( 'wo_admin' );
	}
}

add_action( 'admin_enqueue_scripts', 'wpoauth_server_register_files' );

/**
 * Admin notice: Permalinks should be enabled.
 */
add_action( 'admin_notices', 'wpoauth_permalink_notice' );
add_action( 'admin_post_wpoauth_dismiss_permalink_notice', 'wpoauth_handle_permalink_notice_action' );
add_action( 'admin_post_wpoauth_remind_permalink_notice', 'wpoauth_handle_permalink_notice_action' );
add_action( 'update_option_permalink_structure', 'wpoauth_reset_permalink_notice_state', 10, 2 );

function wpoauth_handle_permalink_notice_action() {
	if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
		return;
	}

	if ( empty( $_GET['_wpnonce'] ) ) {
		return;
	}

	if ( ! wp_verify_nonce( sanitize_text_field( $_GET['_wpnonce'] ), 'wo_permalink_notice_action' ) ) {
		return;
	}

	$action = isset( $_GET['action'] ) ? sanitize_text_field( $_GET['action'] ) : '';
	if ( 'wpoauth_remind_permalink_notice' === $action ) {
		update_user_meta( get_current_user_id(), 'wo_permalink_notice_snooze_until', time() + ( 30 * DAY_IN_SECONDS ) );
	} elseif ( 'wpoauth_dismiss_permalink_notice' === $action ) {
		update_user_meta( get_current_user_id(), 'wo_dismiss_permalink_notice', 1 );
	}

	$redirect = wp_get_referer();
	if ( ! $redirect ) {
		$redirect = admin_url();
	}
	wp_safe_redirect( $redirect );
	exit;
}

/**
 * Reset notice history when permalinks change.
 */
function wpoauth_reset_permalink_notice_state( $old_value, $value ) {
	if ( $old_value === $value ) {
		return;
	}

	delete_metadata( 'user', 0, 'wo_dismiss_permalink_notice', '', true );
	delete_metadata( 'user', 0, 'wo_permalink_notice_snooze_until', '', true );
}

function wpoauth_permalink_notice() {
	if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
		return;
	}

	if ( get_option( 'permalink_structure' ) ) {
		return;
	}

	if ( get_user_meta( get_current_user_id(), 'wo_dismiss_permalink_notice', true ) ) {
		return;
	}

	$snooze_until = (int) get_user_meta( get_current_user_id(), 'wo_permalink_notice_snooze_until', true );
	if ( $snooze_until && time() < $snooze_until ) {
		return;
	}

	$permalinks_url = admin_url( 'options-permalink.php' );
	$action_base = admin_url( 'admin-post.php' );
	$dismiss_url = wp_nonce_url( add_query_arg( 'action', 'wpoauth_dismiss_permalink_notice', $action_base ), 'wo_permalink_notice_action' );
	$remind_url = wp_nonce_url( add_query_arg( 'action', 'wpoauth_remind_permalink_notice', $action_base ), 'wo_permalink_notice_action' );

	echo '<div class="notice notice-warning is-dismissible">';
	echo '<p>';
	echo esc_html__( 'WP OAuth Server recommends enabling pretty permalinks for OAuth endpoints to work as expected.', 'wp-oauth' ) . ' ';
	echo '<a href="' . esc_url( $permalinks_url ) . '">' . esc_html__( 'Open Permalink Settings', 'wp-oauth' ) . '</a>.';
	echo '</p>';
	echo '<p>';
	echo '<a class="button" href="' . esc_url( $remind_url ) . '">' . esc_html__( 'Remind me in 30 days', 'wp-oauth' ) . '</a> ';
	echo '<a class="button-link" href="' . esc_url( $dismiss_url ) . '">' . esc_html__( 'Dismiss', 'wp-oauth' ) . '</a>';
	echo '</p>';
	echo '</div>';
}

require_once dirname( __FILE__ ) . '/includes/functions.php';
require_once dirname( __FILE__ ) . '/includes/cron.php';
require_once dirname( __FILE__ ) . '/wp-oauth-main.php';

/**
 * Adds/registers query vars
 *
 * @return void
 */
function wpoauth_server_register_query_vars() {
	_wo_server_register_rewrites();

	global $wp;
	$wp->add_query_var( 'oauth' );
	$wp->add_query_var( 'well-known' );
	$wp->add_query_var( 'wpoauthincludes' );
}

add_action( 'init', 'wpoauth_server_register_query_vars' );

/**
 * Registers rewrites for OAuth2 Server
 *
 * - authorize
 * - token
 * - .well-known
 * - wpoauthincludes
 *
 * @return void
 */
function _wo_server_register_rewrites() {
	add_rewrite_rule( '^oauth/(.+)', 'index.php?oauth=$matches[1]', 'top' );
	add_rewrite_rule( '^.well-known/(.+)', 'index.php?well-known=$matches[1]', 'top' );
	add_rewrite_rule( '^wpoauthincludes/(.+)', 'index.php?wpoauthincludes=$matches[1]', 'top' );
}

/**
 * [template_redirect_intercept description]
 *
 * @return [type] [description]
 */
function wpoauth_server_template_redirect_intercept( $template ) {
	global $wp_query;

	if ( $wp_query->get( 'oauth' ) || $wp_query->get( 'well-known' ) ) {
		define( 'DOING_OAUTH', true );
		include_once dirname( __FILE__ ) . '/library/class-wo-api.php';
		exit;
	}

	return $template;
}

add_filter( 'template_include', 'wpoauth_server_template_redirect_intercept', 100 );

/**
 * OAuth2 Server Activation
 *
 * @param [type] $network_wide [description]
 *
 * @return [type]               [description]
 */
function wpoauth_server_activation( $network_wide ) {
	if ( function_exists( 'is_multisite' ) && is_multisite() && $network_wide ) {
		$mu_blogs = get_sites();
		foreach ( $mu_blogs as $mu_blog ) {
			switch_to_blog( $mu_blog['blog_id'] );
			_wo_server_register_rewrites();
			flush_rewrite_rules();
		}
		restore_current_blog();
	} else {
		_wo_server_register_rewrites();
		flush_rewrite_rules();
	}

	// Schedule the cleanup workers
	wp_schedule_event( time(), 'hourly', 'wpo_global_cleanup' );
}

register_activation_hook( __FILE__, 'wpoauth_server_activation' );

/**
 * OAuth Server Deactivation
 *
 * @param [type] $network_wide [description]
 *
 * @return [type]               [description]
 */
function wpoauth_server_deactivation( $network_wide ) {
	if ( function_exists( 'is_multisite' ) && is_multisite() && $network_wide ) {
		$mu_blogs = get_sites();
		foreach ( $mu_blogs as $mu_blog ) {
			switch_to_blog( $mu_blog['blog_id'] );
			flush_rewrite_rules();
		}
		restore_current_blog();
	} else {
		flush_rewrite_rules();
	}

	// Remove the cleanup workers.
	wp_clear_scheduled_hook( 'wpo_global_cleanup' );
}

register_deactivation_hook( __FILE__, 'wpoauth_server_deactivation' );

register_activation_hook( __FILE__, array( new WO_Server(), 'setup' ) );
register_activation_hook( __FILE__, array( new WO_Server(), 'upgrade' ) );