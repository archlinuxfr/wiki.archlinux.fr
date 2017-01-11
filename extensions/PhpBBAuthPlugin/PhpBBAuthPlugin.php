<?php

$wgExtensionCredits['other'][] = array(
	'name' => 'PhpBBAuthPlugin',
	'version' => '1.1',
	'description' => 'Use phpBB accounts in MediaWiki based on FluxBBAuthPlugin',
	'author' => array('tuxce', 'Skunnyk'),
	'url' => 'https://github.com/archlinuxfr/wiki.archlinux.fr/tree/archfr/extensions/PhpBBAuthPlugin'
);

require_once(__DIR__.'/../../includes/AuthPlugin.php');
require_once(dirname( __FILE__ ) . '/PasswordHash.php');


global $PhpBBDatabase;
$PhpBBDatabase = 'mydatabase';

class PhpBBAuthPlugin extends AuthPlugin {

	public static function isValidPassword($password) {
		$length = strlen($password);
		return $length >= 4;
	}
	
	private function getUserData($username) {
		global $PhpBBDatabase;
		$dbr = wfGetDB( DB_SLAVE );

		return $dbr->selectRow($PhpBBDatabase.'.phpbb3_users',array('username_clean as username', 'user_email as email', 'username as realname'), array('username_clean' => strtolower ($username)));
	}

	public function userExists( $username ) {
		global $PhpBBDatabase;
		$dbr = wfGetDB( DB_SLAVE );
		try {
			$result = $dbr->select($PhpBBDatabase.'.phpbb3_users','user_id', array('username_clean' => strtolower ($username)));
			$exists = ($result->numRows() > 0 ? true : false);
			$result->free();
		} catch (DBQueryError $e) {
			$exists = false;
		}
			error_log(print_r($exists,true));

		return $exists;
	}

	private function checkHash ($password, $hash) {
        if (strlen($hash) == 34)
        {
            // We need to use PasswordHash function to resolv phpbb3.0 hashed passwords, see function phpbb_hash in phpbb3/includes/functions.php
            $t_hasher = new PasswordHash(8, TRUE);
            return ($t_hasher->crypt_private($password, $hash) === $hash) ? true : false;
        }
        else if (strlen($hash) == 60)
        {
            // We need to resolv phpbb3.1 hashed passwords with bcrypt_2y (see function phpbb/passwords/driver/bcrypt.php)
            $salt = substr($hash, 0, 29);
            return $hash === crypt($password, $salt);
        }
        return (md5($password) === $hash) ? true : false;
    }


	public function authenticate( $username, $password ) {
		global $PhpBBDatabase;
		$dbr = wfGetDB( DB_SLAVE );

		try {
			$result = $dbr->select($PhpBBDatabase.'.phpbb3_users', 'user_password', array('username_clean' => strtolower ($username)));
			$data = $result->fetchRow();
			$authenticated = $this->checkHash ($password, $data['user_password']);
			$result->free();
		} catch (DBQueryError $e) {
			$authenticated = false;
		}

		return $authenticated;
	}

	public function modifyUITemplate( &$template, &$type ) {
		$template->set( 'usedomain', false );
	}

	public function updateUser( &$user ) {
		return $this->initUser($user);
	}

	public function autoCreate() {
		return true;
	}

	protected function allowRealNameChange() {
		return false;
	}

	protected function allowEmailChange() {
		return false;
	}

	protected function allowNickChange() {
		return false;
	}

	public function allowPasswordChange() {
		return false;
	}

	public function allowSetLocalPassword() {
		return false;
	}

	public function setPassword( $user, $password ) {
		return false;
	}

	public function updateExternalDB( $user ) {
		return false;
	}

	public function updateExternalDBGroups( $user, $addgroups, $delgroups = array() ) {
		return false;
	}

	public function canCreateAccounts() {
		return false;
	}

	public function addUser( $user, $password, $email = '', $realname = '' ) {
		return false;
	}

	public function strict() {
		return true;
	}

	public function strictUserAuth( $username ) {
		return true;
	}

	public function initUser( &$user, $autocreate = false ) {
		try {
			$data = $this->getUserData($user->getName());
			if (!$data) {
				return false;
			}
			$user->setEmail($data->email);
			$user->confirmEmail();
			$user->setRealName($data->realname);
			$user->saveSettings();
		} catch (Exception $e) {
			return false;
		}
		return true;
	}

	public function getCanonicalName( $username ) {
		try {
			$data = $this->getUserData($username);
			if ($data !== false) {
				return strtoupper(substr($data->username, 0, 1)).substr($data->username, 1);
			}
		} catch (Exception $e) {
		}
		return $username;
	}

}

$wgAuth = new PhpBBAuthPlugin();
$wgHiddenPrefs[] = 'realname';
$wgHooks['isValidPassword'][] = 'PhpBBAuthPlugin::isValidPassword';

?>
