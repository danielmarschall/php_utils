<?php

/*
 * ViaThinkSoft Modular Crypt Format and vts_password_*() functions
 * Copyright 2023-2026 Daniel Marschall, ViaThinkSoft
 * Revision 2026-04-20
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*

Usage of vts_crypt.inc.php
==========================

The function vts_password_hash() replaces password_hash().
It contains all algorithms from password_hash() and
adds ViaThinkSoft Modular Crypt Format (vts_mcf1_hash()),
adds ViaThinkSoft MHA1 (deprecated), MHA2 (deprecated), MHA3 (deprecated),
NTLM, apr1 (htdigest), as well as all hashes from crypt().

The function vts_password_verify() replaces password_verify().
It combines the normal password_verify(), which is also compatible with crypt(),
and adds support for ViaThinkSoft Modular Crypt Format (vts_mcf1_verify()),
MHA1 (deprecated), MHA2 (deprecated), and MHA3 (deprecated).

Furthermore, use:
- vts_password_algos() instead of password_algos()
- vts_password_get_info() instead of password_get_info()
- vts_password_needs_rehash() instead of password_needs_rehash()


About the Modular Crypt Format (MCF)
====================================

see https://en.wikipedia.org/wiki/Crypt_(C)

Implemented are the following hashes:

xxxxxxxxxxxxx                              = DES (Standard DES)
_xxx.xxxxxxxxxxxxxxx                       = BSDi (Extended DES)
$1$...                                     = MD5
$2$..., $2a$..., $2b$..., $2x$..., $2y$... = Blowfish
$3$...                                     = NTHash
$5$...                                     = SHA256
$6$...                                     = SHA512
$apr1$...                                  = MD5 Apr1 (htdigest)
$1.3.6.1.4.1.37476.3.0.1.1$...             = ViaThinkSoft MCF1, wraps arbitary hashes (see below)
$1.3.6.1.4.1.37476.3.2.1.1$...             = ViaThinkSoft MHA1 (deprecated)
$1.3.6.1.4.1.37476.3.2.1.2$...             = ViaThinkSoft MHA2 (deprecated)
$1.3.6.1.4.1.37476.3.2.1.3$...             = ViaThinkSoft MHA3 (deprecated)
$argon2i$...                               = Argon2i
$argon2id$...                              = Argon2id


About ViaThinkSoft Modular Crypt Format (VTS MCF)
=================================================

ViaThinkSoft MCF 1.x was created to allow old passwords (e.g. MD5 with salt) to be easily converted
to a MCF notation ($...$...$) so that these old passwords can be stored in the same data structure
as newer crypt passwords, until they get upgraded to a newer hash.

It can also be used to encapsulate modern hash algorithms like SHA3/512 into a MCF format,
so that they can be stored together with other MCF hashes such as bcrypt.

Another innovation is to use Object Identifiers (OIDs) as MCF algorithm identifier.
Algorithm identifiers such as $1$, $2$, ... are nice to remember and short, but
can quickly lead to conflicts, and soon you run out of short identifiers.

Format of VTS MCF1:
	$1.3.6.1.4.1.37476.3.0.1.1$a=<algo>[,ai=<algo-internal>],m=<mode>[,i=<iterations>]$<salt>$<hash>
where <algo> and <algo-internal> are:
	Any valid hash algorithm (name scheme of PHP hash_algos() preferred), e.g.
		sha3-512
		sha3-384
		sha3-256
		sha3-224
		sha512
		sha512/256
		sha512/224
		sha384
		sha256
		sha224
		sha1
		md5
	NOT possible with VTS MCF are these hashes (because they have a special salt-handling and output their own crypt format):
		bcrypt [Standardized crypt identifier 2, 2a, 2b, 2x, 2y]
		argon2i [Crypt identifier argon2i, not standardized]
		argon2id [Crypt identifier argon2id, not standardized]
ai=<algo-internal> is only required if m=<mode> uses the hash[] formula (see below) and can be omitted if it is equal to a=<algo>
Valid <mode> for VTS MCF1:
	The mode can be one of these:
		sp     = salt + password                  Deprecated. Use instead: hash[sp],       it behaves equal if iterations i=0
		ps     = password + salt                  Deprecated. Use instead: hash[ps],       it behaves equal if iterations i=0
		sps    = salt + password + salt           Deprecated. Use instead: hash[sps],      it behaves equal if iterations i=0
		shp    = salt + Hash(password)            Deprecated. Use instead: hash[shbx(p)],  it behaves equal if iterations i=0 and a=ai
		hps    = Hash(password) + salt            Deprecated. Use instead: hash[hbx(p)s],  it behaves equal if iterations i=0 and a=ai
		shps   = salt + Hash(password) + salt     Deprecated. Use instead: hash[shbx(p)s], it behaves equal if iterations i=0 and a=ai
		hmac   = HMAC (salt is the key)           Deprecated. Use instead: hmac[s;p],      it behaves equal if iterations i=0
		pbkdf2 = PBKDF2-HMAC                      Deprecated. Use instead: pbkdf2[s;p]
		         (Additional param "i" contains the number of iterations)
		hmac[<formula for key>;<formula for payload>]
		pbkdf2[<formula for salt>;<formula for payload>]
		hash[<formula for payload>]               The algorithm for these nested hashes is <algo-internal> and not <algo>
	whereas the formulas can be any custom formula with the following elements:
		hbx(...) means hash binary
		hhu(...) means hash hex upper
		hhl(...) means hash hex lower
		h64(...) means hash base64
		s means salt
		p means password
	Example:
		m=hash[shbx(sp)] means that the hash will be Hash(Salt+Hash(Salt+Password))
Regarding <iterations>:
	The parameter "i" can be omitted if 0.
	It is required for mode=pbkdf2 and mode=pbkdf2[...]
	For other modes it is optional, and implemented as follows:
	- For VTS MCF 1.0 (sp,ps,sps,shp,hps,shps,hmac):
	  It repeats the hash/hmac operation with the password being replaced with the previous hash output concatenated with the iteration number starting with 0.
	- For VTS MCF 1.1 (hash[...], hmac[...], pbkdf2[...]):
	  It repeats the hash/hmac operation with the password being replaced with the previous hash output.
Like most Crypt-hashes, <salt> and <hash> are Radix64 coded with alphabet './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' and no padding.
Link to the online specification:
	https://www.viathinksoft.de/std/viathinksoft-std-0004-mcf1.html
Reference implementation in PHP:
	https://github.com/danielmarschall/php_utils/blob/master/vts_crypt.inc.php

---

TODO:
- Implement more algorithms which are not implemented by PHP, e.g. $7$ scrypt, $y$ YESCRYPT, etc.

*/

require_once __DIR__ . '/misc_functions.inc.php';

define('OID_MCF_VTS_V1',     '1.3.6.1.4.1.37476.3.0.1.1'); // { iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 37476 specifications(3) misc(0) modular-crypt-format(1) vts-crypt-v1(1) }
define('OID_MHA_VTS_V1',     '1.3.6.1.4.1.37476.3.2.1.1'); // { iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 37476 specifications(3) algorithm(2) hash(1) mha1(1) }
define('OID_MHA_VTS_V2',     '1.3.6.1.4.1.37476.3.2.1.2'); // { iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 37476 specifications(3) algorithm(2) hash(1) mha2(2) }
define('OID_MHA_VTS_V3',     '1.3.6.1.4.1.37476.3.2.1.3'); // { iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 37476 specifications(3) algorithm(2) hash(1) mha3(3) }

// Valid algorithms for vts_password_hash(), in addition to the PASSWORD_* contants included in PHP:
define('PASSWORD_STD_DES',   'std-des');       // Algorithm from crypt()
define('PASSWORD_EXT_DES',   'ext-des');       // Algorithm from crypt()
define('PASSWORD_MD5',       'md5');           // Algorithm from crypt()
define('PASSWORD_BLOWFISH',  'blowfish');      // Algorithm from crypt()
define('PASSWORD_SHA256',    'sha256');        // Algorithm from crypt()
define('PASSWORD_SHA512',    'sha512');        // Algorithm from crypt()
define('PASSWORD_NTLM',      'ntlm');          // Algorithm manually implemented
define('PASSWORD_APR_MD5',   'apr_md5');       // Algorithm manually implemented
define('PASSWORD_VTS_MCF1',  OID_MCF_VTS_V1);  // Algorithm by ViaThinkSoft
define('PASSWORD_VTS_MHA1',  OID_MHA_VTS_V1);  // Algorithm by ViaThinkSoft (DEPRECATED!)
define('PASSWORD_VTS_MHA2',  OID_MHA_VTS_V2);  // Algorithm by ViaThinkSoft (DEPRECATED!)
define('PASSWORD_VTS_MHA3',  OID_MHA_VTS_V3);  // Algorithm by ViaThinkSoft (DEPRECATED!)
// Other valid values (already defined in PHP):
// - PASSWORD_DEFAULT (currently defaults to PASSWORD_BCRYPT)
// - PASSWORD_BCRYPT
// - PASSWORD_ARGON2I
// - PASSWORD_ARGON2ID

define('PASSWORD_EXT_DES_DEFAULT_ITERATIONS',   725);

define('PASSWORD_BLOWFISH_DEFAULT_COST',        10);

define('PASSWORD_SHA256_DEFAULT_ROUNDS',        5000);

define('PASSWORD_SHA512_DEFAULT_ROUNDS',        5000);

define('PASSWORD_VTS_MCF1_MODE_SP',             'sp');     // deprecated. Salt+Password
define('PASSWORD_VTS_MCF1_MODE_PS',             'ps');     // deprecated. Password+Salt
define('PASSWORD_VTS_MCF1_MODE_SPS',            'sps');    // deprecated. Salt+Password+Salt
define('PASSWORD_VTS_MCF1_MODE_SHP',            'shp');    // deprecated. Salt+Hash(Password)
define('PASSWORD_VTS_MCF1_MODE_HPS',            'hps');    // deprecated. Hash(Password)+Salt
define('PASSWORD_VTS_MCF1_MODE_SHPS',           'shps');   // deprecated. Salt+Hash(Password)+Salt
define('PASSWORD_VTS_MCF1_MODE_HMAC',           'hmac');   // deprecated. HMAC
define('PASSWORD_VTS_MCF1_MODE_PBKDF2',         'pbkdf2'); // deprecated. PBKDF2-HMAC
define('PASSWORD_VTS_MCF1_DEFAULT_ALGO',        'sha3-512'); // any value in hash_algos(), NOT vts_hash_algos()
define('PASSWORD_VTS_MCF1_DEFAULT_MODE',        'hash[ps]');
define('PASSWORD_VTS_MCF1_DEFAULT_ITERATIONS',  0); // For PBKDF2, iterations=0 means: Default, depending on the algo

define('PASSWORD_VTS_MHA1_DEFAULT_ITERATIONS',  1987);
define('PASSWORD_VTS_MHA1_DEFAULT_BASE_ALGO',   'sha1');

define('PASSWORD_VTS_MHA2_DEFAULT_ITERATIONS',  1987);
define('PASSWORD_VTS_MHA2_DEFAULT_BASE_ALGO',   'sha1');

define('PASSWORD_VTS_MHA3_DEFAULT_ITERATIONS',  500);
define('PASSWORD_VTS_MHA3_DEFAULT_LENGTH',      32);
define('PASSWORD_VTS_MHA3_DEFAULT_BASE_ALGO',   'sha1');

define('BASE64_RFC4648_ALPHABET', '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/');
define('BASE64_APR1_ALPHABET',    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
define('BASE64_CRYPT_ALPHABET',   './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');

// --- Part 1: Modular Crypt Format encode/decode

function crypt_modular_format_encode($id, $bin_salt, $bin_hash, $params=null) {
	// $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
	$out = '$'.$id;
	if (!is_null($params)) {
		$ary_params = array();
		foreach ($params as $name => $value) {
			$ary_params[] = "$name=$value";
		}
		$out .= '$'.implode(',',$ary_params);
	}
	$out .= '$'.crypt_radix64_encode($bin_salt);
	$out .= '$'.crypt_radix64_encode($bin_hash);
	return $out;
}

function crypt_modular_format_decode($mcf) {
	$ary = explode('$', $mcf);

	$dummy = array_shift($ary);
	if ($dummy !== '') return false;

	$dummy = array_shift($ary);
	$id = $dummy;

	$params = array();
	$dummy = array_shift($ary);
	if (strpos($dummy, '=') !== false) {
		$params_ary = explode(',',$dummy);
		foreach ($params_ary as $param) {
			$bry = explode('=', $param, 2);
			if (count($bry) > 1) {
				$params[$bry[0]] = $bry[1];
			}
		}
	} else {
		array_unshift($ary, $dummy);
	}

	if (count($ary) > 1) {
		$dummy = array_shift($ary);
		$bin_salt = crypt_radix64_decode($dummy);
	} else {
		$bin_salt = '';
	}

	$dummy = array_shift($ary);
	$bin_hash = crypt_radix64_decode($dummy);

	return array('id'     => $id,
	             'salt'   => $bin_salt,
	             'hash'   => $bin_hash,
	             'params' => $params);
}

// --- Part 2: ViaThinkSoft hashes (do not use these methods directly!)

function vts_mcf1_execute_formula($algo, $formula, $bin_salt, $str_password) {
    $pos = 0;
    $len = strlen($formula);

    $parse_and_eval = function($input, &$pos, $in_parens = false) use (&$parse_and_eval, $bin_salt, $str_password, $algo, $len) {
        $result = '';

        while ($pos < $len) {
            $char = $input[$pos];

            // Ende of a bracket group
            if ($char === ')') {
                if ($in_parens) {
                    break;
                } else {
                    throw new Exception("Unexpected ')' at position $pos");
                }
            }

            // Variables
            if ($char === 's' || $char === 'p') {
                $result .= ($char === 's') ? $bin_salt : $str_password;
                $pos++;
                continue;
            }

            // Detect method (only at the current offset!)
            if (preg_match('/^h(bx|hu|hl|64)/', substr($input, $pos), $match)) {
                $func = $match[0];
                $pos += strlen($func);

                if (!isset($input[$pos]) || $input[$pos] !== '(') {
                    throw new Exception("Expected '(' after $func at position $pos");
                }

                $pos++; // skip '('

                // Parse contents recursively
                $inner = $parse_and_eval($input, $pos, true);

                if (!isset($input[$pos]) || $input[$pos] !== ')') {
                    throw new Exception("Expected ')' at position $pos");
                }

                $pos++; // skip ')'

                // Call method
                switch ($func) {
                    case 'hbx':
                        $result .= hash_ex($algo, $inner, true);
                        break;
                    case 'hhu':
                        $result .= strtoupper(bin2hex(hash_ex($algo, $inner, true)));
                        break;
                    case 'hhl':
                        $result .= strtolower(bin2hex(hash_ex($algo, $inner, true)));
                        break;
                    case 'h64':
                        $result .= base64_encode(bin2hex(hash_ex($algo, $inner, true)));
                        break;
                }

                continue;
            }

            throw new Exception("Unexpected character '$char' at position $pos");
        }

        return $result;
    };

    $output = $parse_and_eval($formula, $pos, false);

    // Verify that everything was processed
    if ($pos !== $len) {
        throw new Exception("Unexpected trailing input at position $pos");
    }

    return $output;
}

function vts_mcf1_hash($algo, $algo_internal, $str_password, $bin_salt, $mode=PASSWORD_VTS_MCF1_DEFAULT_MODE, $iterations=PASSWORD_VTS_MCF1_DEFAULT_ITERATIONS) {
	if (preg_match('@hash\[([^;]*)\]@', $mode, $m)) {
		$bin_hash = $str_password;
		for ($i=0; $i<=$iterations; $i++) {
			$payload  = vts_mcf1_execute_formula($algo_internal, $m[1], $bin_salt, $bin_hash);
			$bin_hash = hash_ex($algo, $payload, true);
		}
	} else if (preg_match('@hmac\[([^;]*);([^;]*)\]@', $mode, $m)) {
		$bin_hash = $str_password;
		for ($i=0; $i<=$iterations; $i++) {
			$key      = vts_mcf1_execute_formula($algo_internal, $m[1], $bin_salt, $bin_hash);
			$payload  = vts_mcf1_execute_formula($algo_internal, $m[2], $bin_salt, $bin_hash);
			$bin_hash = hash_hmac_ex($algo, $payload, $key, true);
		}
	} else if (preg_match('@pbkdf2\[([^;]*);([^;]*)\]@', $mode, $m)) {
		$salt     = vts_mcf1_execute_formula($algo_internal, $m[1], $bin_salt, $str_password);
		$payload  = vts_mcf1_execute_formula($algo_internal, $m[2], $bin_salt, $str_password);
		// Note: If $iterations=0, then hash_pbkdf2_ex() will correct it to the best value depending on $algo, see _vts_password_default_iterations().
		$bin_hash = hash_pbkdf2_ex($algo, $payload, $salt, $iterations, /*length*/0, true);
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_SP) {
		$bin_hash = hash_ex($algo, $bin_salt.$str_password, true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_ex($algo, $bin_salt.$bin_hash.$i, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_PS) {
		$bin_hash = hash_ex($algo, $str_password.$bin_salt, true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_ex($algo, $bin_hash.$i.$bin_salt, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_SPS) {
		$bin_hash = hash_ex($algo, $bin_salt.$str_password.$bin_salt, true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_ex($algo, $bin_salt.$bin_hash.$i.$bin_salt, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_SHP) {
		$bin_hash = hash_ex($algo, $bin_salt.hash_ex($algo,$str_password,true), true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_ex($algo, $bin_salt.$bin_hash.$i, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_HPS) {
		$bin_hash = hash_ex($algo, hash_ex($algo,$str_password,true).$bin_salt, true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_ex($algo, $bin_hash.$i.$bin_salt, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_SHPS) {
		$bin_hash = hash_ex($algo, $bin_salt.hash_ex($algo,$str_password,true).$bin_salt, true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_ex($algo, $bin_salt.$bin_hash.$i.$bin_salt, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_HMAC) {
		$bin_hash = hash_hmac_ex($algo, $str_password, $bin_salt, true);
		for ($i=0; $i<$iterations; $i++) {
			$bin_hash = hash_hmac_ex($algo, $str_password, $bin_hash.$i, true);
		}
	} else if ($mode == PASSWORD_VTS_MCF1_MODE_PBKDF2) {
		// Note: If $iterations=0, then hash_pbkdf2_ex() will correct it to the best value depending on $algo, see _vts_password_default_iterations().
		$bin_hash = hash_pbkdf2_ex($algo, $str_password, $bin_salt, $iterations, /*length*/0, true);
	} else {
		throw new Exception("Invalid VTS MCF1 Mode '$mode'");
	}
	$params = array();
	$params['a'] = $algo;
	if ($algo_internal != $algo) $params['ai'] = $algo_internal;
	$params['m'] = $mode;
	if ($iterations > 0) $params['i'] = $iterations; // i can be omitted if it is 0.
	return crypt_modular_format_encode(OID_MCF_VTS_V1, $bin_salt, $bin_hash, $params);
}

function vts_mcf1_verify($password, $hash): bool {
	if (!str_starts_with($hash, '$'.OID_MCF_VTS_V1.'$')) {
		throw new Exception("This is not a VTS MCF1 hash.");
	}

	// Decode the MCF hash parameters
	$data = crypt_modular_format_decode($hash);
	if ($data === false) throw new Exception('Invalid auth key');
	$id = $data['id'];
	$bin_salt = $data['salt'];
	$bin_hash = $data['hash'];
	$params = $data['params'];

	if (!isset($params['a'])) throw new Exception('Param "a" (algo) missing');
	$algo = $params['a'];
	$algo_internal = $params['ai'] ?? $params['a'];

	if (!isset($params['m'])) throw new Exception('Param "m" (mode) missing');
	$mode = $params['m'];

	if (str_starts_with($mode, 'pbkdf2')) {
		if (!isset($params['i'])) throw new Exception('Param "i" (iterations) missing');
		$iterations = $params['i'];
	} else {
		$iterations = isset($params['i']) ? $params['i'] : 0;
	}

	// Create a VTS MCF 1.0 hash based on the parameters of $hash and the password $password
	$calc_authkey_1 = vts_mcf1_hash($algo, $algo_internal, $password, $bin_salt, $mode, $iterations);

	// We re-encode the MCF to make sure that it can be compared with the VTS MCF 1.0 (correct sorting of params etc.)
	$calc_authkey_2 = crypt_modular_format_encode($id, $bin_salt, $bin_hash, $params);

	return hash_equals($calc_authkey_2, $calc_authkey_1);
}

function vts_mha1_hash($data, $iteratedSalt='', $iterations=1987, $base_algo='sha1') {
	if (!is_numeric($iterations) || ($iterations<1)) {
		trigger_error('at function ' . __FUNCTION__ . ': $iterations has to be greater or equal 1', E_USER_ERROR);
		return false;
	}
	$m = $data;
	for ($i=1; $i<=$iterations; $i++) {
		$m = hash($base_algo, $iteratedSalt.$m.$iteratedSalt, true); // SHA1 with binary output
	}
	$bin_hash = $m;
	$bin_salt = $iteratedSalt;
	$params = [ "a" => $base_algo, "i" => $iterations ];
	return crypt_modular_format_encode(OID_MHA_VTS_V1, $bin_salt, $bin_hash, $params);
}

function vts_mha1_verify($password, $hash): bool {
	if (!str_starts_with($hash, '$'.OID_MHA_VTS_V1.'$')) {
		throw new Exception("This is not a VTS MHA1 hash.");
	}

	// Decode the MCF hash parameters
	$data = crypt_modular_format_decode($hash);
	if ($data === false) throw new Exception('Invalid auth key');
	$id = $data['id'];
	$bin_salt = $data['salt'];
	$bin_hash = $data['hash'];
	$params = $data['params'];

	if (!isset($params['a'])) throw new Exception('Param "a" (algo) missing');
	$base_algo = $params['a'];

	if (!isset($params['i'])) throw new Exception('Param "i" (iterations) missing');
	$iterations = $params['i'];

	// Create a VTS MHA 1.0 hash based on the parameters of $hash and the password $password
	$calc_authkey_1 = vts_mha1_hash($password, $bin_salt, $iterations, $base_algo);

	// We re-encode the MCF to make sure that it can be compared with the VTS MHA 1.0 (correct sorting of params etc.)
	$calc_authkey_2 = crypt_modular_format_encode($id, $bin_salt, $bin_hash, $params);

	return hash_equals($calc_authkey_2, $calc_authkey_1);
}

function vts_mha2_hash($data, $salt='', $iterations=1987, $base_algo='sha1') {
	if (!is_numeric($iterations) || ($iterations<0)) {
		trigger_error('at function ' . __FUNCTION__ . ': $iterations has to be greater or equal 0', E_USER_ERROR);
		return false;
	}
	$MHA2_K = chr(0x24).chr(0x12).chr(0x19).chr(0x87);
	$MHA2_P = chr(0x12).chr(0x24).chr(0x19).chr(0x87);
	$MHA2_Q = chr(0x19).chr(0x87).chr(0x12).chr(0x24);
	$a = '';
	$b = '';
	$c = '';
	for ($i=0; $i<=$iterations; $i++) { // run $iterations+1 times
		$a  = hash($base_algo, $MHA2_P.$a.$data.$salt.$MHA2_Q, true);
		$b  = hash($base_algo, $MHA2_Q.$salt.$data.$b.$MHA2_P, true);
		$c .= $MHA2_K.$data.$salt;
	}
	$c = hash($base_algo, $c, true);
	$bin_hash = ($a ^ $b ^ $c);
	$bin_salt = $salt;
	$params = [ "a" => $base_algo, "i" => $iterations ];
	return crypt_modular_format_encode(OID_MHA_VTS_V2, $bin_salt, $bin_hash, $params);
}

function vts_mha2_verify($password, $hash): bool {
	if (!str_starts_with($hash, '$'.OID_MHA_VTS_V2.'$')) {
		throw new Exception("This is not a VTS MHA2 hash.");
	}

	// Decode the MCF hash parameters
	$data = crypt_modular_format_decode($hash);
	if ($data === false) throw new Exception('Invalid auth key');
	$id = $data['id'];
	$bin_salt = $data['salt'];
	$bin_hash = $data['hash'];
	$params = $data['params'];

	if (!isset($params['a'])) throw new Exception('Param "a" (algo) missing');
	$base_algo = $params['a'];

	if (!isset($params['i'])) throw new Exception('Param "i" (iterations) missing');
	$iterations = $params['i'];

	// Create a VTS MHA 2.0 hash based on the parameters of $hash and the password $password
	$calc_authkey_1 = vts_mha2_hash($password, $bin_salt, $iterations, $base_algo);

	// We re-encode the MCF to make sure that it can be compared with the VTS MHA 2.0 (correct sorting of params etc.)
	$calc_authkey_2 = crypt_modular_format_encode($id, $bin_salt, $bin_hash, $params);

	return hash_equals($calc_authkey_2, $calc_authkey_1);
}

function vts_mha3_hash($data, $length=32, $iterations=500, $base_algo='sha1') {
	if (!is_numeric($iterations) || ($iterations<1)) {
		trigger_error('at function ' . __FUNCTION__ . ': $iterations has to be greater or equal 1', E_USER_ERROR);
		return false;
	}
	$ary = array();
	for ($l=0; $l<$length; $l++) {
		$ary[$l] = 0;
	}
	for ($i=0; $i<$iterations; $i++) {
		for ($l=0; $l<$length; $l++) {
			$n = $i*$length + $l;
			$salt = str_repeat(chr(1), $n);

			$x = hash($base_algo, $data.$salt, true);
			$bytesum_mod256 = 0;
			for ($j=0; $j<strlen($x); $j++) $bytesum_mod256 = ($bytesum_mod256 + ord($x[$j])) % 256;

			$ary[$l] ^= $bytesum_mod256;;
		}
	}
	$out = '';
	for ($i = 0; $i < count($ary); $i++) {
		$out .= chr($ary[$i]);
	}
	$bin_hash = $out;
	$bin_salt = '';
	$params = [ "a" => $base_algo, "i" => $iterations, "l" => $length ];
	return crypt_modular_format_encode(OID_MHA_VTS_V3, $bin_salt, $bin_hash, $params);
}

function vts_mha3_verify($password, $hash): bool {
	if (!str_starts_with($hash, '$'.OID_MHA_VTS_V3.'$')) {
		throw new Exception("This is not a VTS MHA3 hash.");
	}

	// Decode the MCF hash parameters
	$data = crypt_modular_format_decode($hash);
	if ($data === false) throw new Exception('Invalid auth key');
	$id = $data['id'];
	$bin_salt = $data['salt'];
	$bin_hash = $data['hash'];
	$params = $data['params'];

	if ($bin_salt != '') throw new Exception('MHA3 does not support salt');

	if (!isset($params['a'])) throw new Exception('Param "a" (base algo) missing');
	$base_algo = $params['a'];

	if (!isset($params['l'])) throw new Exception('Param "l" (length) missing');
	$length = $params['l'];

	if (!isset($params['i'])) throw new Exception('Param "i" (iterations) missing');
	$iterations = $params['i'];

	// Create a VTS MHA 3.0 hash based on the parameters of $hash and the password $password
	$calc_authkey_1 = vts_mha3_hash($password, $length, $iterations, $base_algo);

	// We re-encode the MCF to make sure that it can be compared with the VTS MHA 3.0 (correct sorting of params etc.)
	$calc_authkey_2 = crypt_modular_format_encode($id, $bin_salt, $bin_hash, $params);

	return hash_equals($calc_authkey_2, $calc_authkey_1);
}

function ntlm_hash($password) {
	return '$3$$'.strtolower(hash('md4',iconv('UTF-8','UTF-16LE',$password)));
}

function ntlm_verify($password, $hash): bool {
	if (!str_starts_with($hash, '$3$')) {
		throw new Exception("This is not a NTLM hash.");
	}
	return hash_equals($hash, ntlm_hash($password));
}

function apr1_hash($mdp, $salt_binary = null) {
        // Source/References for core algorithm:
        // http://www.cryptologie.net/article/126/bruteforce-apr1-hashes/
        // http://svn.apache.org/viewvc/apr/apr-util/branches/1.3.x/crypto/apr_md5.c?view=co
        // http://www.php.net/manual/en/function.crypt.php#73619
        // http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        // Wikipedia
        $BASE64_ALPHABET = BASE64_APR1_ALPHABET;
        $APRMD5_ALPHABET = BASE64_CRYPT_ALPHABET;

        if (is_null($salt_binary)) {
            $salt = '';
            for($i=0; $i<8; $i++) {
                $offset = hexdec(bin2hex(openssl_random_pseudo_bytes(1))) % 64;
                $salt .= $APRMD5_ALPHABET[$offset];
            }
        } else {
                $salt = crypt_radix64_encode($salt_binary);
        }
        $salt = substr($salt, 0, 8);
        $max = strlen($mdp);
        $context = $mdp.'$apr1$'.$salt;
        $binary = pack('H32', md5($mdp.$salt.$mdp));
        for($i=$max; $i>0; $i-=16)
            $context .= substr($binary, 0, min(16, $i));
        for($i=$max; $i>0; $i>>=1)
            $context .= ($i & 1) ? chr(0) : $mdp[0];
        $binary = pack('H32', md5($context));
        for($i=0; $i<1000; $i++) {
            $new = ($i & 1) ? $mdp : $binary;
            if($i % 3) $new .= $salt;
            if($i % 7) $new .= $mdp;
            $new .= ($i & 1) ? $binary : $mdp;
            $binary = pack('H32', md5($new));
        }
        $hash = '';
        for ($i = 0; $i < 5; $i++) {
            $k = $i+6;
            $j = $i+12;
            if($j == 16) $j = 5;
            $hash = $binary[$i].$binary[$k].$binary[$j].$hash;
        }
        $hash = chr(0).chr(0).$binary[11].$hash;
        $hash = strtr(
            strrev(substr(base64_encode($hash), 2)),
            $BASE64_ALPHABET,
            $APRMD5_ALPHABET
        );
        return '$apr1$'.$salt.'$'.$hash;
}

function apr1_verify($password, $hash): bool {
	if (!str_starts_with($hash, '$apr1$')) {
		throw new Exception("This is not a APR MD5 hash.");
	}
	$data = crypt_modular_format_decode($hash);
	return hash_equals($hash, apr1_hash($password,$data['salt']/*this is binary*/));
}

// --- Part 3: vts_password_*() replacement functions

/**
 * This function replaces password_algos() by extending it with
 * password hashes that are implemented in vts_password_hash().
 * @return array of hashes that can be used in vts_password_hash().
 */
function vts_password_algos() {
	$hashes = password_algos();     // Algorithm from password_*()
	$hashes[] = PASSWORD_STD_DES;   // Algorithm from crypt()
	$hashes[] = PASSWORD_EXT_DES;   // Algorithm from crypt()
	$hashes[] = PASSWORD_MD5;       // Algorithm from crypt()
	$hashes[] = PASSWORD_BLOWFISH;  // Algorithm from crypt()
	$hashes[] = PASSWORD_SHA256;    // Algorithm from crypt()
	$hashes[] = PASSWORD_SHA512;    // Algorithm from crypt()
	$hashes[] = PASSWORD_NTLM;      // Algorithm manually implemented
	$hashes[] = PASSWORD_APR_MD5;   // Algorithm manually implemented
	$hashes[] = PASSWORD_VTS_MCF1;  // Algorithm by ViaThinkSoft
	$hashes[] = PASSWORD_VTS_MHA1;  // Algorithm by ViaThinkSoft (DEPRECATED!)
	$hashes[] = PASSWORD_VTS_MHA2;  // Algorithm by ViaThinkSoft (DEPRECATED!)
	$hashes[] = PASSWORD_VTS_MHA3;  // Algorithm by ViaThinkSoft (DEPREACTED!)
	return $hashes;
}

/**
 * vts_password_get_info() is the same as password_get_info(),
 * but it adds the crypt() and ViaThinkSoft MCF 1.0 algos which can be
 * produced by vts_password_hash()
 * @param string $hash Hash created by vts_password_hash(), password_hash(), or crypt().
 * @return array Same output like password_get_info().
 */
function vts_password_get_info($hash) {
	$options = array();
	if (str_starts_with($hash, '$'.OID_MCF_VTS_V1.'$')) {
		// PASSWORD_VTS_MCF1
		$mcf = crypt_modular_format_decode($hash);

		//$options['salt_length'] = strlen($mcf['salt']);  // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()

		if (!isset($mcf['params']['a'])) throw new Exception('Param "a" (algo) missing');
		$options['algo'] = $mcf['params']['a'];
		$options['algo-internal'] = $mcf['params']['ai'] ?? $mcf['params']['a'];

		if (!isset($mcf['params']['m'])) throw new Exception('Param "m" (mode) missing');
		$options['mode'] = $mcf['params']['m'];

		if (str_starts_with($options['mode'], 'pbkdf2')) {
			if (!isset($mcf['params']['i'])) throw new Exception('Param "i" (iterations) missing');
			$options['iterations'] = (int)$mcf['params']['i'];
		} else {
			$options['iterations'] = isset($mcf['params']['i']) ? (int)$mcf['params']['i'] : 0;
		}

		return array(
			"algo" => PASSWORD_VTS_MCF1,
			"algoName" => "vts-mcf-v1",
			"options" => $options
		);
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V1.'$')) {
		// PASSWORD_VTS_MHA1
		$mcf = crypt_modular_format_decode($hash);

		//$options['salt_length'] = strlen($mcf['salt']);  // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()

		if (!isset($mcf['params']['a'])) throw new Exception('Param "a" (algo) missing');
		$options['algo'] = $mcf['params']['a'];

		if (!isset($mcf['params']['i'])) throw new Exception('Param "i" (iterations) missing');
		$options['iterations'] = (int)$mcf['params']['i'];

		return array(
			"algo" => PASSWORD_VTS_MHA1,
			"algoName" => "vts-mha-v1",
			"options" => $options
		);
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V2.'$')) {
		// PASSWORD_VTS_MHA2
		$mcf = crypt_modular_format_decode($hash);

		//$options['salt_length'] = strlen($mcf['salt']);  // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()

		if (!isset($mcf['params']['a'])) throw new Exception('Param "a" (algo) missing');
		$options['algo'] = $mcf['params']['a'];

		if (!isset($mcf['params']['i'])) throw new Exception('Param "i" (iterations) missing');
		$options['iterations'] = (int)$mcf['params']['i'];

		return array(
			"algo" => PASSWORD_VTS_MHA2,
			"algoName" => "vts-mha-v2",
			"options" => $options
		);
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V3.'$')) {
		// PASSWORD_VTS_MHA3
		$mcf = crypt_modular_format_decode($hash);

		//$options['salt_length'] = strlen($mcf['salt']);  // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()

		if (!isset($mcf['params']['a'])) throw new Exception('Param "a" (algo) missing');
		$options['algo'] = $mcf['params']['a'];

		if (!isset($mcf['params']['l'])) throw new Exception('Param "l" (length) missing');
		$options['length'] = $mcf['params']['l'];

		if (!isset($mcf['params']['i'])) throw new Exception('Param "i" (iterations) missing');
		$options['iterations'] = (int)$mcf['params']['i'];

		return array(
			"algo" => PASSWORD_VTS_MHA3,
			"algoName" => "vts-mha-v3",
			"options" => $options
		);
	} else if (str_starts_with($hash, '$3$')) {
		// NTLM
		$mcf = crypt_modular_format_decode($hash);

		return array(
			"algo" => PASSWORD_NTLM,
			"algoName" => "ntlm",
			"options" => $options
		);
	} else if (str_starts_with($hash, '$apr1$')) {
		// APR MD5
		$mcf = crypt_modular_format_decode($hash);

		return array(
			"algo" => PASSWORD_APR_MD5,
			"algoName" => "apr1",
			"options" => $options
		);
	} else if (!str_starts_with($hash, '$') && (strlen($hash) == 13)) {
		// PASSWORD_STD_DES
		return array(
			"algo" => PASSWORD_STD_DES,
			"algoName" => "std-des",
			"options" => array(
				// None
			)
		);
	} else if (str_starts_with($hash, '_') && (strlen($hash) == 20)) {
		// PASSWORD_EXT_DES
		return array(
			"algo" => PASSWORD_EXT_DES,
			"algoName" => "ext-des",
			"options" => array(
				"iterations" => (int)base64_int_decode(substr($hash,1,4))
			)
		);
	} else if (str_starts_with($hash, '$1$')) {
		// PASSWORD_MD5
		return array(
			"algo" => PASSWORD_MD5,
			"algoName" => "md5",
			"options" => array(
				// None
			)
		);
	} else if (str_starts_with($hash, '$2$')  || str_starts_with($hash, '$2a$') || str_starts_with($hash, '$2b$') ||
	           str_starts_with($hash, '$2x$') || str_starts_with($hash, '$2y$')) {
		// PASSWORD_BLOWFISH
		return array(
			"algo" => PASSWORD_BLOWFISH,
			"algoName" => "blowfish",
			"options" => array(
				"cost" => (int)ltrim(explode('$',$hash)[2],'0')
			)
		);
	} else if (str_starts_with($hash, '$5$')) {
		// PASSWORD_SHA256
		return array(
			"algo" => PASSWORD_SHA256,
			"algoName" => "sha256",
			"options" => array(
				'rounds' => (int)str_replace('rounds=','',explode('$',$hash)[2])
			)
		);
	} else if (str_starts_with($hash, '$6$')) {
		// PASSWORD_SHA512
		return array(
			"algo" => PASSWORD_SHA512,
			"algoName" => "sha512",
			"options" => array(
				'rounds' => (int)str_replace('rounds=','',explode('$',$hash)[2])
			)
		);
	} else {
		// PASSWORD_DEFAULT
		// PASSWORD_BCRYPT
		// PASSWORD_ARGON2I
		// PASSWORD_ARGON2ID
		return password_get_info($hash);
	}
}

/**
 * This function extends password_hash() with the algorithms supported by crypt().
 * It also adds vts_mcf*_hash() which implements the ViaThinkSoft Modular Crypt Format.
 * The result can be verified using vts_password_verify().
 * @param string $password to be hashed
 * @param mixed $algo algorithm
 * @param array $options options for the hashing algorithm
 * @return string Crypt style password hash
 */
function vts_password_hash($password, $algo, $options=array()): string {
	$options = vts_password_fill_default_options($algo, $options);

	$crypt_salt = null;
	if (($algo === PASSWORD_STD_DES) && defined('CRYPT_STD_DES')) {
		// Standard DES-based hash with a two character salt from the alphabet "./0-9A-Za-z". Using invalid characters in the salt will cause crypt() to fail.
		$crypt_salt = des_compat_salt(2);
	} else if (($algo === PASSWORD_EXT_DES) && defined('CRYPT_EXT_DES')) {
		// Extended DES-based hash. The "salt" is a 9-character string consisting of an underscore followed by 4 characters of iteration count and 4 characters of salt. Each of these 4-character strings encode 24 bits, least significant character first. The values 0 to 63 are encoded as ./0-9A-Za-z. Using invalid characters in the salt will cause crypt() to fail.
		$iterations = $options['iterations'];
		$crypt_salt = '_' . base64_int_encode($iterations,4) . des_compat_salt(4);
	} else if (($algo === PASSWORD_MD5) && defined('CRYPT_MD5')) {
		// MD5 hashing with a twelve character salt starting with $1$
		$crypt_salt = '$1$'.des_compat_salt(12).'$';
	} else if (($algo === PASSWORD_BLOWFISH) && defined('CRYPT_BLOWFISH')) {
		// Blowfish hashing with a salt as follows: "$2a$", "$2b"$, "$2x$", or "$2y$", a two digit cost parameter, "$", and 22 characters from the alphabet "./0-9A-Za-z". Using characters outside of this range in the salt will cause crypt() to return a zero-length string. The two digit cost parameter is the base-2 logarithm of the iteration count for the underlying Blowfish-based hashing algorithm and must be in range 04-31, values outside this range will cause crypt() to fail. "$2x$" hashes are potentially weak; "$2a$" hashes are compatible and mitigate this weakness. For new hashes, "$2y$" should be used.
		// Note: "$2$" is not implemented in PHP
		$algo = '$2y$'; // most secure
		$cost = $options['cost'];
		$crypt_salt = $algo.str_pad($cost,2,'0',STR_PAD_LEFT).'$'.des_compat_salt(22).'$';
	} else if (($algo === PASSWORD_SHA256) && defined('CRYPT_SHA256')) {
		// SHA-256 hash with a sixteen character salt prefixed with $5$. If the salt string starts with 'rounds=<N>$', the numeric value of N is used to indicate how many times the hashing loop should be executed, much like the cost parameter on Blowfish. The default number of rounds is 5000, there is a minimum of 1000 and a maximum of 999,999,999. Any selection of N outside this range will be truncated to the nearest limit.
		$algo = '$5$';
		$rounds = $options['rounds'];
		$crypt_salt = $algo.'rounds='.$rounds.'$'.des_compat_salt(16).'$';
	} else if (($algo === PASSWORD_SHA512) && defined('CRYPT_SHA512')) {
		// SHA-512 hash with a sixteen character salt prefixed with $6$. If the salt string starts with 'rounds=<N>$', the numeric value of N is used to indicate how many times the hashing loop should be executed, much like the cost parameter on Blowfish. The default number of rounds is 5000, there is a minimum of 1000 and a maximum of 999,999,999. Any selection of N outside this range will be truncated to the nearest limit.
		$algo = '$6$';
		$rounds = $options['rounds'];
		$crypt_salt = $algo.'rounds='.$rounds.'$'.des_compat_salt(16).'$';
	}

	if (!is_null($crypt_salt)) {
		// Algorithms: PASSWORD_STD_DES
		//             PASSWORD_EXT_DES
		//             PASSWORD_MD5
		//             PASSWORD_BLOWFISH
		//             PASSWORD_SHA256
		//             PASSWORD_SHA512
		$out = crypt($password, $crypt_salt);
		if (strlen($out) < 13) throw new Exception("crypt() failed");
		return $out;
	} else if ($algo === PASSWORD_VTS_MCF1) {
		// Algorithms: PASSWORD_VTS_MCF1
		$algo = $options['algo'];
		$algo_internal = $options['algo-internal'] ?? $options['algo'];
		$mode = $options['mode'];
		$iterations = $options['iterations'];
		$salt_len = isset($options['salt_length']) ? $options['salt_length'] : 32; // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()
		$salt = random_bytes_ex($salt_len, true, true);
		return vts_mcf1_hash($algo, $algo_internal, $password, $salt, $mode, $iterations);
	} else if ($algo === PASSWORD_VTS_MHA1) {
		// Algorithms: PASSWORD_VTS_MHA1
		$base_algo = $options['algo'];
		$iterations = $options['iterations'];
		$salt_len = isset($options['salt_length']) ? $options['salt_length'] : 32; // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()
		$salt = random_bytes_ex($salt_len, true, true);
		return vts_mha1_hash($password, $salt, $iterations, $base_algo);
	} else if ($algo === PASSWORD_VTS_MHA2) {
		// Algorithms: PASSWORD_VTS_MHA2
		$base_algo = $options['algo'];
		$iterations = $options['iterations'];
		$salt_len = isset($options['salt_length']) ? $options['salt_length'] : 32; // Note: salt_length is not an MCF option! It's just a hint for vts_password_hash()
		$salt = random_bytes_ex($salt_len, true, true);
		return vts_mha2_hash($password, $salt, $iterations, $base_algo);
	} else if ($algo === PASSWORD_VTS_MHA3) {
		// Algorithms: PASSWORD_VTS_MHA3
		$base_algo = $options['algo'];
		$iterations = $options['iterations'];
		$length = $options['length'];
		return vts_mha3_hash($password, $length, $iterations, $base_algo);
	} else if ($algo === PASSWORD_NTLM) {
		// Algorithms: PASSWORD_NTLM
		return ntlm_hash($password);
	} else if ($algo === PASSWORD_APR_MD5) {
		// Algorithms: PASSWORD_APR_MD5
		return apr1_hash($password); // $salt_binary=null means that the salt is auto-generated
	} else {
		// Algorithms: PASSWORD_DEFAULT (Currently defaults to PASSWORD_BCRYPT)
		//             PASSWORD_BCRYPT
		//             PASSWORD_ARGON2I
		//             PASSWORD_ARGON2ID
		return password_hash($password, $algo, $options);
	}
}

/**
 * This function replaces password_needs_rehash() by adding additional algorithms
 * supported by vts_password_hash().
 * @param string $hash The current hash
 * @param string|int|null $algo Desired new default algo
 * @param array $options Desired new default options
 * @return bool True if algo or options of the current hash don't match the current desired values ($algo and $options), otherwise false.
 */
function vts_password_needs_rehash($hash, $algo, $options=array()) {
	$options = vts_password_fill_default_options($algo, $options);

	$info = vts_password_get_info($hash);
	$algo2 = $info['algo'];
	$options2 = $info['options'];

	// Check if algorithm matches
	if ($algo !== $algo2) return true;

	if (str_starts_with($hash, '$'.OID_MCF_VTS_V1.'$')) {

		if (($options['algo-internal']??"") == $options['algo']) unset($options['algo-internal']);
		if (($options2['algo-internal']??"") == $options2['algo']) unset($options2['algo-internal']);

		if (isset($options['salt_length'])) {
			// For VTS MCF 1.0, salt_length is a valid option for vts_password_hash(),
			// but it is not a valid option inside the MCF options
			// and it is not a valid option for vts_password_get_info().
			unset($options['salt_length']);
		}

		// For PBKDF2, iterations=0 means: Default, depending on the algo
		if (($options['iterations'] == 0/*default*/) && str_starts_with($options2['mode'], 'pbkdf2')) {
			$algo = $options2['algo'];
			//$algo_internal = $options2['algo-internal'] ?? $options2['algo'];
			$userland = !hash_pbkdf2_supported_natively($algo) && str_starts_with($algo, 'sha3-') && method_exists('\bb\Sha3\Sha3', 'hash_pbkdf2');
			$options['iterations'] = _vts_password_default_iterations($algo, $userland);
		}
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V1.'$')) {
		if (isset($options['salt_length'])) {
			// For VTS MHA 1.0, salt_length is a valid option for vts_password_hash(),
			// but it is not a valid option inside the MCF options
			// and it is not a valid option for vts_password_get_info().
			unset($options['salt_length']);
		}
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V2.'$')) {
		if (isset($options['salt_length'])) {
			// For VTS MHA 1.0, salt_length is a valid option for vts_password_hash(),
			// but it is not a valid option inside the MCF options
			// and it is not a valid option for vts_password_get_info().
			unset($options['salt_length']);
		}
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V3.'$')) {
		// MHA3 has no salt, hence no salt length option which needs to be removed
	} else if (str_starts_with($hash, '$3$')) {
		// NTLM has no parameters, so it does not need a rehash
		return false;
	} else if (str_starts_with($hash, '$apr1$')) {
		// APR MD5 has no parameters, so it does not need a rehash
		return false;
	}

	// Check if options match
	if (count($options) !== count($options2)) return true;
	foreach ($options as $name => $val) {
		if ($options2[$name] != $val) return true;
	}
	return false;
}

/**
 * This function extends password_verify() by adding ViaThinkSoft Modular Crypt Format 1.0.
 * @param string $password to be checked
 * @param string $hash Hash created by crypt(), password_hash(), or vts_password_hash().
 * @return bool true if password is valid
 */
function vts_password_verify($password, $hash): bool {
	if (str_starts_with($hash, '$'.OID_MCF_VTS_V1.'$')) {
		// Hash created by vts_password_hash(), or vts_mcf1_hash()
		return vts_mcf1_verify($password, $hash);
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V1.'$')) {
		// Hash created by vts_password_hash(), or vts_mha1_hash()
		return vts_mha1_verify($password, $hash);
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V2.'$')) {
		// Hash created by vts_password_hash(), or vts_mha2_hash()
		return vts_mha2_verify($password, $hash);
	} else if (str_starts_with($hash, '$'.OID_MHA_VTS_V3.'$')) {
		// Hash created by vts_password_hash(), or vts_mha3_hash()
		return vts_mha3_verify($password, $hash);
	} else if (str_starts_with($hash, '$3$')) {
		// Hash created by vts_password_hash()
		return ntlm_verify($password, $hash);
	} else if (str_starts_with($hash, '$apr1$')) {
		// Hash created by vts_password_hash()
		return apr1_verify($password, $hash);
	} else {
		// Hash created by vts_password_hash(), password_hash(), or crypt()
		return password_verify($password, $hash);
	}
}

// --- Part 4: Functions which include a fallback to a pure-PHP sha3 implementation (requires https://github.com/danielmarschall/php-sha3 )

function hash_ex($algo, $data, $binary=false, $options=array()) {
	if (!hash_supported_natively($algo) && str_starts_with($algo, 'sha3-') && method_exists('\bb\Sha3\Sha3', 'hash')) {
		$bits = (int)explode('-',$algo)[1];
		$hash = \bb\Sha3\Sha3::hash($data, $bits, $binary);
	} else {
		$hash = hash($algo, $data, $binary);
	}
	return $hash;
}

function hash_hmac_ex($algo, $data, $key, $binary=false) {
	if (!hash_hmac_supported_natively($algo) && str_starts_with($algo, 'sha3-') && method_exists('\bb\Sha3\Sha3', 'hash_hmac')) {
		$bits = (int)explode('-',$algo)[1];
		$hash = \bb\Sha3\Sha3::hash_hmac($data, $key, $bits, $binary);
	} else {
		$hash = hash_hmac($algo, $data, $key, $binary);
	}
	return $hash;
}

function hash_pbkdf2_ex($algo, $password, $salt, &$iterations=0, $length=0, $binary=false) {
	if (!hash_pbkdf2_supported_natively($algo) && str_starts_with($algo, 'sha3-') && method_exists('\bb\Sha3\Sha3', 'hash_pbkdf2')) {
		if ($iterations == 0/*default*/) {
			$iterations = _vts_password_default_iterations($algo, true);
		}
		$bits = (int)explode('-',$algo)[1];
		$hash = \bb\Sha3\Sha3::hash_pbkdf2($password, $salt, $iterations, $bits, $length, $binary);
	} else {
		if ($iterations == 0/*default*/) {
			$iterations = _vts_password_default_iterations($algo, false);
		}
		$hash = hash_pbkdf2($algo, $password, $salt, $iterations, $length, $binary);
	}
	return $hash;
}

// --- Part 5: Useful functions required by the crypt-functions

function des_compat_salt($salt_len) {
	if ($salt_len <= 0) return '';
	$characters = BASE64_CRYPT_ALPHABET;
	$salt = '';
	$bytes = random_bytes_ex($salt_len, true, true);
	for ($i=0; $i<$salt_len; $i++) {
		$salt .= $characters[ord($bytes[$i]) % strlen($characters)];
	}
	return $salt;
}

function base64_int_encode($num, $len) {
	// https://stackoverflow.com/questions/15534982/which-iteration-rules-apply-on-crypt-using-crypt-ext-des
	$alphabet_raw = BASE64_CRYPT_ALPHABET;
	$alphabet = str_split($alphabet_raw);
	$arr = array();
	$base = sizeof($alphabet);
	while ($num) {
		$rem = $num % $base;
		$num = (int)($num / $base);
		$arr[] = $alphabet[$rem];
	}
	$string = implode($arr);
	return str_pad($string, $len, '.', STR_PAD_RIGHT);
}

function base64_int_decode($base64) {
	$num = 0;
	for ($i=strlen($base64)-1;$i>=0;$i--) {
		$num += strpos(BASE64_CRYPT_ALPHABET, $base64[$i])*pow(strlen(BASE64_CRYPT_ALPHABET),$i);
	}
	return $num;
}

function crypt_radix64_encode($str) {
	$x = $str;
	$x = base64_encode($x);
	$x = rtrim($x, '='); // remove padding
	$x = strtr($x, BASE64_RFC4648_ALPHABET, BASE64_CRYPT_ALPHABET);
	return $x;
}

function crypt_radix64_decode($str) {
	$x = $str;
	$x = strtr($x, BASE64_CRYPT_ALPHABET, BASE64_RFC4648_ALPHABET);
	$x = base64_decode($x);
	return $x;
}

function hash_supported_natively($algo) {
	if (version_compare(PHP_VERSION, '5.1.2') >= 0) {
		return in_array($algo, hash_algos());
	} else {
		return false;
	}
}

function hash_hmac_supported_natively($algo): bool {
	if (version_compare(PHP_VERSION, '7.2.0') >= 0) {
		return in_array($algo, hash_hmac_algos());
	} else if (version_compare(PHP_VERSION, '5.1.2') >= 0) {
		return in_array($algo, hash_algos());
	} else {
		return false;
	}
}

function hash_pbkdf2_supported_natively($algo) {
	return hash_supported_natively($algo);
}

function vts_password_fill_default_options($algo, $options) {
	if ($algo === PASSWORD_STD_DES) {
		// No options
	} else if ($algo === PASSWORD_EXT_DES) {
		if (!isset($options['iterations'])) {
			$options['iterations'] = PASSWORD_EXT_DES_DEFAULT_ITERATIONS;
		}
	} else if ($algo === PASSWORD_MD5) {
		// No options
	} else if ($algo === PASSWORD_BLOWFISH) {
		if (!isset($options['cost'])) {
			$options['cost'] = PASSWORD_BLOWFISH_DEFAULT_COST;
		}
	} else if ($algo === PASSWORD_SHA256) {
		if (!isset($options['rounds'])) {
			$options['rounds'] = PASSWORD_SHA256_DEFAULT_ROUNDS;
		}
	} else if ($algo === PASSWORD_SHA512) {
		if (!isset($options['rounds'])) {
			$options['rounds'] = PASSWORD_SHA512_DEFAULT_ROUNDS;
		}
	} else if ($algo === PASSWORD_VTS_MCF1) {
		if (!isset($options['algo'])) {
			$options['algo'] = PASSWORD_VTS_MCF1_DEFAULT_ALGO;
		}
		if (!isset($options['mode'])) {
			$options['mode'] = PASSWORD_VTS_MCF1_DEFAULT_MODE;
		}
		if (str_starts_with($options['mode'], 'pbkdf2')) {
			if (!isset($options['iterations'])) {
				$options['iterations'] = PASSWORD_VTS_MCF1_DEFAULT_ITERATIONS;
			}
		} else {
			$options['iterations'] = isset($options['iterations']) ? $options['iterations'] : 0;
		}
	} else if ($algo === PASSWORD_VTS_MHA1) {
		if (!isset($options['iterations'])) {
			$options['iterations'] = PASSWORD_VTS_MHA1_DEFAULT_ITERATIONS;
		}
		if (!isset($options['algo'])) {
			$options['algo'] = PASSWORD_VTS_MHA1_DEFAULT_BASE_ALGO;
		}
	} else if ($algo === PASSWORD_VTS_MHA2) {
		if (!isset($options['iterations'])) {
			$options['iterations'] = PASSWORD_VTS_MHA2_DEFAULT_ITERATIONS;
		}
		if (!isset($options['algo'])) {
			$options['algo'] = PASSWORD_VTS_MHA2_DEFAULT_BASE_ALGO;
		}
	} else if ($algo === PASSWORD_VTS_MHA3) {
		if (!isset($options['iterations'])) {
			$options['iterations'] = PASSWORD_VTS_MHA3_DEFAULT_ITERATIONS;
		}
		if (!isset($options['length'])) {
			$options['length'] = PASSWORD_VTS_MHA3_DEFAULT_LENGTH;
		}
		if (!isset($options['algo'])) {
			$options['algo'] = PASSWORD_VTS_MHA3_DEFAULT_BASE_ALGO;
		}
	}
	return $options;
}

function _vts_password_default_iterations($algo, $userland) {
	if ($userland) {
		return 100; // because the userland implementation is EXTREMELY slow, we must choose a small value, sorry...
	} else {
		// Recommendations taken from https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
		// Note that hash_pbkdf2() implements PBKDF2-HMAC-*
		if      ($algo == 'sha3-512')    return  100000;
		else if ($algo == 'sha3-384')    return  100000;
		else if ($algo == 'sha3-256')    return  100000;
		else if ($algo == 'sha3-224')    return  100000;
		else if ($algo == 'sha512')      return  210000; // value by owasp.org cheatsheet (28 February 2023)
		else if ($algo == 'sha512/256')  return  210000; // value by owasp.org cheatsheet (28 February 2023)
		else if ($algo == 'sha512/224')  return  210000; // value by owasp.org cheatsheet (28 February 2023)
		else if ($algo == 'sha384')      return  600000;
		else if ($algo == 'sha256')      return  600000; // value by owasp.org cheatsheet (28 February 2023)
		else if ($algo == 'sha224')      return  600000;
		else if ($algo == 'sha1')        return 1300000; // value by owasp.org cheatsheet (28 February 2023)
		else if ($algo == 'md5')         return 5000000;
		else                             return    5000;
	}
}

// --- Part 6: Selftest

/*
for ($i=0; $i<9999; $i++) {
	assert($i===base64_int_decode(base64_int_encode($i,4)));
}

$rnd = random_bytes_ex(50, true, true);
assert(crypt_radix64_decode(crypt_radix64_encode($rnd)) === $rnd);

$password = random_bytes_ex(20, false, true);

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_STD_DES)));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_EXT_DES)));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_MD5)));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_BLOWFISH)));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_SHA256)));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_SHA512)));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));

// --- MCF 1.0

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'pbkdf2',
	'iterations' => 0
))));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));
assert(false===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 51,
	'algo' => 'sha3-512',
	'mode' => 'pbkdf2',
	'iterations' => 0
)));
assert(true===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 50,
	'algo' => 'sha3-256',
	'mode' => 'pbkdf2',
	'iterations' => 0
)));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'sps',
	'iterations' => 2
))));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));
assert(false===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 51,
	'algo' => 'sha3-512',
	'mode' => 'sps',
	'iterations' => 2
)));
assert(true===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 50,
	'algo' => 'sha3-256',
	'mode' => 'sps',
	'iterations' => 2
)));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hmac',
	'iterations' => 2
))));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));
assert(false===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 51,
	'algo' => 'sha3-512',
	'mode' => 'hmac',
	'iterations' => 2
)));
assert(true===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 50,
	'algo' => 'sha3-256',
	'mode' => 'hmac',
	'iterations' => 2
)));

// --- MCF 1.1

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'pbkdf2[s;p]',
	'iterations' => 0
))));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));
assert(false===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 51,
	'algo' => 'sha3-512',
	'mode' => 'pbkdf2[s;p]',
	'iterations' => 0
)));
assert(true===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 50,
	'algo' => 'sha3-256',
	'mode' => 'pbkdf2[s;p]',
	'iterations' => 0
)));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[sps]',
	'iterations' => 2
))));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));
assert(false===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 51,
	'algo' => 'sha3-512',
	'mode' => 'hash[sps]',
	'iterations' => 2
)));
assert(true===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 50,
	'algo' => 'sha3-256',
	'mode' => 'hash[sps]',
	'iterations' => 2
)));

assert(vts_password_verify($password,$dummy = vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hmac[s;p]',
	'iterations' => 2
))));
//echo "'$dummy' ".strlen($dummy)."\n";
//var_dump(vts_password_get_info($dummy));
assert(false===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 51,
	'algo' => 'sha3-512',
	'mode' => 'hmac[s;p]',
	'iterations' => 2
)));
assert(true===vts_password_needs_rehash($dummy,PASSWORD_VTS_MCF1,array(
	'salt_length' => 50,
	'algo' => 'sha3-256',
	'mode' => 'hmac[s;p]',
	'iterations' => 2
)));

// --- MCF 1.0 == MCF 1.1 tests (requires i=0 for non-pbkdf2 modes)

assert(vts_password_verify($password,$dummy =
str_replace('hash[sp]','sp',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[sp]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hash[sp]','sp',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[sp]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('hash[ps]','ps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[ps]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hash[ps]','ps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[ps]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('hash[sps]','sps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[sps]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hash[sps]','sps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[sps]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('hash[shbx(p)]','shp',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[shbx(p)]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hash[shbx(p)]','shp',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[shbx(p)]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('hash[hbx(p)s]','hps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[hbx(p)s]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hash[hbx(p)s]','hps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[hbx(p)s]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('hash[shbx(p)s]','shps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[shbx(p)s]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hash[shbx(p)s]','shps',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hash[shbx(p)s]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('hmac[s;p]','hmac',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hmac[s;p]',
	'iterations' => 0
)))));
assert(!vts_password_verify($password,$dummy =
str_replace('hmac[s;p]','hmac',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'hmac[s;p]',
	'iterations' => 1
)))));

assert(vts_password_verify($password,$dummy =
str_replace('pbkdf2[s;p]','pbkdf2',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'pbkdf2[s;p]',
	'iterations' => 0
)))));
assert(vts_password_verify($password,$dummy =
str_replace('pbkdf2[s;p]','pbkdf2',
vts_password_hash($password, PASSWORD_VTS_MCF1, array(
	'algo' => 'sha3-512',
	'mode' => 'pbkdf2[s;p]',
	'iterations' => 1
)))));

// --- MHA 1
$hash = vts_password_hash('hello world', PASSWORD_VTS_MHA1, ['salt_length'=>0]);
assert(vts_password_verify('hello world', $hash));
assert(!vts_password_verify('hello world!', $hash));

// --- MHA 2
$hash = vts_password_hash('hello world', PASSWORD_VTS_MHA2, ['algo'=>'sha1', 'salt_length'=>0]);
assert(vts_password_verify('hello world', $hash));
assert(!vts_password_verify('hello world!', $hash));

// --- MHA 3
$hash = vts_password_hash('hello world', PASSWORD_VTS_MHA3);
assert(vts_password_verify('hello world', $hash));
assert(!vts_password_verify('hello world!', $hash));

// --- NTLM
$hash = vts_password_hash('hello world', PASSWORD_NTLM);
assert(vts_password_verify('hello world', $hash));
assert(!vts_password_verify('hello world!', $hash));

// --- htdigest
$hash = vts_password_hash('hello world', PASSWORD_APR_MD5);
assert(vts_password_verify('hello world', $hash));
assert(!vts_password_verify('hello world!', $hash));
*/
