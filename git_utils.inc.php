<?php

/*
 * PHP git functions
 * Copyright 2021 Daniel Marschall, ViaThinkSoft
 * Revision 2021-12-29
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

function git_get_latest_commit_message($git_dir) {
	// First try an official git client
	$cmd = "git --git-dir=".escapeshellarg("$git_dir")." log -1 2>&1";
	$ec = -1;
	$out = array();
	@exec($cmd, $out, $ec);
	$out = implode("\n",$out);
	if (($ec == 0) && ($out != '')) return $out;

	// If that failed, try to decode the binary files outselves
	$cont = @file_get_contents($git_dir.'/HEAD');
	if (preg_match('@ref: (.+)[\r\n]@', "$cont\n", $m) && file_exists($git_dir.'/'.$m[1])) {
		// Example content of a .git folder file:
		// 091a5fa6b157be035e88f5d24aa329ba44d20d63
		// Not available
		$commit_object = trim(file_get_contents($git_dir.'/'.$m[1]));
	} else if (file_exists($git_dir.'/refs/heads/master')) {
		// Missing at Plesk Git initial checkout, but available on update.
		$commit_object = trim(file_get_contents($git_dir.'/refs/heads/master'));
	} else if (file_exists($git_dir.'/FETCH_HEAD')) {
		// Example content of a Plesk Git folder (fresh):
		// 091a5fa6b157be035e88f5d24aa329ba44d20d63	not-for-merge	branch 'master' of https://github.com/danielmarschall/oidplus
		// 091a5fa6b157be035e88f5d24aa329ba44d20d63	not-for-merge	remote-tracking branch 'origin/trunk' of https://github.com/danielmarschall/oidplus
		$cont = file_get_contents($git_dir.'/FETCH_HEAD');
		$commit_object = substr(trim($cont),0,40);
	} else {
		throw new Exception("Cannot detect last commit object");
	}

	$objects_dir = $git_dir . '/objects';


	// Sometimes, objects are uncompressed, sometimes compressed in a pack file
	// Plesk initial checkout is compressed, but pulls via web interface
	// save uncompressed files

	$uncompressed_file = $objects_dir . '/' . substr($commit_object,0,2) . '/' . substr($commit_object,2);
	if (file_exists($uncompressed_file)) {
		// Read compressed data
		$compressed = file_get_contents($uncompressed_file);

		// Uncompress
		$uncompressed = @gzuncompress($compressed);
		if ($uncompressed === false) throw new Exception("Decompression failed");

		// The format is "commit <nnn>\0<Message>" where <nnn> is only a 3 digit number?!
		$ary = explode(chr(0), $uncompressed);
		$uncompressed = array_pop($ary);

		return $uncompressed;
	} else {
		$pack_files = @glob($objects_dir.'/pack/pack-*.pack');
		$last_exception = 'No pack files found';
		if ($pack_files) foreach ($pack_files as $basename) {
			$basename = substr(basename($basename),0,strlen(basename($basename))-5);
			try {
				return git_read_object($commit_object,
					$objects_dir.'/pack/'.$basename.'.idx',
					$objects_dir.'/pack/'.$basename.'.pack',
					false
				);
			} catch (Exception $e) {
				$last_exception = $e;
			}
		}
		throw new Exception($last_exception);
	}
}

function git_read_object($object_wanted, $idx_file, $pack_file, $debug=false) {
	// More info about the IDX and PACK format: https://git-scm.com/docs/pack-format

	// Do some checks
	if (!preg_match('/^[0-9a-fA-F]{40}$/', $object_wanted, $m)) throw new Exception("Is not a valid object: $object_wanted");
	if (!file_exists($idx_file)) throw new Exception("Idx file $idx_file not found");
	if (!file_exists($pack_file)) throw new Exception("Pack file $pack_file not found");

	// Open index file
	$fp = fopen($idx_file, 'rb');
	if (!$fp) throw new Exception("Cannot open index file $idx_file");

	// Read version
	fseek($fp, 0);
	$unpacked = unpack('N', fread($fp, 4)); // vorzeichenloser Long-Typ (immer 32 Bit, Byte-Folge Big-Endian)
	if ($unpacked[1] === 0xFF744F63) {
		$version = unpack('N', fread($fp, 4))[1]; // vorzeichenloser Long-Typ (immer 32 Bit, Byte-Folge Big-Endian)
		$fanout_offset = 8;
		if ($version != 2) throw new Exception("Version $version unknown");
	} else {
		$version = 1;
		$fanout_offset = 0;
	}
	if ($debug) echo "Index file version = $version\n";

	// Read fanout table
	fseek($fp, $fanout_offset);
	$fanout_ary[0] = 0;
	$fanout_ary = unpack('N*', fread($fp, 4*256));
	$num_objects = $fanout_ary[256];

	// Find out approximate object number (from fanout table)
	$fanout_index = hexdec(substr($object_wanted,0,2));
	if ($debug) echo "Fanout index = ".($fanout_index-1)."\n";
	$object_no = $fanout_ary[$fanout_index]; // approximate
	if ($debug) echo "Object no approx $object_no\n";

	// Find the exact object number
	fseek($fp, $fanout_offset + 4*256 + 20*$object_no);
	$object_no--;
	$pack_offset = -1; // avoid that phpstan complains
	do {
		$object_no++;
		if ($version == 1) {
			$pack_offset = fread($fp, 4);
		}
		$binary = fread($fp, 20);
		if (substr(bin2hex($binary),0,2) != substr(strtolower($object_wanted),0,2)) {
			throw new Exception("Object $object_wanted not found");
		}
	} while (bin2hex($binary) != strtolower($object_wanted));
	if ($debug) echo "Exact object no = $object_no\n";

	if ($version == 2) {
		// Get CRC32
		fseek($fp, $fanout_offset + 4*256 + 20*$num_objects + 4*$object_no);
		$crc32 = unpack('N', fread($fp,4))[1];
		if ($debug) echo "CRC32 = ".sprintf('0x%08x',$crc32)."\n";

		// Get offset (32 bit)
		fseek($fp, $fanout_offset + 4*256 + 20*$num_objects + 4*$num_objects + 4*$object_no);
		$offset_info = unpack('N', fread($fp,4))[1];
		if ($offset_info >= 0x80000000) {
			// MSB set, so the offset is 64 bit
			if ($debug) echo "64 bit pack offset\n";
			$offset_info &= 0x7FFFFFFF;
			fseek($fp, $fanout_offset + 4*256 + 20*$num_objects + 4*$num_objects + 4*$num_objects + 8*$offset_info);
			$pack_offset = unpack('J', fread($fp,8))[1];
		} else {
			// MSB is not set, so the offset is 32 bit
			if ($debug) echo "32 bit pack offset\n";
			$offset_info &= 0x7FFFFFFF;
			$pack_offset = $offset_info;
		}
	}

	if ($debug) echo "Pack file offset = ".sprintf('0x%x',$pack_offset)."\n";

	// Close index file
	fclose($fp);

	// Open pack file
	$fp = fopen($pack_file, 'rb');
	if (!$fp) throw new Exception("Cannot open pack file $pack_file");

	// Find out type
	fseek($fp, $pack_offset);
	$size_info = unpack('C', fread($fp,1))[1];

	$type = ($size_info & 0xE0) >> 5; /*0b11100000*/
	switch ($type) {
		case 1:
			if ($debug) echo "Type = OBJ_COMMIT ($type)\n";
			break;
		case 2:
			if ($debug) echo "Type = OBJ_TREE ($type)\n";
			break;
		case 3:
			if ($debug) echo "Type = OBJ_BLOB ($type)\n";
			break;
		case 4:
			if ($debug) echo "Type = OBJ_TAG ($type)\n";
			break;
		case 6:
			if ($debug) echo "Type = OBJ_OFS_DELTA ($type)\n";
			break;
		case 7:
			if ($debug) echo "Type = OBJ_REF_DELTA ($type)\n";
			break;
		default:
			if ($debug) echo "Type = Invalid ($type)\n";
			break;
	}

	// Find out size
	$size = $size_info & 0x1F /*0x00011111*/;
	$shift_info = 5;
	do {
		$size_info = unpack('C', fread($fp,1))[1];
		$size = (($size_info & 0x7F) << $shift_info) + $size;
		$shift_info += 8;
	} while ($size_info >= 0x80);

	if ($debug) echo "Packed size = ".sprintf('0x%x',$size)."\n";

	// Read delta base type
	if ($type == 6/*OBJ_OFS_DELTA*/) {
		// "a negative relative offset from the delta object's position in the pack
		// if this is an OBJ_OFS_DELTA object"
		$delta_info = unpack('C*', fread($fp,4))[1]; // TODO?!
		if ($debug) echo "Delta negative offset: $delta_info\n";
	}
	if ($type == 7/*OBJ_REF_DELTA*/) {
		// "base object name if OBJ_REF_DELTA"
		$delta_info = bin2hex(fread($fp,20))[1]; // TODO?!
		if ($debug) echo "Delta base object name: $delta_info\n";
	}

	// Read compressed data
	$compressed = fread($fp,$size);

	// Uncompress
	$uncompressed = @gzuncompress($compressed);
	if ($uncompressed === false) throw new Exception("Decompression failed");
	if ($debug) echo "$uncompressed\n";

	// Close pack file
	fclose($fp);

	// Check CRC32
	// TODO: Does not fit; neither crc32, nor crc32b...
	// if ($debug) echo "CRC32 found = 0x".hash('crc32',$compressed)."\n";

	return $uncompressed;
}
