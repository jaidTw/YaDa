rule Rule01 {
meta:
	author = "Inndy"

strings:
	$a1  = "str1"
	$a2  = "str2"
	$a3  = /asdf.*zxcv{1,8}/
	$a4  = { aa bb cc dd [1-20] ee ff }
	$a5  = { 00 01 02 03 04 05 06 }
	$b1  = { 00 02 03 04 05 06 }
	$b2  = { 00 03 04 05 06 }
	$b3  = { 00 04 05 06 }
	$b4  = { 00 05 06 }
	$b5  = { 00 06 }
	$b6  = { 11 22 3? 44 [1-5] 65 77 ?9 11 ?? 33 ?? 44 55 66 }
	$b7  = { 00 00 ?? 06 [1-4] 11 [10-11] 33}

condition:
	(all of them) or (3 of them) and uint16(0) == 0x5a4d
}

rule Rule02 {
meta:
	author = "Inndy"
	meta_bool = false
	meta_int = 31415926

strings:
	$a1  = "str1"
	$a2  = "str2"
	$a3  = /asdf.*zxcv{1,8}/
	$a4  = { aa bb cc dd [1-20] ee ff }
	$a5  = { 00 01 02 03 04 05 06 }
	$b4  = { 00 05 06 }
	$b5  = { 00 [1-5] 06 07 08 09 0a [1-10] 0b 0c }
	$mz  = "MZ"

condition:
	(all of them) or ((3 of them) and $mz at 0)
}

// vim: ft=yara
