rule Rule01 {
meta:
	author = "Inndy"

strings:
	$a1 = "str1"
	$a2 = "str2"
	$a3 = /asdf.*zxcv{1,8}/
	$a4 = { aa bb cc dd [1-20] ee ff }

condition:
	any of them
}
// vim: ft=yara
