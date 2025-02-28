# YaDa

YaDa is the [Yara](https://github.com/VirusTotal/yara) binary file decompiler, it currently supports Yara 3.4.0 and Yara 3.9.0.

It is inspired by the project [jbgalet/yaradec](https://github.com/jbgalet/yaradec), which disassembles yara rule into bytecode.

## Usage
```sh
./yada.py <yara_rule_binary>
```

* Example
```
$ ./yada.py testcase/RARsilence.yac

rule default:APT1_RARSilent_EXE_PDF {
        // ptr = 3feb
        meta:
                author = "AlienVault Labs"
                info = "CommentCrew-threat-apt1"
        strings:
        /*0x41ef*/      $winrar1 = "WINRAR.SFX" wide ascii
        /*0x471f*/      $str2 = "Steup=" wide ascii
        condition:
                all of them
}


rule default:APT1_known_malicious_RARSilent {
        // ptr = 4097
        meta:
                author = "AlienVault Labs"
                info = "CommentCrew-threat-apt1"
        strings:
        /*0x517f*/      $str1 = "Analysis And Outlook.doc" wide ascii
        /*0x56af*/      $str2 = "North Korean launch.pdf" wide ascii
        /*0x5bdf*/      $str3 = "Dollar General.doc" wide ascii
        /*0x610f*/      $str4 = "Dow Corning Corp.pdf" wide ascii
        condition:
                (any of them) and APT1_RARSilent_EXE_PDF
}
```

You may also directly called into the decompiler API to embed the tool into your own script,
there are methods to output rules syntax tree in JSON and to output the bytecode.

Please refer to classes defined in `v11dec.py` and `v39dec.py`.

## Materials
If you are intrested in the implementation, YaDa is presented at [SECCON 13 Open Conference](https://www.seccon.jp/13/ep250301.html).

Slides:

I also submitted YaDa as my graduate school's project. You can get the report [here](https://drive.google.com/file/d/1IBZ9boTltduVgLBn66IU5It7lI5ULFc1/view?usp=sharing).


## Limitations
* Some complex regex could not be extracted in Yara 3.9.0
* module related functionalities is not supported
* `for ... of ... : condition` statement is not supported

## TODO (maybe):
* Support `for ... of ... : condition` structure
* Improve the support of complex regular expression
* Reduce the repetition structure in regular expressions
* Use wildcard to show same prefix variables
* Support other versions
* Rewrite in other languages

## License
MIT License
