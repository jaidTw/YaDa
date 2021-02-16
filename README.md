# YaraDec

YaraDec is a simple yara-rules "decompiler"

## Supported Versions

YaraDec currently supports Yara 3.4.0 and Yara 3.9.0

## Limitations
* Some regex could not be extracted in Yara 3.9.0
* module related functionalities is not supported
* `for ... of ... : condition` statement is not supported

## TODO (maybe):
* Support `for ... of ... : condition` structure
* Improve the support of complex regular expression
* Reduce the repeat structure in regular expressions
* Use wildcard to show same prefix variables
* Support other versions

## Usage
./yaradec.py <compiled_yara_rules>
