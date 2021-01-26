# YaraDec #

yaradec is a simple yara-rules "decompiler"

## Limitations ##
* Regex are not extracted
* FAST_EXP_REGEXP with wildcards or placeholders are not extracted
* The "condition" is not reversed (Yet!)
* import is not supported
* for ... of ... : condition statement is not supported

## Usage ##
python3 yaradec.py <compiled_yara_rules>
