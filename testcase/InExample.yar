rule InExample
{
    strings:
        $a = "dummy1"
       $b = "dummy2"

    condition:
       $a in (0..100) and $b in (100..filesize)
}
