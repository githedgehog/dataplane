def md_for_cve(cve; prog; acked):
    "### " + cve + "\n" +
    "\n" +
    "- **package**: " + prog.pname + " " + (prog.version | tostring) + "\n" +
    "- **CVSSv3**: " + (prog.cvssv3_basescore[cve] | tostring) + "\n\n" +
    prog.description[cve] +
    "\n\n" +
    (if (acked and $acks[][cve].note) then ("#### Notes\n\n" + $acks[][cve].note + "\n") else "" end)
    ;

. as $stream |
($stream | ([
 if ($stream == null) then [] else . end |
 .[] as $prog |
 $prog.affected_by? as $new |
 if ($new == []) then (
   null
 )
 else (
   $new[] as $cve | [ md_for_cve($cve; $prog; false) ]
 )
 end
]) as $unacked |
if (([$unacked[] | select(. != null)]) == []) then [["## No new CVEs reported by scan\n\n"]] else [["## Newly reported CVEs\n\n"]] + $unacked end)
+
($stream | ([
 if ($stream == null) then [] else . end |
 .[] as $prog |
 $prog.whitelisted? as $acked |
 if ($acked == []) then (
   null
 ) else (
   $acked[] as $cve | [ md_for_cve($cve; $prog; true) ]
 )
 end
]) as $acked |
if (([$acked[] | select(. != null)]) == []) then [["## No CVEs previously acknowledged\n\n"]] else [["## Acknowledged CVEs\n\n"]] + $acked end) |
add | join("-------------------------\n\n")
