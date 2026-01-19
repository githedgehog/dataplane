def rate_icon:
    . as $score |
    if $score >= 9.0 then ":fire:"
    elif $score >= 8.0 then ":rotating_light:"
    elif $score >= 6.0 then ":warning:"
    elif $score >= 4.0 then ":orange_circle:"
    elif $score >= 3.0 then ":yellow_circle:"
    else ":white_square_button:"
    end
;

def md_for_cve(cve; prog):
    "### " + (prog.cvssv3_basescore[cve] | rate_icon) + "[" + cve + "](https://nvd.nist.gov/vuln/detail/" + cve + ")\n" +
    "\n" +
    "| Package | Version | CVSSv3 |\n" +
    "|:--------|:--------|:-------|\n" +
    "| " + prog.pname + " | " + (prog.version | tostring) + " | " + (prog.cvssv3_basescore[cve] | tostring) + " |\n" +
    "\n" +
    if ($acks[][cve]?.description) then (
        $acks[][cve].description
    ) else (
        prog.description[cve]
    ) end +
    "\n\n" +
    if ($acks[][cve].note) then (
       "#### Impact on Hedgehog Dataplane\n" +
       "\n" +
       $acks[][cve].note +
       "\n"
    ) else (
        ""
    ) end
;

def all_cves:
    . as $stream |
    if ($stream == null) then [] else $stream end |
    $stream[] as $prog |
    $prog.affected_by as $cves |
    $cves[] |
    { cve: ., prog: $prog }
;

def main:
    . as $input |
    [$input | all_cves] | sort_by(.prog.cvssv3_basescore[.cve]) | reverse | map({ key: .cve, value: .prog}) as $all_cves |
    $all_cves | map(select(.key | in($acks[]) | not)) as $new_cves |
    $all_cves | map(select(.key | in($acks[]))) as $acked_cves |
    "# Security Scan\n\n" +
    (now | todate) + "\n\n" +
    if ($new_cves == []) then
        "## No newly reported CVEs\n\n"
    else
        "## Newly reported CVEs\n\n" +
        ($new_cves | map(md_for_cve(.key; .value)) | join("---\n\n"))
    end
    +
    if ($acked_cves == []) then
        "## No previously reported CVEs\n\n"
    else
        "## Previously reported CVEs\n\n" +
        ($acked_cves | map(md_for_cve(.key; .value)) | join("---\n\n"))
    end
;

main
