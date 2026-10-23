#!/bin/sh
# 7.3: run all three attempts against both client policies and print the matrix.
cd "$(dirname "$0")/.."
sh scripts/attempt1-tamper.sh
echo
sh scripts/attempt2-roguecert.sh
echo
sh scripts/attempt3-downgrade.sh
echo
cat <<'MATRIX'

================= 7.3 outcome matrix (does the attack land?) =================
 attempt                         | strict (refuses cleartext) | lax (permits cleartext)
---------------------------------+----------------------------+-------------------------
 (i)  alter answer in transit    | no  (TLS integrity)        | no  (TLS integrity)
 (ii) rogue-cert impersonation   | no  (cert not trusted)     | no  (cert not trusted)
 (iii) block transport, downgrade| no, fails closed (DoS)     | YES, forged to rogue
=============================================================================
Only (iii) against the lax client lands, and only because that client accepts a
cleartext fallback. The encryption and authentication did their job; the policy
that permitted cleartext is what reopened the Phase 2 forgery.
MATRIX
