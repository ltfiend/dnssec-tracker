"""Parsers for the artefacts dnssec-tracker watches.

- bind_state: BIND's K*.state files written by dnssec-policy
- bind_key: BIND's K*.key / K*.private files (timing comments)
- iodyn_syslog: iodyn-dnssec's tagged syslog lines
- named_log: BIND named log lines from the dnssec category
- rndc_status: output of `rndc dnssec -status <zone>`
"""
