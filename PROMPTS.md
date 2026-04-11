## 2026-04-10 08:27:10

I need to build a new tool.  Part of my job is understanding how dnssec keys are being used by BIND to sign zones and when certain events occur.  I need to use some niche pieces such as dnssec-policy with offline keys in BIND 9.18 and 9.20 and I need to manage keys with my own tool behind that.  I want this new tool to help me track events over the course of time (when keys change, when signing occurs, when deletions happen, DS deplyment / withdrawal, etc) and build reports showing the behavior of the keys over time under different scenarios.   Since it's DNSSEC the only real way to test is by waiting so the tool will need to run as a background process, preferably in a docker, constantly checking and logging the events as they occur and then letting me query it for a report about the keys.  I'd like this to all produce onto a webpage and also be exportable as a professionally looking test report capturing the relevant data and helping explain how different options affected the keys deployment

---

## 2026-04-11 06:25:59

Adjust the docker to use user 53:53 so that it will have the same permissions as the keys on the host system.  also make sure the key directory searches recursively below it key files are in /mnt/bind/keys/<zonename>/<file>.key.  I haven't been able to test but the documentation implies it's looking for the keys only in the root.

---

## 2026-04-11 06:27:47

misclick, continue

---

## 2026-04-11 06:38:19

Add a dark theme please

---

