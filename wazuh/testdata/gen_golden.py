"""Regenerates the case-extraction fixture and its expected output.

The expected output (cases_golden.json) is produced by the ORIGINAL
implementation, Thaki-Siem assess/events.py, so the Go port in
wazuh/cases.go is checked against it rather than against itself.

  python3 wazuh/testdata/gen_golden.py <THAKI_SIEM_DIR>

Every host, account and address below is synthetic. Rule ids that the
patterns hard-code (login success 5715/1009xx, exfil 100815) are real ids;
the 2000xx ids exist only in this fixture's catalog.
"""
import datetime as dt
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TODAY = "2026-11-16"
EXT, EXT2, EXT3 = "45.33.32.156", "45.33.32.200", "45.33.32.201"  # public addresses
alerts = []


def at(day, hh, mm=0, ss=0):
    return dt.datetime(2026, 11, day, hh, mm, ss)


def add(t, host, rule, level, desc, groups=(), **fields):
    doc = {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "agent": {"name": host},
           "rule": {"id": rule, "level": level, "description": desc, "groups": list(groups)}}
    data = {}
    for key, value in fields.items():
        if key in ("full_log", "syscheck_path"):
            continue
        node = data
        parts = key.split("__")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    if data:
        doc["data"] = data
    if "full_log" in fields:
        doc["full_log"] = fields["full_log"]
    if "syscheck_path" in fields:
        doc["syscheck"] = {"path": fields["syscheck_path"]}
    alerts.append(doc)


def fail(t, host, src, user):
    add(t, host, "5716", 5, "sshd: authentication failed.", ["sshd"], srcip=src, dstuser=user)


def login(t, host, src, user, rule="5715"):
    add(t, host, rule, 3, "sshd: authentication success.", ["sshd"], srcip=src, dstuser=user)


def sudo(t, host, user):
    add(t, host, "5402", 3, "Successful sudo to ROOT executed.", ["sudo"], srcuser=user, dstuser="root", command="/usr/bin/id")


# S1 (P1): fail burst then success from a public address, then sudo. Posture U-03 on web-01.
for i in range(6):
    fail(at(10, 1, i), "web-01", EXT, "alice")
login(at(10, 1, 10), "web-01", EXT, "alice")
sudo(at(10, 1, 15), "web-01", "alice")
# not enough failures before this login: no P1
for i in range(3):
    fail(at(10, 5, i), "web-02", "10.9.1.1", "erin")
login(at(10, 5, 5), "web-02", "10.9.1.1", "erin")

# S2 (P2): first-seen source off hours with sudo; a second source matching known activity (same subject);
#          direct root login from the admin range; out-of-range rule 100900.
login(at(10, 14, 0), "db-01", "10.9.9.9", "bob")      # 23:00 KST
sudo(at(10, 14, 20), "db-01", "bob")
login(at(11, 2, 0), "db-01", "10.9.9.8", "bob")       # known activity
login(at(11, 3, 0), "db-02", "10.7.0.5", "root", rule="100904")
login(at(11, 4, 0), "db-03", "10.9.2.2", "frank", rule="100900")

# S3 (P3): login, host privilege change, intrusion activity within 2h (no remote source on the last two).
login(at(12, 1, 0), "app-01", "10.7.1.5", "carol")
add(at(12, 2, 0), "app-01", "200001", 10, "New user added to the system.", full_log="useradd: new user: name=svc1, UID=1001")
add(at(12, 2, 30), "app-01", "200002", 12, "Suspicious interpreter started.", audit__exe="/usr/bin/python3",
    audit__auid="4294967295", audit__execve={"a0": "python3", "a1": "-c", "a2": "import pty", "a10": "last"})
sudo(at(12, 1, 30), "app-01", "carol")
# privilege change with no preceding login: no chain
add(at(12, 9, 0), "app-07", "200001", 10, "New user added to the system.", full_log="useradd: new user: name=svc2")

# S4 (P4): defence evasion burst, then secret read and trace removal within 1h.
add(at(13, 1, 0), "app-02", "200003", 12, "Audit daemon stopped by an interactive user and left disabled.", audit__exe="/usr/bin/systemctl", audit__auid="1001")
add(at(13, 1, 1), "app-02", "200003", 12, "Audit daemon stopped by an interactive user and left disabled.", audit__exe="/usr/bin/systemctl", audit__auid="1001")
add(at(13, 1, 10), "app-02", "200005", 12, "Credential file read.", audit__file__name="/etc/shadow", audit__auid="1001")
add(at(13, 1, 20), "app-02", "200004", 10, "Shell history removed.", audit__exe="/usr/bin/rm", audit__auid="1001", audit__execve={"a0": "rm", "a1": "/root/.bash_history"})
# defence evasion with nothing after it: stays a P9 single
add(at(13, 9, 0), "app-08", "200003", 12, "Audit daemon stopped by an interactive user and left disabled.", audit__exe="/usr/bin/systemctl", audit__auid="1002")

# S5 (P5): secret read then archive tool on the same host (near S4 in time).
add(at(13, 1, 12), "app-03", "200005", 12, "Credential file read.", audit__file__name="/etc/kubernetes/admin.conf", audit__auid="1003")
add(at(13, 1, 40), "app-03", "100815", 10, "Archive created from a sensitive path.", audit__exe="/usr/bin/tar", audit__auid="1003", audit__execve={"a0": "tar", "a1": "czf", "a2": "/tmp/x.tgz"})

# S6 (P6): one account failing from 12 sources, 60 events on web-01 (timeline clipped) and 3 on web-02.
for s in range(12):
    for i in range(5):
        fail(at(14, 1, s, i), "web-01", "10.20.0.%d" % (s + 1), "dave")
for i in range(3):
    fail(at(14, 2, i), "web-02", "10.20.0.%d" % (i + 1), "dave")

# S7 (P7): public source probing two hosts; attack-pattern rule on web-02 (matches known activity);
#          a public source below the request threshold and an internal source: no case.
for i in range(25):
    add(at(14, 5, i), "web-01", "200006", 3, "Web request to an unusual path.", ["web", "accesslog"], srcip=EXT2,
        url="/admin/%d?id=%d" % (i % 4, i), status="404")
for i in range(2):
    add(at(14, 5, 30 + i), "web-02", "200007", 7, "SQL injection attempt.", ["web"], srcip=EXT2, url="/login?u=' or 1=1", status="403")
for i in range(3):
    add(at(14, 6, i), "web-01", "200006", 3, "Web request to an unusual path.", ["web"], srcip=EXT3, url="/x", status="404")
for i in range(30):
    add(at(14, 7, i), "web-01", "200006", 3, "Web request to an unusual path.", ["web"], srcip="10.30.0.1", url="/y", status="404")

# S8 (P8): error burst on the last day vs. earlier days; sshd crash.
for day, count in ((10, 2), (11, 1), (12, 15)):
    for i in range(count):
        add(at(day, 3, i), "app-04", "200008", 5, "Service reported an error 4711.", ["syslog"], full_log="svc[%d]: error 4711" % i)
add(at(12, 4, 0), "app-05", "200008", 5, "Service reported an error 4711.", ["syslog"], full_log="kernel: sshd[1234]: segfault at 0 ip 00007f")

# S9 (P9): two rules of one criterion by one actor in two bursts; a rule with no criterion (known activity);
#          a level 8 case rule (below the P9 floor) and an agg rule (never a case).
exe = {"audit__exe": "/usr/bin/curl", "audit__auid": "1000"}
add(at(15, 1, 0), "app-06", "200009", 14, "Download tool fetched a remote payload.", audit__execve={"a0": "curl", "a1": "http://198.51.100.7/a"}, **exe)
add(at(15, 1, 10), "app-06", "200009", 14, "Download tool fetched a remote payload.", audit__execve={"a0": "curl", "a1": "http://198.51.100.7/b"}, **exe)
add(at(15, 4, 0), "app-06", "200002", 12, "Suspicious interpreter started.", audit__execve={"a0": "curl", "a1": "-s"}, **exe)
add(at(15, 6, 0), "app-06", "200012", 11, "Unlinked detection rule fired.", full_log="Nov 15 06:00:00 app-06 thing: state changed 42")
add(at(15, 6, 5), "app-06", "200013", 8, "Low level case rule.", audit__exe="/usr/bin/true", audit__auid="1000")
add(at(15, 6, 6), "app-06", "200011", 12, "Aggregated only.", audit__exe="/usr/bin/true", audit__auid="1000")

# S12: Kubernetes subjects (service account, OIDC user, client certificate), comma-separated ATT&CK ids.
ref = {"resource": "clusterrolebindings", "name": "cluster-admin-x"}
add(at(15, 8, 0), "k8s-cp-01", "200010", 10, "Cluster role binding created.", user__username="system:serviceaccount:kube-system:deployer",
    objectRef=ref, verb="create", sourceIPs=["10.7.2.2"])
add(at(15, 8, 1), "k8s-cp-01", "200010", 10, "Cluster role binding created.", user__username="admin@corp.example",
    objectRef={"resource": "rolebindings", "namespace": "prod", "name": "edit-x"}, verb="create", sourceIPs=["10.7.2.3"])
add(at(15, 8, 2), "k8s-cp-01", "200010", 10, "Cluster role binding created.", user__username="kubernetes-admin",
    objectRef={"resource": "clusterroles"}, verb="patch", sourceIPs=["10.7.2.4"])

alerts.sort(key=lambda a: a["timestamp"])  # the indexer returns timestamp order

CATALOG = """rule_id\tsrc\tlevel\tcategory\tuse\tattack\tkeys\ttitle\tnote\tlayer
5716\twazuh\t5\tEV-AUTH\tagg\tT1110\t-\tsshd: authentication failed.\t\tactivity
5715\twazuh\t3\tEV-ACCESS\tagg\tT1078\t-\tsshd: authentication success.\t\tactivity
100900\tsiem-auth\t10\tEV-ACCESS\tcase\tT1078\t-\tLogin from outside the allowed range\t\tactivity
100904\tsiem-auth\t10\tEV-ACCESS\tcase\tT1078.003\t-\tDirect root login\t\tactivity
5402\twazuh\t3\tEV-ACCESS\tagg\tT1548.003\t-\tSuccessful sudo to ROOT executed.\t\tactivity
200001\tsiem-host\t10\tEV-PRIV\tcase\tT1136.001\t-\tNew user added to the system.\t\tactivity
200002\tsiem-host\t12\tEV-EXEC\tcase\tT1059\t-\tSuspicious interpreter started.\t\tactivity
200003\tsiem-host\t12\tEV-EXEC\tcase\tT1562.001\t-\tAudit daemon stopped\t\tactivity
200004\tsiem-host\t10\tEV-EXEC\tcase\tT1070.003\t-\tShell history removed.\t\tactivity
200005\tsiem-host\t12\tEV-DATA\tcase\tT1552.001\t-\tCredential file read.\t\tactivity
100815\tsiem-host\t10\tEV-DATA\tcase\tT1560.001\t-\tArchive created from a sensitive path.\t\tactivity
200006\tsiem-web\t3\tEV-RECON\tagg\tT1595\t-\tWeb request to an unusual path.\t\tactivity
200007\tsiem-web\t7\tEV-RECON\tcase\tT1190\t-\tSQL injection attempt.\t\tactivity
200008\tsiem-host\t5\tEV-ERR\tagg\t\t-\tService reported an error.\t\tactivity
200009\tsiem-host\t14\tEV-EXEC\tcase\tT1105\t-\tDownload tool fetched a remote payload.\t\tactivity
200010\tsiem-k8s-api\t10\tEV-PRIV\tcase\tT1098,T1136\t-\tCluster role binding created.\t\tactivity
200011\tsiem-host\t12\tEV-EXEC\tagg\tT1059\t-\tAggregated only.\t\tactivity
200012\tsiem-host\t11\tEV-EXEC\tcase\tT1204\t-\tUnlinked detection rule fired.\t\tactivity
200013\tsiem-host\t8\tEV-EXEC\tcase\tT1204\t-\tLow level case rule.\t\tactivity
200099\tsiem-host\t3\t-\t-\t\t-\tNot analysed.\t\tactivity
"""

CRITERIA = """# fixture detection criteria
code\ttitle\tcategory\tpattern\tref\trules\tstatus\tnote
EV-CORR-01\tFail burst then success\tEV-CORR\tP1\t-\t-\tactive\t-
EV-CORR-02\tUnusual login\tEV-CORR\tP2\t-\t-\tactive\t-
EV-CORR-03\tIntrusion chain\tEV-CORR\tP3\t-\t-\tactive\t-
EV-CORR-04\tDefence evasion then access\tEV-CORR\tP4\t-\t-\tactive\t-
EV-CORR-05\tSecret read then exfiltration\tEV-CORR\tP5\t-\t-\tactive\t-
EV-CORR-06\tDistributed password guessing\tEV-CORR\tP6\t-\t-\tactive\t-
EV-CORR-07\tExternal reconnaissance\tEV-CORR\tP7\t-\t-\tactive\t-
EV-CORR-08\tError burst\tEV-CORR\tP8\t-\t-\tactive\t-
EV-CORR-99\tRetired correlation\tEV-CORR\tP9\t-\t-\tretired\t-
EV-EXEC-01\tSuspicious execution\tEV-EXEC\t-\t-\t200002,200009\tactive\t-
EV-EXEC-02\tDefence evasion\tEV-EXEC\t-\t-\t200003\tactive\t-
EV-EXEC-03\tTrace removal\tEV-EXEC\t-\t-\t200004\tactive\t-
EV-DATA-01\tCredential access\tEV-DATA\t-\t-\t200005,100815\tactive\t-
EV-PRIV-01\tAccount or role change\tEV-PRIV\t-\t-\t200001,200010\tactive\t-
EV-ACCESS-02\tUnusual login rule\tEV-ACCESS\t-\t-\t100900,100904,5715\tactive\t-
"""

KNOWN = """# fixture known activity
pattern\tmatch\treason\texpires\tapproved_by
P9\trule=200012\tscheduled state change job\t2027-01-01\treviewer
EV-CORR-07\tsrc=45\\.33\\.32\\.200 host:web-02\tcontracted scanner\t2027-01-01\treviewer
P2\tsrc=10\\.9\\.9\\.8\tbastion address\t\treviewer
*\tuser=alice\texpired entry must be ignored\t2026-01-01\treviewer
"""

ADMIN = "# fixture admin ranges\n10.7.:\n192.168.50.: \n"
SEEN = [["db-01", "bob", "10.9.9.9"], ["db-01", "bob", "10.9.9.8"], ["web-02", "erin", "10.9.1.1"]]
POSTURE = {"web-01": ["U-03", "U-01"], "db-02": ["U-01", "U-28"], "db-01": ["U-66"]}


def write(name, text):
    with open(os.path.join(HERE, name), "w", encoding="utf-8") as f:
        f.write(text)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    write("alerts.json", json.dumps(alerts, ensure_ascii=False, indent=1) + "\n")
    write("event-catalog.tsv", CATALOG)
    write("event-criteria.tsv", CRITERIA)
    write("known-activity.tsv", KNOWN)
    write("siem-admin-src", ADMIN)
    write("seen.json", json.dumps(SEEN) + "\n")
    write("posture.json", json.dumps(POSTURE, sort_keys=True) + "\n")

    sys.path.insert(0, os.path.join(sys.argv[1], "assess"))
    import events
    events.CATALOG = os.path.join(HERE, "event-catalog.tsv")
    events.CRITERIA = os.path.join(HERE, "event-criteria.tsv")
    events.KNOWN = os.path.join(HERE, "known-activity.tsv")
    events.ADMIN_SRC = os.path.join(HERE, "siem-admin-src")
    cat, crit, admin = events.catalog(), events.criteria(), events.admin_prefixes()
    # read_known() filters on the real date; filter on the fixture date instead
    with open(events.KNOWN, encoding="utf-8") as f:
        lines = [l.rstrip("\n").split("\t") for l in f if l.strip() and not l.startswith("#")]
    known = [dict(zip(lines[0], l + [""] * 4)) for l in lines[1:]]
    known = [k for k in known if k.get("match") and (not k.get("expires") or k["expires"] >= TODAY)]
    seen = {tuple(x) for x in SEEN}
    posture = {h: set(c) for h, c in POSTURE.items()}

    by, _ = events.build(alerts, cat, seen, admin)
    rows, timelines = events.cases(by, cat, seen, admin, known, posture, crit)
    head = events.CASE_HEAD
    out = []
    for row in rows:
        r = dict(zip(head, row))
        out.append({
            "id": r["case_id"], "pattern": r["pattern"], "score": r["score"], "entity": r["entity"],
            "hosts": [h for h in r["hosts"].split(",") if h], "first": r["first"], "last": r["last"], "n": r["n"],
            "attack": [t for t in r["attack"].split(",") if t], "summary": r["summary"], "known": r["known"],
            "near": [c for c in r["near"].split(",") if c], "severity": r["severity"], "sev_basis": r["sev_basis"],
            "criterion": r["criterion"], "actor": r["actor"],
            "timeline": [list(e) for e in timelines[r["case_id"]]],
        })
    write("cases_golden.json", json.dumps(out, ensure_ascii=False, indent=1) + "\n")
    print("%d alerts, %d cases: %s" % (len(alerts), len(out), " ".join("%s=%d" % (p, sum(1 for c in out if c["pattern"] == p))
                                                                  for p in sorted({c["pattern"] for c in out}))))


if __name__ == "__main__":
    main()
