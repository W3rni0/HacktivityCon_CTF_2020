# **H@cktivityCon CTF 2020**

<div align='center'>
  <img width=500 src='assets//images//logo.gif'>
</div>

This is my writeup for the challenges in H@cktivityCon CTF 2020, I'll try adding as many challenges as I can during the next few days starting with the web challenges.


# Table of Content
* [Web](#web)
  - [Ladybug](#ladybug)
  - [Bite](#bite)
  - [GI Joe](#gi-joe)
  - [Waffle Land](#waffle-land)
  - [Lightweight Contact Book](#lightweight-contact-book)
  - [Template Shack](#template-shack)

# Web

## Ladybug
Want to check out the new Ladybug Cartoon? It's still in production, so feel free to send in suggestions!

Connect here:\
http://jh2i.com:50018

**`flag{weurkzerg_the_worst_kind_of_debug}`**

**Solution:** With the challenge we are given a url to a website:

![](assets//images//ladybug_1.png)

The page seems pretty bare, there are some links to other pages in the webserver and an option to search the website or to contact ladybug using a form, I first tried checking if there's an XXS vulnerability in the contact page or an SQLi vulnerability / file inclusion vulnerability in the search option, that didn't seem to work, then I tried looking in the other pages in the hope I'll discover something there, none of them seemed very interesting, but, their location in the webserver stood out to me, all of them are in the `film/` directory, the next logical step was to fuzz the directory, by doing so I got an Error on the site:

![](assets//images//ladybug_2.png)

This is great because we now know that the site is in debugging mode (we could infer that also from the challenge description but oh well), also we now know that the site is using Flask as a web framework, Flask is a web framework which became very popular in recent years mostly due to it simplicity, the framework depends on a web server gateway interface (WSGI) library called Werkzeug, A WSGI is a calling convention for web servers to request to web frameworks (in our case Flask).\
Werkzeug also provides a web server with a debugger and a console to execute Python expression from, we can navigate to the console using by navigating to `/console`:

`

![](assets//images//ladybug_3.png)

From this console we can execute commands on the server (RCE), let's first see which user we are on the server, I used the following commands for that:

```python
import subprocess;out = subprocess.Popen(['whoami'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT);stdout,stderr = out.communicate();print(stdout);
```

the command simply imports the subprocess library, creates a new process which execute `whoami` and prints the output of the command, by doing so we get:

![](assets//images//ladybug_4.png)

The command worked!, now we can execute`ls` by changing the command in order to see which files are in the current directory, by doing so we see that there's a file called flag.txt in there, and by using `cat` on the file we get the flag:

![](assets//images//ladybug_5.png)

**Resources:**
* Flask: https://en.wikipedia.org/wiki/Flask_(web_framework)
* Flask RCE Debug Mode: http://ghostlulz.com/flask-rce-debug-mode/

## Bite
Want to learn about binary units of information? Check out the "Bite of Knowledge" website!

Connect here:\
http://jh2i.com:50010

**`flag{lfi_just_needed_a_null_byte}`**

**Solution:** With the challenge we get a url for a website:

![](assets//images//bite_1.png)

the site is about binary units, a possible clue for the exploit we need to use, it's seems we can search the site or navigate to other pages, by looking at the url we can see that it uses a parameter called page for picking which resource to display, so the format is:

`http://jh2i.com:50010/index.php?page=<resource>`

we possibly have a local file inclusion vulnerability (LFI), as I explained in my writeup for nahamCon CTF:

>  PHP allows the inclusion of files from the server as parameters in order to extend the functionality of the script or to use code from other files, but if the script is not sanitizing the input as needed (filtering out sensitive files) an attacker can include any arbitrary file on the web server or at least use what's not filtered to his advantage

let's first try including the PHP file itself, this will create some kind of a loop where the file included again and again and will probably cause the browser to crash...but it's a good indicator that we have an LFI vulnerability, navigating to `/index.php?page=index.php` gives us:

![](assets//images//bite_2.png)

index.php.php? it's seems that the PHP file includes a resource with a name  matching the parameter given appended to .php, lets try `/index.php?page=index` :

![](assets//images//bite_3.png)

It worked! so we know that we have an LFI vulnerability where the parameter given is appended to a php extension, appending a string to the parameter's value is a common defense mechanism against arbitrary file inclusion as we are now limited only to a small scope of files, hopefully only files that are safe to display, but there are ways to go around this.\
In older versions of PHP by adding a null byte at the end of the parameter we can terminate the parameter's string, a null byte or null character is a character with the code `\x00`, this character signifies the end of a string in C and as such strings in C are often called null-terminated strings, because PHP uses C functions for filesystem related operations adding a null byte in the parameter will cause the C function to only consider the string before the null byte.

with that in mind let's check if we can use a null byte to display an arbitrary file, to mix things we'll try to include `/etc/passwd`, this file exists in all linux servers and is commonly accessible by all the users in the system (web applications running are considered as users in linux) as such it's common to display the content of this file in order to prove access to a server (as proof of concept), we can represent a null byte in url encoding using `%00`, navigating to `/index.php?page=/etc/passwd%00` gives us:

![](assets//images//bite_4.png)

We can use null bytes!...but where is the flag located?\
At this point I tried a lot of possible locations until I discovered that the flag is located in the root directory in a file called `file.txt` by navigating to `/index.php?page=/flag.txt%00` we get the flag:

![](assets//images//bite_5.png)

**Resources:**
* File Inclusion Vulnerabilities: https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/
* Payload all the things - File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
* Null byte: https://en.wikipedia.org/wiki/Null_character
* Null byte issues in PHP: https://www.php.net/manual/en/security.filesystem.nullbytes.php

## GI Joe
The real American hero!

Connect here:\
http://jh2i.com:50008

**Post-CTF Writeup**\
**`flag{old_but_gold_attacks_with_cgi_joe}`**

**Solution:** With the challenge we get a url to a website about G.I joe's movies called See GI Joe:

![](assets//images//gi_joe_1.png)

By the name of the challenge we can assume it has something to do with Common Gateway Interface or CGI (See GI), Common Gateway Interface are interface specification for communication between a web server (which runs the website) and other programs on the server, this allows webserver to execute commands on the server (such as querying a database), and is mostly used to generate webpages dynamically, this type of communication is handled by CGI scripts which are often stored in a directory called `cgi-bin` in the root directory of the web server.\
Looking around in the web site I didn't find any other interesting thing, but by looking at the headers of the server responses using the inspect tool I discovered that the website is using PHP version 5.4.1 and Apache version 2.4.25, this are quite old versions of both PHP (current version is 7.3) and Apache (current version is 2.4.43) so I googled `php 5.4.1 exploit cgi` and discovered this [site](https://www.zero-day.cz/database/337/), according to it there is a vulnerability in this version which allows us to execute arbitrary code on the server, this vulnerability is often referred to by CVE-2012-1823 (or by CVE-2012-2311 because of later discovery related to this vulnerability).\
In more details when providing vulnerable website with a value with no parameter (lacks the `=` symbol) the value is interpreted as options for the php-cgi program which handles communication with the web server related to PHP, the options available are listed in the man page in the resources, so for example by using the -s flag we can output the source code for a PHP file and so by adding `/?-s` to the url for a PHP file located on a vulnerable server we can view the source code of the file, let's try it on the index page (which is a PHP file) by navigating to `/index.php?-s` we get the following:

![](assets//images//gi_joe_2.png)

It worked! and we now know that the flag is in a file called flag.txt in the root directory of the server, as I mentioned before this vulnerability allows us to execute commands on the server, this can be done by using the -d option, this option allows us to change and define INI entries, or in other words change the configuration files of PHP, we need to change the option `auto_prepend_file` to `php://input`, this will force PHP to parse the HTTP request and include the output in the response, also we need to change the option `allow_url_include` to `1` to allow the usage of `php://input`, so by navigating to `/?-d allow_url_include=1 -d auto_prepend_file=php://input` and adding to the HTTP request a PHP code to execute commands on the system `<?php system(<command>) ?>` we can achieve arbitrary code execution on the server.\
let's try doing that to view the flag, we can use cURL with -i option to include the HTTP headers and --data-binary option to add the PHP code, in the PHP code we'll use `cat /flag.txt` to output the content of the file, the command is:

`curl -i --data-binary "<?php system(\"cat /flag.txt \") ?>" "http://jh2i.com:50008/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"`

and by executing this command we get the flag:

![](assets//images//gi_joe_3.png)

**Resources:**
* Common Gateway Interface: https://en.wikipedia.org/wiki/Common_Gateway_Interface
* CVE-2012-1823: https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2012-1823
* CVE-2012-2311: https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2012-2311
* a detailed explanation on CVE-2012-1823: https://pentesterlab.com/exercises/cve-2012-1823/course
* man page for php-cgi: https://www.systutorials.com/docs/linux/man/1-php-cgi/

## Waffle Land
We got hacked, but our waffles are now safe after we mitigated the vulnerability.

Connect here:\
http://jh2i.com:50024

**`flag{check_your_WAF_rules}`**

**Solution:** With the challenge we get a url to a website about waffles:

![](assets//images//waffle_land_1.png)

We have two options in this webpage, to search using the search bar or to sign in to the website using a username and a password, as we don't have any credentials let's try to fiddle with the search option. The search option returns only the waffles that has the search parameter in them, trying to insert the character `'` gives us an error message:

![](assets//images//waffle_land_2.png)

This gives us information about two things, first we know now that the search option uses SQL to filter data, SQL is a language designed for managing and querying databases (with SQL it is common to think of the as tables with rows of data and columns of attributes), in this case a SQL query is used to select all the products with the name attribute is similar to the input given, second we know that the web server uses SQLite3 management system, this has some influence on the version of SQL used and on the operations we can use or exploit.\
A common attack against SQL systems is using SQL injection or SQLi, computers can't differentiate between data and commands and as such it's sometime possible to inject commands where data is requested, for example we can search for `' limit 1 ---` and this will cause the SQL management system vulnerable to SQLi to execute the following query:

`select * from product where name like '' limit 1`

this query returns the first row of data in the product table, this will be executed because we closed the quotations and added `-- -` which signifies that the rest of the string is a comment.
To prevent this attack there are systems in place to filter (sanitize) the input given, one of those is a Web Application Firewall or WAF, this type of system monitors the HTTP traffic of a web server and prevents attacks such as SQLi by blocking suspicious traffic.\
Let's first check if we have SQLi to begin with, using the search parameter in the example above gives us the following:

![](assets//images//waffle_land_3.png)

Seems like we can use SQLi, now let's try to view the users table in order to sign in to the site, for that we need to add the data of the users table to the output of the query, we can use union for that but it will only work if the number of attributes in the output is the same, let's start with finding the number of attributes in the products table using `' order by n -- -`, adding this to the query will sort the data according to the n'th attribute, and if n is bigger then the number of attributes in this table the query will cause an error, by doing so we can discover that the number of attributes in the product table (the table of waffles) is 5.\
with the number of attributes in mind we can try adding data, first we'll try using `' union select 1,2,3,4,5 -- -` this will add the row `1,2,3,4,5` to the output of the query, by doing so we get the following:

![](assets//images//waffle_land_4.png)

It appears that the web server is blocking this search, so we might be working against a WAF after all (fitting the theme of this challenge), trying to work around this I discovered that the WAF is filtering searches with the string ` union select` so a simple workaround I found is using `/**/union/**/select` instead (I added a cheatsheet for this kind of thing in the resources), the symbol `/*` signifies the start of a comment and the symbol `*/` the end of a comment so using `/**/` doesn't change the query meaning but could possibly help us pass through the WAF, using  `'/**/union/**/select 1,2,3,4,5 -- -` gives us the following:

![](assets//images//waffle_land_5.png)

 It worked! so now we have a way to add data to the output, we still need to get data about the users, checking if we can select data from a table named `users` by using `'/**/union/**/select 1,2,3,4,5 from users -- -` gives us an error but by checking for `user` seems to work so we can guess there is a table named `user` in the database, we need to get usernames and passwords from this table, U discovered through this trial and error that there are attributes named `password` and `username` in this table so we can search for the following to get the data from this table:

`' and 0=1/**/union/**/select/**/1,username,password,4,5 from user ---`

the query executed will be:

`select * from product where name like '' and 0=1/**/union/**/select/**/1,username,password,4,5 from user`

this will first select the data from the product table and filter only the data that make the condition 0=1 true, so the query will filter all the data from this table, then it adds the data in the username and the password columns of the table user and the number 1,4 and 5 to pad the data so we can use union, we get the following output from the search:

![](assets//images//waffle_land_6.png)

And we got the password, we can now login as admin and receive the flag:

![](assets//images//waffle_land_7.png)

**Resources:**
* SQL: https://en.wikipedia.org/wiki/SQL
* SQLite: https://en.wikipedia.org/wiki/SQLite
* SQL injection (SQLi): https://en.wikipedia.org/wiki/SQL_injection
* Web Application Firewall (WAF): https://en.wikipedia.org/wiki/Web_application_firewall
* SQLi cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

## Lightweight Contact Book
Lookup the contact details of any of our employees!

Connect here:\
http://jh2i.com:50019

**`flag{kids_please_sanitize_your_inputs}`**

**Solution:** We again receive a url to a website with the challenge which seems...empty

![](assets//images//lightweight_1.png)

We have two options (again), to search and to login using a username and a password, but this time we also have the option to recover a user's password:

![](assets//images//lightweight_2.png)

We can try some common usernames, all of them seems to give us the message "Sorry, this functionality is currently unavailable" except for the username `administrator` which gives us the following:

![](assets//images//lightweight_3.png)

Okay so we have a username that is administrator...what's next? after a bit of fuzzing the search bar I got an error message:

![](assets//images//lightweight_4.png)

by googling the error message I discovered that this website using a protocol called LDAP for the search, LDAP or Lightweight Directory Access Protocol is a protocol for accessing directory service over the internet (directory service is a shared information infrastructure, can be thought of as a database for this challenge), in this protocol the symbol `*` stands for a wildcard and filtering is done using `(<attribute>=<value>)` and filters can be appended together. By searching for `*` we can view the display name and the email of employees, one that stand out is the employee with the display name `Administrator User`, by trying to search for `Admin*` we can see that only the row with this employee is left, so we can assume that the statement used by the search option is `(name=<search input>)` and that we need to discover the description for the employee with the name `Administrator User`.\
A common attack against LDAP is using LDAP injection which is very similar to SQL injection, a simple example for LDAP injection is to search for `*)(mail=administrator@hacktivitycon*` the statement that will be executed by our assumption is:

 `(name=*)(email=administrator@hacktivitycon.local)`

 and only the employee(s) with this email will be displayed, trying that gives us:

 ![](assets//images//lightweight_5.png)

 and it seems that we can use LDAP injection, so we want to get the password stores in  the description of the administrator but we cannot display it so we can do something similar to blind SQL injection, by search for `Admin*)(description=<string>*` and changing the value of string character by character, we have two options:
 * The value is the start of password and the information about the Administrator will be displayed as it matches both of the filters.
 * The value is not the start of the password and information about the Administrator will not be displayed because it doesn't match the second filter.

we can start with an empty string an go through all the characters trying to append the character to the string until information about the Admin is displayed, at this point we know that the string is the start of the password and we can try to add another character to the string by again going through all the characters and so on until we can no longer add characters, so I wrote a python script to do that:

 ```python
 import urllib.parse, urllib.request
from string import printable

password = ''
while 1:
	for c in printable:
		query = 'Admin*)(description={}*'.format(password + c)
		url = 'http://jh2i.com:50019/?search=' + urllib.parse.quote(query)
		response = urllib.request.urlopen(url).read()
		if b'Admin' in response:
			password += c
			print(password)
			break
 ```

by running the script we get the password:

![](assets//images//lightweight_6.png)

and we can connect with the username `administrator` and the password `very_secure_hacktivity_pass` to receive the flag:

![](assets//images//lightweight_7.png)

**Resources:**
* Lightweight Directory Access Protocol (LDAP): https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol
* LDAP injection: https://www.synopsys.com/glossary/what-is-ldap-injection.html
* LDAP injection cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection

## Template Shack
Check out the coolest web templates online!

Connect here:\
http://jh2i.com:50023

**Post-CTF Writeup**\
**`flag{easy_jinja_SSTI_RCE}`**

**Solution:** With the challenge we get a url for a webpage about web templates:

![](assets//images//template_shack_1.png)

By the name of the challenge we can guess we need to use Server-Side Template Injection or SSTI.\
This vulnerability is caused due to the nature of template engine, template engines are programs designed to embed dynamic data into static template files, a good example for this king of templates are actually the one shown in this site, but using templates could allow attackers to inject template code to the website, because the template engine can't distinguish between the intended code and the data unsafe embedding of user input without sanitization could result with user input interpreted as code and parsed by the engine,  allowing attackers to reveal private information and even run arbitrary code on the server.\
...but, this page doesn't seems to be vulnerable to SSTI, we could guess by the design and HTTP response headers that this site is running jinja as the template engine with flask as the framework.\
After the CTF ended I discovered that there is an SSTI vulnerability...in the admin page, so we need to sign in as admin (again), looking around the website some more we can see that the site uses cookies to save user state, as I explained in a previous writeup:

>...because HTTP connection is stateless (doesn't save the state of the connection server-side) and because sometimes the server needs to know who is the user in a session it saves cookies on the computer of the user, cookies are data which is most of the time encrypted and sent with HTTP requests to helps the server recognize the user

in our case it's actually a JSON Web Token or JWT, JWT is an internet standard for creating signed data and is used for authentication, a token composes of three parts separated by a dot:
*  An Header, this header identifies the algorithm used to generate the signature (the third part of the token), this part is base64 encoded
*  A Payload, contains the set of claims, or in other words the actual signed data, this part is also base64 encoded
*  A signature, this part is used to validate the authenticity of the token, the signature is created by appending the previous two parts to a secret and then using the signing scheme or the message authentication code system listed in the header to encrypt the data.

Let's look at our token using a tool called jwt_tool (listed in the resources):

![](assets//images//template_shack_2.png)

We have only one claim in the token's payload and it's for the username used, so we need to change the value to admin, there are multiple ways to modify a JWT but bruteforcing the secret key using a dictionary worked for me, we could do that using the same tool and a public dictionary for passwords called rockyou.txt with the following command:

`python3 jwt_tool.py -C eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.9SvIFMTsXt2gYNRF9I0ZhRhLQViY-MN7VaUutz9NA9Y -d rockyou.txt`


By doing so we get the secret key `supersecret`, and we can modify the token to so that the username claimed is admin using the same tool, the modified token is:

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.Ykqid4LTnSPZtoFb11H+/2q+Vo32g4mLpkEcajK0H7I`

and by changing the cookie stored for the website to this token we are signed in as admin:

![](assets//images//template_shack_3.png)

Checking out the admin page we see that it uses the first template shown on the index page:

![](assets//images//template_shack_4.png)

so we now might be able to use SSTI, there are only two pages available two us, the charts page and the tables page, both show a 404 error:

![](assets//images//template_shack_5.png)

After a bit of fuzzing I discovered that we can add template code to the 404 error page by changing the URL of the page to `http://jh2i.com:50023/admin/<code>`, for example by navigating to `http://jh2i.com:50023/admin/{{7*7}}` we get:

![](assets//images//template_shack_6.png)

so now that we can use SSTI we can get RCE using the following payload:

`{{config.__class__.__init__.__globals__['os'].popen('<command>').read()}}`

I will not go to details about why it works because this writeup is long as it is but basically the part `config.__class__.__init__.__globals__` returns a list global variables of the class which config is an instance of, one of those is the module os, using the module os we can create a new process with popen which will execute a command and using read() will return the output of the command, first let's see what we have in our working directory:

![](assets//images//template_shack_7.png)

it worked! and there is a file called flag.txt in this directory reading it using `cat flag.txt` gives us the flag:

![](assets//images//template_shack_8.png)

**Resources:**
* Server Side Template Injection (SSTI): https://portswigger.net/research/server-side-template-injection
* Template engine: https://en.wikipedia.org/wiki/Template_processor
* SSTI cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
* JSON Web Tokens: https://en.wikipedia.org/wiki/JSON_Web_Token
* JSON Web Tokens cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
* jwt_tool: https://github.com/ticarpi/jwt_tool
