# **H@cktivity Con CTF 2020**

<div align='center'>
  <img width=500 src='assets//images//logo.gif'>
</div>
\
This is my writeup for the challenges in H@cktivityCon CTF 2020, I'll try adding as many challenges as I can during the next few days, as of now it contains the only challenge I managed to write about during the CTF.

# Table of Content

# Web

## Ladybug
Want to check out the new Ladybug Cartoon? It's still in production, so feel free to send in suggestions!

Connect here:\
http://jh2i.com:50018

**Solution:** With the challenge we are given a url to a webserver:

![](assets//images//ladybug_1.png)

The page seems pretty bare, there are some links to other pages in the webserver and an option to search the website or to contact ladybug using a form, I first tried checking if there's an XXS vulnerability in the contact page or an SQLi vulnerability / file inclusion vulnerability in the search option, that didn't seem to work, then I tried looking in the other pages in the hope I'll discover something there, none of them seemed very interesting, but, their location in the webserver stood out to me, all of them are in the `film/` directory, the next logical step was to fuzz the directory, by doing so I got an Error on the site:

![](assets//images//ladybug_2.png)

This is great because we now know that the site is in debug mode (we could infer that also from the challenge description but oh well), also we now know that the site is using Flask as a web framework, Flask is a web framework which became very popular in recent years mostly due to it simplicity, the framework depends on a web server gateway interface (WSGI) library called Werkzeug, A WSGI is a calling convention for web servers to request to web frameworks (in our case Flask).\
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
