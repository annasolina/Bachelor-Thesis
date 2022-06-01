# Bachelor-Thesis
In this repository you will find the different challenges I have solved for the degree thesis.  In each one there is a readme file for a better understanding.

## web_Command_Execution_Challenge

The challenge consists of exploiting a command injection.

Through a GET request to the root / with the domain parameter, it is possible to make a dns request to a site. e.g. /?domain=www.ulisse.unibo.it

The purpose of the exercise is to exploit command injection and retrieve/read the file /etc/passwd.

The first step is to see that if you run http://127.0.0.1:8000/?domain=www.ulisse.unibo.it in the explorer you can see that the server is not able to give you the information correctly. However, if you run dig www.ulisse.unibo.it in the terminal, you can see the DNS information. 

The next step is to check that you can execute two commands at the same time, but of course, you have to be aware that the browser has not been able to deliver the correct DNS information, so if you run http://127.0.0.1:8000/?domain=www.ulisse.unibo.it && ls in the browser it will not work because it cannot do both commands. Instead, we have to use "||" as it will do only one. 

Finally, you can see that there are quite a few filters to print the file in question. For example, if you use the cat command, you will get a response specifying that the command used is banned. Another example is that it has a filter that prohibits files ending in wd from being seen, so the solution is to use less /etc/passw*.

So, the answer to the exercise is to run the following line in the explorer browser: http://127.0.0.1:8000/?domain=www.ulisse.unibo.it || less /etc/passw*.

## Web_SQLi_Challenge

The challenge is to exploit a sql injection to bypass the login.

The login is performed by a GET call to the address /login with the parameters username and password, for example /login?username=&password=.

The goal of the exercise is to log in as the administrator user.

For the exercise to be successful, the student must deliver: the FLAG, the complete query that exploits the SQLi, a brief description of the steps performed, why the vulnerability exists and how it is exploited. 

For this challenge you need to be trained in SQL injection and how to circumvent it. Thanks to the documentation obtained by the teachers, the challenge has been solved [15]. 

The secret is to understand that the injection must always be correct. This is solved by adding a condition that is always true. For example OR 1=1.

If we add this in the search engine and mark that the user is the admin we will get the answer. So, the line we have to put in the search engine is the following: 127.0.0.1:8000/login?username=admin&password='OR'1’='1.

Is important to understand how the password condition works. That is, understand how the apostrophes work and what they are commenting out. 

Finally, when inserting the answer in the browser, we can't see the flag. This is because it is activated so that the answer does not remain and vanishes after a second. This obstacle can be easily solved, one of the many options, is to use Burb Suite and forward the browser to obtain the static answer and be able to see the answer [16].

## Web_Path_Traversal_Challenge

The challenge is to exploit a LFI (Local File Inclusion)

Through a GET request to the root / with the path parameter it is possible to open a local file e.g. /?path=file_locale.txt.

The purpose of this exercise is to exploit the LFI and retrieve/read the file /etc/passwd.

There are some filters on the characters that you can send as a path.

This challenge aims to provide the user with knowledge of file paths in Ubuntu and how to move through directories using the terminal.

As the statement says, the challenge has quite a few filters and these will help you to solve it.

First of all, we have to try the obvious answer, to put the file directly. That is, use http://127.0.0.1:8000/?path=/etc/passwd. In this case we see that we don't get the answer because there is a filter.

Then, we have to think that if we are in a directory mobility exercise we have to think of the following tool: ../ or /.. since they are very used techniques to make the jumps in the directories.

Even so, if we use them we see that it is not possible, that there is a filter that forbids it. Then we think that maybe if we use the double slash it will work (//), but we get another filter that denies us the answer. This filter tells us that we could try the combination of the two signs.

So, we try ./ and see that there is a new filter telling us that we can't end the line with the wd parameters. So, we modify the line with the asterisk * parameter.

Then, we see that it does work, that is to say, that no filter comes out, but it is still not the answer because the file has to be printed on the screen, and what we see is a few lines of code that can indicate that we are on the right track, but it is not the definitive answer.

At this point, we have to think as if we were in the terminal and start making jumps in the directories, that is to say, use the ../ tool to go jumping directories. If you don't know how many jumps you have to make, you can add them consecutively until you get the answer or understand where the folder etc. is located and know that there are five jumps.

That is to say, the URL that you have to put in the search engine is http://127.0.0.1:8000/?path=./../../../../../etc/passw*.
