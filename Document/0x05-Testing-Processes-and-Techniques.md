# Testing Processes and Techniques

## Black-box Testing
Black box testing or functional testing is testing without knowledge of the internal workings of the item being tested. Functional testing is testing core functionality of mobile application as per specification and correct performance. This can involve testing of the applications user interface, APIs, database management, security, installation, and networking.

## White-box Testing
In a whitebox testing, the security tester has complete access to the original source code.  With source code for the client-side app, a security tester can execute and debug the app within an IDE.  The application still runs on an actual device or emulator/simulator, but the application's flow of execution can be tightly controlled through the IDE.

## Static Analysis
Automated code review. These tools often involve hooking into a compiler to under-stand an application’s data flow. 
They are particularly effective at finding some of the highest risk input validation vulnerabilities, such as ceridential information hardcode, permision checking.

## Dynamic Analysis
Automated runtime testing. Generally focused specifically on web applications, dynamic analysis tools crawl (application activiy) through the application looking for specific issues by automatically executing attacks and analyzing responses for evidence that the attacks work.
