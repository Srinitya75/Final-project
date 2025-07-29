# Final-project

Contents of the project and their actions
----------------------------------------------

* 404.html: this page gets invoked when the wrong url is provided to the website

* app.py: this file can be viewed in 2 aspects. 
        1. which does the db activities
        2. executes actions for the web page index.html 
          supports both the verbs get / post 
        3. corresponding secure_login / vulnerable_login logic is written here. 
           triggers or invokes secure_login.html / vulnerable_login.htm
           read sections secure_login.html / vulnerable_login.html on how the processing is different for both the similar actions
           
* dashboard.html: this page gets invoked when the user logs out after giving correct admin / password values in index.html

* index.html: this is the main landing page of the application. 
            webpage divided in to 2 sections
            1. general login
              user can provide the unsecured / sql injection attack values for username /password
              the results can be seen whether they can be logged in or not
            2. secure login
              though user provides the sql injection username / password values, the actions fails.
              where as in general login / case 1, the results fail

* schema.sql: sql file to create the tables users 
            1. users: unique username & password can be inserted here to allow login to system
  
* vulnerable_login.html: Displays at top of the page whether the username / passord is valid. 
                  this page gets displayed when the user is logged in as a consequence of action index.html
                  triggered from app.py contains the flask code which does not check for vulnerability sql code, and executes it
                  flask code in app.py reads the data from db for the usrename / password.
                  check whether the username / password is valid or not and sends a message to this page which is displayed on top of the page.
        
* secure_login.html: Displays at top of the page whether the username / passord is valid
                  this page gets displayed when the user is logged in as a consequence of action index.html
                  triggered from app.py contains the flask code. sql data is sent as parameterized values, which helps in detection of sql injection values
                  flask code in app.py reads the data from db for the usrename / password.
                  check whether the username / password is valid or not and sends a message to this page which is displayed on top of the page
                 
* sqli_detector.py: python file to detect the vulnerabilites for the project
                  see section "Automating testing project"
                   
* sql_injection.log: penetration testing log file
                  logs url, input values for admin & password, status code

Starting the web project
---------------------
1. Make a directory "Project"
2. Go to the directory "Project"
3. Copy all the files in to "Project"
4. At command prompt invoke the web project using this command
   $ python3 app.py
5. Starts the webserver at port 5000

Testing the web project
---------------------
1. Invoke the url
   http://127.0.0.1:5000
2. Start testing

Automating testing project
---------------------------
1. Goto directory "Project"
2. Give executable permissions for sql_detector.py using following command
   sudo chmod +X sql_detector.py
4. Once this command is executed successfully the sql_detector.py can be executed with the below command to trigger the testing sequence
   sudo python3 sql_detector.py
5. the log file is generated with filename "sql_injection.log"   
6. check the log file for the details

