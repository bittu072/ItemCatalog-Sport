# ITEM CATALOG - Sports
***
### Introduction
This project is about developing a RESTful web application using Flask along with implementing third-party OAuth authentication.
Also, It is about Mapping HTTP method to relate and implement CRUD operations

For the database, this app uses SQLAlchemy ORM.
### Features
* Written in Pyhton  

### What's included
```
ItemCatalog-Sport/
  |-- static
	|-- js
		|-- jquery.js
	|-- style.css
	|-- title.css
  |-- templates
    |-- {{all the html files}}
  |-- data.py
  |-- database_setup.py
  |-- project.py
```

### Library Requirement:
flask, json, sqlalchemy, oauth2client, httplib2, build of vagrant

### Instruction:
To run this web application,
* Install Vagrant and VirtualBox 
* Clone this repository inside created vagrant directory
* Launch the Vagrant VM
   * If you are new to vagrant and virtual box,
    1. After downoading vagrant, open terminal and cd to the vagrant directory
    2. Type `vagrant up`
    3. Type `vagrant ssh`, you should be inside virtual machine *

* Edit functionality of web application in project. py
* Run a web application on loaclhost by typing `python project.py`

### File description:
**`project.py`**
This is the main project API file, which has all the function defined to connet to the database, login authentication, request or submit a query  
**`database_setup.py`**
This file is the definition of the database to create all the tables and columns  
**`data.py`** 
This is a data generation file. To test your application with some datas, run this file.
