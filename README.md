# project-3-fullstack


## Introduction

This is the project 3 blog app for Udacity Fullstack Nanodegree. This app covers the basics features such as...
- designing a basic blog
- User Registration and Authentication
- Add Login and Logout 
- create/delete posts and comments 


## Requirements

* python >= 2.7
* web browser: any recent stable release of Safari/Chrome/Firefox


## Usage

Simplest 
* 1. Visit http://blog-app-project-3.appspot.com/
* 2. Run this application locally. 
	1. Download or clone from https://github.com/SangTran01/project-3-fullstack
    2. Using windows terminal where the folder is located, type "dev_appserver.py project-3-fullstack"
    3. Open up a web browser and enter "localhost:8080" into the URL search bar
* 3. Use Google App Engine Launcher 
	1. Download or clone from https://github.com/SangTran01/project-3-fullstack
    2. Import folder into GAE Launcher then click "Run"
    3. 3. Open up a web browser and enter "localhost:8080" into the URL search bar

## Details

* This application allows users to register/login to the website, this sets a cookie which confirms if they are the correct user 
* The sent cookie allows us to control what actions users can take. Example. create post/comment and like or dislike posts
* Without a cookie, users are only able to view the main blog page
