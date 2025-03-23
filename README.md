-- Setup mysql on local --
create user 'shubham'@'localhost';
create database userservice;
grant all privileges on userservice.* to 'shubham'@'localhost';