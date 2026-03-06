# AI-Powered Ransomware Early Detection and Prevention Platform

## About the Project

This project is a simple AI-based security system that detects ransomware attacks at an early stage and helps protect the system from damage.

The system monitors system activity and analyzes behavior using a machine learning model. If it finds activity that looks similar to ransomware behavior, it generates an alert and can take preventive action.

The project also includes a small web dashboard where users can see alerts and system status.

## Purpose

The main purpose of this project is to demonstrate how artificial intelligence can be used to detect ransomware attacks before files are encrypted.

Early detection can help reduce data loss and improve system security.

## Features

* Real-time monitoring of system activity
* Detection of suspicious behavior using machine learning
* Alert system when ransomware-like behavior is detected
* Basic prevention mechanism
* Simple web dashboard to view system status

## Technologies Used

* Python
* Flask
* Machine Learning
* HTML
* Scikit-learn
* Pandas

## Project Files

app.py – runs the main application
ai_engine.py – handles ransomware detection logic
data_collector.py – collects system activity data
train_models.py – trains the machine learning model
requirements.txt – contains required libraries

templates/index.html – web dashboard page

## How to Run the Project

Install required libraries:

pip install -r requirements.txt

Run the application:

python app.py

Open the browser and go to:

http://127.0.0.1:5000

## How It Works

The system continuously monitors system activity using the data collector module.
Collected data is analyzed by the AI detection engine.

If the behavior matches patterns similar to ransomware activity, the system alerts the user and can trigger preventive actions.

## Note

This project is created for educational purposes to demonstrate ransomware detection using machine learning.
