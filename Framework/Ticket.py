import logging
import sys
import mysql.connector
import datetime
from mysql.connector import MySQLConnection, Error
from prettytable import *
import csv

try:
    mydb1 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "alertsdatabaseDemo")
    logging.info("Sucessfully Logged into Alerts DB")
except Error as e:
        logging.error("Unable to Login to Alerts DB")
        logging.error(e)

myCursor1 = mydb1.cursor(buffered=True,dictionary=True)

#########################################################################################################################

try:

     myCursor1.execute("UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Ticket_Status ON Transform.Ticket_Status.Alertkey = alertsdatabaseDemo.alertsdatabaseDemo.Alertkey AND Transform.Ticket_Status.Ticket_Status = 2 SET alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Status = 2,alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Closure_Time=CURRENT_TIMESTAMP();")
     
     myCursor1.execute("DELETE FROM Transform.Ticket_Status WHERE Ticket_Status = 2;") 
     
    
except Error as e:
    logging.error("Unable to Change Ticket Status to 2")
    logging.error(e)

"""try:
    myCursor1.execute("INSERT INTO Transform.Ticket_Status SELECT Alertkey, Ticket_Creation_Time,Ticket_Closure_Time,Ticket_int,Ticket_Status,Alert_ID FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Status = 3;")
    
    
except:
    logging.error("Unable to add alert to Transform DB")
    logging.error(e)
"""

 
mydb1.commit()
mydb1.close()