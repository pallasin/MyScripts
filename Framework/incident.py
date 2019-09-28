import logging
import sys
import mysql.connector
import datetime
from mysql.connector import MySQLConnection, Error
from prettytable import *
import random
logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='C:/Users/pallasin/Desktop/Framework/Demo/Logs/Alert.log', filemode='a', level=logging.DEBUG)
LogFile1 = "C:/Users/pallasin/Desktop/Framework/Demo/Logs/Incident.log"
#LogFile2 = "C:/Users/pallasin/Desktop/Framework/Demo/Logs/Incident1.log"


try:
    mydb1 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "alertsdatabaseDemo")
    
    logging.info("Sucessfully Logged into Alerts DB")
    #print(mydb1)
except Error as e:
        logging.error("Unable to Login to Alerts DB")
        logging.error(e)

myCursor1 = mydb1.cursor(buffered=True,dictionary=True)


#########################################################################################################################
try:
    myCursor1.execute("UPDATE alertsdatabaseDemo SET Ticket_Status = 3,Ticket_Creation_Time = CURRENT_TIMESTAMP();")
except Error as e:
    logging.error("")


try:

    #logging.info("Database Fetched")
    myCursor1.execute("SELECT * FROM alertsdatabaseDemo;")
    
    outputTable = myCursor1.fetchall()
    f = open(LogFile1, "w")
    #myCursor1.execute("UPDATE alertsdatabaseDemo SET Ticket_int = 3;")
    #myCursor1.execute("UPDATE alertsdatabaseDemo SET Alert_ID = concat(Server_Name, '_', Serial_No);")
    myCursor1.execute("UPDATE alertsdatabaseDemo SET Ticket_int = concat('INC','0000',Serial_No);")
    
except Error as e:
    logging.error("Unable to Fetch Data")
    logging.error(e)
    

x = PrettyTable()
tableFields = ["Alertkey", "Identifier", "Node", "Agent", "AlertGroup", "Manager", "Serial_No", "FirstOccurrence", "Severity", "Ticket_Creation_Time", "Ticket_Submmission_Time", "LastOccurrence", "ClearTime", "Alert_Type","Ticket_Closure_Time","Summary","Description","Server_Name","Platform","Additional_Details","Assigment_Group","Ticket_Urgency","Ticket_Impact","CIName","Ticket_Flag","Suppression_Flag","Tally","Correlation_Id","Correlation_Flag","Additional_Field1","Additional_Field2","Additional_Field3","Additional_Field4","Additional_Field5","Alert_ID","Ticket_int","Ticket_Status","Customer"]
x.field_names = tableFields
#outputTable = myCursor1.fetchall()
#f = open(LogFile1, "w")
for o in outputTable:
    data = []
    for colname in tableFields:
        data.append(o[colname])
        
    x.add_row(data)
f = open(LogFile1, "w")
f.write(str(x))
f.close 
mydb1.commit()
mydb1.close()    
        
        
        

    



