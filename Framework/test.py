import logging
import sys
import mysql.connector
from mysql.connector import MySQLConnection, Error
logger = logging.getLogger(__name__)
#Alertkey = sys.argv[1]
#Identifier = sys.argv[2]
#test = Alertkey+"_"+Identifier;
#print(test)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='C:/Users/pallasin/Desktop/Framework/Logfile/test.log', filemode='w', level=logging.DEBUG)
#logging.info('This message is a new one. Thanks')
try:
    mydb1 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "alertsdatabaseDemo")
    logging.info("Sucessfully Logged into Alerts DB")
    #print(mydb1)
except Error as e:
        logging.error("Unable to Login to Alerts DB")
        logging.error(e)
try:
    mydb2 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "archivaldbDemo")
    logging.info("Sucessfully Logged into Archival DB")
    #print(mydb2)
except Error as e:
        logging.error("Unable to Login to Archival DB")
        logging.error(e)

try:
    mydb3 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "JobDetails")
    logging.info("Sucessfully Logged into Parameter DB")
    #print(mydb1)
except Error as e:
        logging.error("Unable to Login to Parameter DB")
        logging.error(e)
myCursor1 = mydb1.cursor(buffered=True,dictionary=True)
myCursor2= mydb2.cursor(buffered=True,dictionary=True)
myCursor3= mydb3.cursor(buffered=True,dictionary=True)

###############################################################################################################################

try:
    myCursor2.execute("SELECT * FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE `Ticket_Status` = 2;")
    output = myCursor2.fetchall()
    #logging.info(output)
    x = [d['Alertkey'] for d in output]
    y = [d['Identifier'] for d in output] 
    #print(x)
    #print(y)
    for a, b in zip(x, y):
        #print(a, b)
        logging.info("Alert having Alert_Key = "+ a +" and Identifier = "+ b  +" added to ArchivalDB")
    myCursor2.execute("INSERT INTO archivaldbDemo.archivaldbDemo (Alertkey,Identifier,Node,Agent,AlertGroup,Manager,Serial_No,FirstOccurrence,Severity,Ticket_Creation_Time,Ticket_Submmission_Time,LastOccurrence,ClearTime,Alert_Type,Ticket_Closure_Time,Summary,Description,Server_Name,Platform,Additional_Details,Assigment_Group,Ticket_Urgency,Ticket_Impact,CIName,Ticket_Flag,Suppression_Flag,Tally,Correlation_Id,Correlation_Flag,Additional_Field1,Additional_Field2,Additional_Field3,Additional_Field4,Additional_Field5,Alert_ID,Ticket_int,Ticket_Status,Customer) SELECT * FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE Ticket_Status = 2;")
    if len(output) == 0:
        logging.error("No Alert Found in Alerts DB with Ticket Status = 2")
        logging.error("Exiting the Script")
        sys.exit()
       
except Error as e:
        logging.error("Unable to Insert alerts with Ticket Status = 2 into Archival DB")
        logging.error(e)
        logging.error("Exiting the Script")
        sys.exit()
try:
    myCursor2.execute("UPDATE archivaldbDemo SET Delete_at = CURRENT_TIMESTAMP();")
    
except Error as e:
    logging.error(e)
    
try:
    myCursor2.execute("DELETE FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE Ticket_Status = 2;") 
    myCursor3.execute("INSERT INTO JobDetails.JobParameter(JobName,LastRun,NextRun)VALUES('Archival Operation',now(),NOW()+INTERVAL 12 HOUR);") 
    for a, b in zip(x, y):
        logging.info("Alert = " + a + " with Ticket Status = 2 deleted from Alerts DB")
except Error as e:
    logging.error("Unable to Delete Alert Keys with Ticket_Status = 2\n")
    logging.error(e)    
try:
    myCursor2.execute("SELECT * FROM archivaldbDemo;")   
    output2 = myCursor2.fetchall()
    #logging.info(output2)
except Error as e:
    logging.error("Data not found")
    logging.error(e)
    
"""try:
    myCursor3.execute("INSERT INTO JobDetails.JobParameter(JobName,LastRun,NextRun)VALUES('Archival Operation',now(),NOW()+INTERVAL 12 HOUR);")   
    
except Error as e:
    logging.error("Unable to update Prameter DB")
    logging.error(e)"""
  
mydb2.commit()
mydb3.commit()
mydb1.commit()
mydb1.close()
mydb2.close()  
mydb3.close()