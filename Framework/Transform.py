import logging
import sys
import mysql.connector
import datetime
from mysql.connector import MySQLConnection, Error
from prettytable import *
logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='C:/Users/pallasin/Desktop/Framework/Demo/Logs/Alert.log', filemode='a', level=logging.DEBUG)
LogFile3 = "C:/Users/pallasin/Desktop/Framework/Demo/Logs/Incident3.log"
LogFile2 = "C:/Users/pallasin/Desktop/Framework/Demo/Logs/Incident1.log"


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
        
try:
    mydb4 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "Transform")
    logging.info("Sucessfully Logged into Transfor DB")
    #print(mydb1)
except Error as e:
        logging.error("Unable to Login to Transfor DB")
        logging.error(e)
myCursor1 = mydb1.cursor(buffered=True,dictionary=True)
myCursor2= mydb2.cursor(buffered=True,dictionary=True)
myCursor3= mydb3.cursor(buffered=True,dictionary=True)
myCursor4= mydb4.cursor(buffered=True,dictionary=True)

#########################################################################################################################

try:
    myCursor1.execute("UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Destination_table ON Transform.Destination_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer SET alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Flag = Transform.Destination_table.ITSM_Instance;")
    logging.info("Ticket Flag Updated")
    
except Error as e:
    logging.error("Unable to Update Flag")
    logging.error(e)
    
try:
    myCursor1.execute("UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Priority_table ON Transform.Priority_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer AND Transform.Priority_table.Severity = alertsdatabaseDemo.alertsdatabaseDemo.Severity SET alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Urgency = Transform.Priority_table.Urgency, alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Impact = Transform.Priority_table.Impact;")
    logging.info("Alert's Urgency and Impact Updated")
    
except Error as e:
    logging.error("Unable to Update Urgency and Update")
    logging.error(e)
    
try:
    myCursor1.execute("UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Assigment_table ON Transform.Assigment_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer AND Transform.Assigment_table.Platform != ''  SET alertsdatabaseDemo.alertsdatabaseDemo.Assigment_Group = Transform.Assigment_table.Assignment_Group;")
    logging.info("Assignment Group Updated")
   
except Error as e:
    logging.error("Platform Not found. Searching for Hostname....")
    logging.error(e)
    
try:
    
    myCursor1.execute("UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Assigment_table ON Transform.Assigment_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer AND alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Flag != 0 AND alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Flag = 1 SET alertsdatabaseDemo.alertsdatabaseDemo.Assigment_Group = (CASE WHEN IFNULL(Transform.Assigment_table.Hostname,'') AND IFNULL(Transform.Assigment_table.Platform,'') then 'UnManaged' ELSE Transform.Assigment_table.Assignment_Group END);")
    myCursor1.execute("UPDATE alertsdatabaseDemo SET Ticket_Status = 1;")
    logging.info("Assignment Group Updated")
   
except Error as e:
    logging.error("Unable to update Assignment Group")
    logging.error(e)
    
try:
    myCursor1.execute("SELECT * FROM alertsdatabaseDemo;")
    outputTable = myCursor1.fetchall()
    f = open(LogFile3, "w")
    dateObj = datetime.datetime.today()
    dateCheckFormat = dateObj.strftime("%Y-%m-%d %H:%M:%S")
    for i in outputTable:
        str1 = ''
        for j,k in i.items():
            str1 += "{0} : {1}\n".format(j,k)
        f.write("\n\n{0} : {1}".format(dateCheckFormat,str1))
    f.close()
except Error as e:
    logging.error("Unable to update Assignment Group")
    logging.error(e)

try:
    myCursor3.execute("INSERT INTO JobDetails.JobParameter(JobName,LastRun,NextRun)VALUES('Alert Creation',now(),NOW()+INTERVAL 12 HOUR);") 
    myCursor1.execute("INSERT INTO alertsdatabaseDemo.alertsdatabaseDemo(Ticket_Submmission_Time)VALUES(CURRENT_TIMESTAMP());")     
    
except Error as e:
    logging.error("Unable to update Prameter DB")
    logging.error(e)

x = PrettyTable()
tableFields = ["Alertkey", "Identifier", "Node", "Agent", "AlertGroup", "Manager", "Serial_No", "FirstOccurrence", "Severity", "Ticket_Creation_Time", "Ticket_Submmission_Time", "LastOccurrence", "ClearTime", "Alert_Type","Ticket_Closure_Time","Summary","Description","Server_Name","Platform","Additional_Details","Assigment_Group","Ticket_Urgency","Ticket_Impact","CIName","Ticket_Flag","Suppression_Flag","Tally","Correlation_Id","Correlation_Flag","Additional_Field1","Additional_Field2","Additional_Field3","Additional_Field4","Additional_Field5","Alert_ID","Ticket_int","Ticket_Status","Customer"]
x.field_names = tableFields
for o in outputTable:
    data = []
    for colname in tableFields:
        data.append(o[colname])
        
    x.add_row(data)
f = open(LogFile2, "w")
f.write(str(x))
f.close 
mydb1.commit()
mydb2.commit;
mydb3.commit;  
mydb1.close()    
        
        
        

    



