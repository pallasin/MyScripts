import logging
import sys
import mysql.connector
import datetime
from mysql.connector import MySQLConnection, Error
from prettytable import *
import csv
logger = logging.getLogger(__name__)
#Alertkey = sys.argv[1]
#Identifier = sys.argv[2]
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='C:/Users/pallasin/Desktop/Framework/Demo/Logs/Alert.log', filemode='w', level=logging.DEBUG)


LogFile1 = "C:/Users/pallasin/Desktop/Framework/Demo/Logs/Tally.log"
filename1 = "C:/Users/pallasin/Desktop/Framework/Demo/Script/Alert3.csv"

fields = [] 
rows = []
output = []
with open(filename1, 'r') as csvfile: 
    csvreader = csv.reader(csvfile) 
    fields = list(csvreader)
    
def reemovNestings(fields): 
    for i in fields:
        if len(i) == 0:
            i = 0
        if type(i) == list: 
            reemovNestings(i)
        else: 
            output.append(i) 
reemovNestings(fields)
#print(fields) 
#print(output)
#output = ', '.join('%s' * len(output))
#print(var_string)
try:
    mydb1 = mysql.connector.connect(host = "localhost", user = "root", passwd = "root",database = "alertsdatabaseDemo")
    logging.info("Sucessfully Logged into Alerts DB")
except Error as e:
        logging.error("Unable to Login to Alerts DB")
        logging.error(e)

myCursor1 = mydb1.cursor(buffered=True,dictionary=True)

#########################################################################################################################

try:
    #myCursor1.execute(query_string, output)
    #myCursor1.execute("INSERT INTO alertsdatabaseDemo(Alertkey,Identifier,Node,Agent,AlertGroup,Manager,Severity,Alert_Type,Summary,Description,Server_Name,Platform,Customer,FirstOccurrence,LastOccurrence)VALUES(output[0],'nh','QUEST-PR2.seabourn.com','ITM','customAlert','MTTrapd Probe on corpprdtivmi15',5,1,'carnival_  QUEST-PR2.seabourn.com on ship Quest is down, at Monday, August 5, 2019 4:20 AM','carnival_  QUEST-PR2.seabourn.com on ship Quest is dow, at Monday, August 5, 2019 4:20 AM','USDAL','SolarWinds','CARNI',CURRENT_TIMESTAMP(),CURRENT_TIMESTAMP())ON DUPLICATE KEY UPDATE tally = tally+1,LastOccurrence = CURRENT_TIMESTAMP(),severity = 1,Summary = 'Node_Down';")
    #logging.info("Alert having Alert_Key = "+ Alertkey +" and Identifier = "+ Identifier  +" added to Alert")
    
    #myCursor1.execute("INSERT INTO alertsdatabaseDemo(Alertkey,Identifier,Node,Agent,AlertGroup,Manager,Severity,Alert_Type,Summary,Description,Server_Name,Platform,Additional_Details,CIName,Suppression_Flag,Additional_Field1,Additional_Field2,Additional_Field3,Additional_Field4,Additional_Field5,Ticket_int,Ticket_Status,Customer,FirstOccurrence,LastOccurrence)VALUES(%r,CURRENT_TIMESTAMP(),CURRENT_TIMESTAMP())ON DUPLICATE KEY UPDATE tally = tally+1,LastOccurrence = CURRENT_TIMESTAMP(),severity = 1,Summary = 'Node_Down';"%(tuple(output),)
    #logging.info("Alert having Alert_Key = "+ fields[0][0] +" and Identifier = "+ fields[1][0]  +" added to Alert")
    
    query_string = """INSERT INTO  alertsdatabaseDemo(Alertkey,Identifier,Node,Agent,AlertGroup,Manager,Severity,Alert_Type,Summary,Description,Server_Name,Platform,Additional_Details,CIName,Suppression_Flag,Additional_Field1,Additional_Field2,Additional_Field3,Additional_Field4,Additional_Field5,Ticket_int,Ticket_Status,Customer,FirstOccurrence,LastOccurrence,Tally) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP(),CURRENT_TIMESTAMP(),1)ON DUPLICATE KEY UPDATE tally = tally+1,LastOccurrence = CURRENT_TIMESTAMP();"""
    #"INSERT INTO table VALUES %r;" % (tuple(varlist),)
    #print(tuple(output))
    #print (len(output))
    myCursor1.execute(query_string, tuple(output))
    myCursor1.execute("UPDATE alertsdatabaseDemo SET Alert_ID = concat(Server_Name, '_', Serial_No);")
    #myCursor1.execute("UPDATE alertsdatabaseDemo SET FirstOccurrence = CURRENT_TIMESTAMP(),LastOccurrence = CURRENT_TIMESTAMP();")
    logging.info("Alert having Alert_Key  and Identifier added to Alert")
    #logging.info("Alert having Alert_Key = "+ output[0] +" and Identifier = "+ output [1] +" added to Alert")
except Error as e:
        logging.error("No Insertion Done")
        logging.error(e)
    
try:                                                                                                                                                                                     
    myCursor1.execute("SELECT * FROM alertsdatabaseDemo;")
    outputTable = myCursor1.fetchall()
    #f = open(LogFile1, "w")
    #for d in outputTable:
     #   f.write("Alertkey  :  %-20s  Tally   :   %s\n" %(str(d['Alertkey']),str(d['Tally'])))
    #f.close()

    x = PrettyTable()
    tableFields = ["Serial_No","LastOccurrence","Alertkey", "Tally"]
    x.field_names = tableFields
    for o in outputTable:
        data = []
        for colname in tableFields:
            data.append(o[colname])
            
        x.add_row(data)
    f = open(LogFile1, "w")
    f.write(str(x))

except Error as e:
    logging.error("Unable to fetch table")
    logging.error(e)
 
mydb1.commit()
mydb1.close()