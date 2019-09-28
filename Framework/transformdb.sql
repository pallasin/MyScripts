CREATE SCHEMA Transform;
CREATE DATABASE Transform;
USE Transform;
CREATE TABLE Destination_table (
Customer    VARCHAR(155),
ITSM_Instance    VARCHAR(156),
FullName    VARCHAR(157)
);
CREATE TABLE Assigment_table (
Customer    VARCHAR(155),
HostName    VARCHAR(155),
Platform    VARCHAR(155),
AlertGroup    VARCHAR(155),
AlertKey    VARCHAR(155),
Assignment_Group    VARCHAR(155),
Parameter_    VARCHAR(155)
);
CREATE TABLE Priority_table (
Customer    VARCHAR(155),
Severity    VARCHAR(155),
Urgency    VARCHAR(155),
Impact    VARCHAR(155),
Priority    VARCHAR(155)
);
CREATE TABLE Ticket_Status (
Alertkey VARCHAR(155),
Ticket_Creation_Time    DATETIME,
Ticket_Closure_Time    DATETIME,
Ticket_int    VARCHAR(155),
Ticket_Status    VARCHAR(155),
Alert_ID    VARCHAR(155)
);
DROP TABLE Ticket_Status;
show tables;
INSERT into Ticket_Status(Alertkey,Ticket_Creation_Time,Ticket_Closure_Time,Ticket_int,Ticket_Status,Alert_ID)VALUES('CARNI_Zaandam_ship_down',CURRENT_TIMESTAMP(),CURRENT_TIMESTAMP(),'INC00005',3,'USDAL_5');
INSERT into Destination_table(Customer,ITSM_Instance,FullName)VALUES('CONA',111,'Coke one NA');
INSERT into Destination_table(Customer,ITSM_Instance,FullName)VALUES('ALE',333,'Alcatel');
INSERT into Destination_table(Customer,ITSM_Instance,FullName)VALUES('CARNI',222,'Carnival');
select * from Destination_table;
DELETE from Destination_table;
DELETE from Ticket_Status;
Select * from Ticket_Status;
UPDATE Ticket_Status SET Ticket_Status =2 WHERE Alertkey = 'CARNI_Quest_ship_down';
select * from Priority_table;
INSERT into Priority_table(Customer,Severity,Urgency,Impact,Priority)VALUES('CARNI',5,1,1,'P1');
INSERT into Priority_table(Customer,Severity,Urgency,Impact,Priority)VALUES('CARNI',4,2,2,'P2');
INSERT into Priority_table(Customer,Severity,Urgency,Impact,Priority)VALUES('CARNI',3,3,3,'P3');
INSERT into Priority_table(Customer,Severity,Urgency,Impact,Priority)VALUES('CARNI',2,4,4,'P4');
INSERT into Priority_table(Customer,Severity,Urgency,Impact,Priority)VALUES('CARNI',5,5,5,'P5');
DELETE FROM Priority_table;
INSERT into Assigment_table(Customer,AlertGroup)VALUES('MOM','ABF');
INSERT into Assigment_table(Customer,Hostname,Assignment_Group)VALUES('CGNIS','bhd','Hello');
INSERT into Assigment_table(Customer,Platform,Assignment_Group)VALUES('CARNI','SolarWinds','SolarWind_Wintel_Team');
DELETE FROM Assigment_table;

UPDATE Transform.Ticket_Status SET Ticket_Status =2 WHERE Alertkey = 'CARNI_Zaandam_ship_down';

select * from Assigment_table;
SELECT (CASE WHEN IFNULL(Hostname,'') ='' AND IFNULL(Platform,'') = '' then "UnManaged" ELSE Transform.Assigment_table.Assignment_Group END )FROM Transform.Assigment_table;
UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Assigment_table ON Transform.Assigment_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer SET alertsdatabaseDemo.alertsdatabaseDemo.Assigment_Group = (CASE WHEN IFNULL(Transform.Assigment_table.Hostname,'') ='' AND IFNULL(Transform.Assigment_table.Platform,'') = '' then "UnManaged" ELSE Transform.Assigment_table.Assignment_Group END ); 
 
UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Destination_table ON Transform.Destination_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer SET alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Flag = Transform.Destination_table.ITSM_Instance;

UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Priority_table ON Transform.Priority_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer AND alertsdatabaseDemo.alertsdatabaseDemo.Severity = alertsdatabaseDemo.alertsdatabaseDemo.Severity SET alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Urgency = Transform.Priority_table.Urgency, alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Impact = Transform.Priority_table.Impact;

UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Assigment_table ON Transform.Assigment_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer AND Transform.Assigment_table.Platform != ''  SET alertsdatabaseDemo.alertsdatabaseDemo.Assigment_Group = Transform.Assigment_table.Assignment_Group;

UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Assigment_table ON Transform.Assigment_table.Customer = alertsdatabaseDemo.alertsdatabaseDemo.Customer AND alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Flag != 0 AND alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Flag != 1 SET alertsdatabaseDemo.alertsdatabaseDemo.Assigment_Group = (CASE WHEN IFNULL(Transform.Assigment_table.Hostname,'') AND IFNULL(Transform.Assigment_table.Platform,'') then 'UnManaged' ELSE Transform.Assigment_table.Assignment_Group END);

INSERT INTO Transform.Ticket_Status SELECT Alertkey, Ticket_Creation_Time,Ticket_Closure_Time,Ticket_int,Ticket_Status,Alert_ID FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE Ticket_Status = 3;