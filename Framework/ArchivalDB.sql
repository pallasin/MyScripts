CREATE SCHEMA archivaldbDemo;
CREATE DATABASE archivaldbDemo;
USE archivaldbDemo;
CREATE TABLE archivaldbDemo (
Alertkey    VARCHAR(155),
Identifier    VARCHAR(256),
Node    VARCHAR(155),
Agent    VARCHAR(155),
AlertGroup    VARCHAR(155),
Manager    VARCHAR(155),
Serial_No    int(15),
FirstOccurrence    DATETIME,
Severity    int(15),
Ticket_Creation_Time    DATETIME,
Ticket_Submmission_Time    DATETIME,
LastOccurrence    DATETIME,
ClearTime    DATETIME,
Alert_Type    VARCHAR(155),
Ticket_Closure_Time    DATETIME,
Summary    VARCHAR(255),
Description    VARCHAR(4500),
Server_Name    VARCHAR(155),
Platform    VARCHAR(155),
Additional_Details    VARCHAR(4500),
Assigment_Group    VARCHAR(155),
Ticket_Urgency    int(15),
Ticket_Impact    int(15),
CIName    VARCHAR(155),
Ticket_Flag    int(15),
Suppression_Flag    int(15),
Tally    int(15),
Correlation_Id    VARCHAR(155),
Correlation_Flag    int(15),
Additional_Field1    VARCHAR(155),
Additional_Field2    VARCHAR(155),
Additional_Field3    VARCHAR(155),
Additional_Field4    VARCHAR(155),
Additional_Field5    VARCHAR(155),
Alert_ID    VARCHAR(155),
Ticket_int    VARCHAR(155),
Ticket_Status    int(15),
Customer    VARCHAR(155),
Delete_at    DATETIME,
PRIMARY KEY(Alert_ID)
);
show tables;
describe archivaldbDemo;
DELETE FROM archivaldbDemo;
SELECT * FROM archivaldbDemo;
SELECT * FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE `Ticket_Status` = 2;
INSERT INTO archivaldbDemo.archivaldbDemo (Alertkey,Identifier,Node,Agent,AlertGroup,Manager,Serial_No,FirstOccurrence,Severity,Ticket_Creation_Time,Ticket_Submmission_Time,LastOccurrence,ClearTime,Alert_Type,Ticket_Closure_Time,Summary,Description,Server_Name,Platform,Additional_Details,Assigment_Group,Ticket_Urgency,Ticket_Impact,CIName,Ticket_Flag,Suppression_Flag,Tally,Correlation_Id,Correlation_Flag,Additional_Field1,Additional_Field2,Additional_Field3,Additional_Field4,Additional_Field5,Alert_ID,Ticket_int,Ticket_Status,Customer) SELECT * FROM alertsdatabaseDemo.alertsdatabaseDemo WHERE Ticket_Status = 2;
