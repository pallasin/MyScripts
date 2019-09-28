CREATE DATABASE alertsdatabaseDemo;
USE alertsdatabaseDemo;
CREATE TABLE alertsdatabaseDemo (
Alertkey    VARCHAR(155),
Identifier    VARCHAR(256),
Node    VARCHAR(155),
Agent    VARCHAR(155),
AlertGroup    VARCHAR(155),
Manager    VARCHAR(155),
Serial_No int(11) unsigned NOT NULL AUTO_INCREMENT,
FirstOccurrence    DATETIME,
Severity    int(15),
Ticket_Creation_Time  DATETIME,
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
Tally    int(15) Default 0,
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
PRIMARY KEY(Identifier),
KEY(Serial_No)
);

show tables;
describe alertsdatabaseDemo;
DELETE FROM alertsdatabaseDemo ;
select * from alertsdatabaseDemo;
UPDATE alertsdatabaseDemo SET Serial_No = 3;
UPDATE alertsdatabaseDemo SET Ticket_Status =3 WHERE Alertkey = 'CARNI_Zaandam_ship_down';
UPDATE alertsdatabaseDemo SET Ticket_Flag = ITSM_Instance WHERE alertsdatabaseDemo.Customer = Transform.Destination_table;
SELECT @@GLOBAL.secure_file_priv;
#LOAD DATA LOCAL INFILE "Alert1.log" INTO TABLE mytable;
SHOW VARIABLES LIKE "secure_file_priv";
select * from alertsdatabaseDemo into outfile 'C:\ProgramData\MySQL\MySQL Server 8.0\Uploads\Alert1.log' LINES TERMINATED BY '\n';
DROP TABLE alertsdatabaseDemo;
UPDATE alertsdatabaseDemo SET Alert_ID = concat(Server_Name, '_', Serial_No);
UPDATE alertsdatabaseDemo SET FirstOccurrence = CURRENT_TIMESTAMP(),LastOccurrence = CURRENT_TIMESTAMP();
UPDATE alertsdatabaseDemo SET Ticket_Status = 3,Ticket_Creation_Time = CURRENT_TIMESTAMP();
UPDATE alertsdatabaseDemo SET Ticket_int = concat('INC','_',Serial_No);
UPDATE alertsdatabaseDemo SET Ticket_int = 0;
UPDATE alertsdatabaseDemo SET Ticket_Submmission_Time = CURRENT_TIMESTAMP();

UPDATE alertsdatabaseDemo.alertsdatabaseDemo INNER JOIN Transform.Assigment_table ON Transform.Ticket_Status.Alertkey = alertsdatabaseDemo.alertsdatabaseDemo.Alertkey AND alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Staus = 3 SET alertsdatabaseDemo.alertsdatabaseDemo.Ticket_Status = 2;
