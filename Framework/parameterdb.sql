CREATE SCHEMA JRD;
CREATE DATABASE JobDetails;
USE JobDetails;
CREATE TABLE JobParameter (
JobName    VARCHAR(155),
LastRun    DATETIME,
NextRun    DATETIME
);
show tables;
describe JobParameter;
Select * from JobParameter;
INSERT INTO JobDetails.JobParameter(JobName,LastRun,NextRun)VALUES('Archival Operation',now(),NOW()+INTERVAL 12 HOUR);
delete from JobParameter;

