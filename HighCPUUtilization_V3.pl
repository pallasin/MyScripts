##########################################################################################################
# Script Name : ManagementAgentLost.pl                                                                   #
# Purpose     : This is the main script which gets triggered by TEM layer for Managememt Agenet Lost     #
#               Network Alerts. The inputs and the Device type are validated. This module performs       # 
#				different checks such as Pinging and Polling the device, getting the traceroute results. #
#               This module also gathers the CPU amd Memory utilization of the Device along with the     #
#				Uptime and interface logs. Result of each step is maintained in a log file.              #
#               Log file is created and updated for each step.                                           #                                
# Author      : Sujeet Kumar Padhi                                                                       #
# Date        : 31/01/2017                                                                               #           
# Inputs      : DeviceType, Threshold, DeviceIP, Username, Encrypted Password, Ticket Number             #
##########################################################################################################


use strict;
use Net::SSH2;
use Net::SNMP;
use Net::Ping;
use Switch;
use Net::Telnet;

#use UtilityModule;
use UtilityModule_V3;

my $AlertExecId = $ARGV[0];
my $DeviceIP = $ARGV[1];
my $Attributes = $ARGV[2];

my $Command='';
my $LogFileH;
my $RTT='';

my $Community=undef;
my $ObjID=undef;
my $Username=undef;
my $EncrPass=undef;

my $EnablePasswd=undef;
my $DeviceType;
my $CPUThreshold;
my $MemThreshold;
my $OSName=undef;
my $CPUStatus=0;
my %RemoteOutput=();

my %OutputSet=();
my $flag=0;

#########################################################################################
# Subroutine Name : CheckCPUUtilization                                                 #
# Description     : This subroutine reads the DeviceType, CPU Threshold and the Network #
#                   Device CPU data fetched by the SSH protocol Processes the CPU data  #
#					and checks if current CPU utilization is above threshold. If yes,it #
#					obtains the top 5 CPU processes and writes to the log file. Returns #
#                   0 or 1 based on the CPU utilization.                                #
#########################################################################################

sub CheckCPUUtilization
 {

	my %ProcessCPU=@_;
	my $DeviceType=$ProcessCPU{'devicetype'};
	my $Threshold=$ProcessCPU{'threshold'};
	my $LogFileH=$ProcessCPU{'fileptr'};
	
	my $RemoteOutput=$ProcessCPU{'prostr'};

    switch ($DeviceType)
     {
	  case [@CiscoRTSW] 
		 {	
		    if(trim(${$RemoteOutput}{'show processes cpu'}) =~ /Invalid\s+input\s+detected/i)
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get CPU usage. \n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
		    
			if(trim(${$RemoteOutput}{'show processes cpu'}) ne "")
			   {
				 #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			   }
			 else
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
			
            #print ${$RemoteOutput}{'show processes cpu'};
			
			my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show processes cpu'});
			
			my $var=""; my @temp=(); my @temp1=(); my @temp2=();
			my $CPUStatus=0;
			my $line='';
			my $flag=undef;
			my $CurrentUtil="";
			
			# Check if Current CPU utilization if above threshold
			
				 foreach $line (@RemoteOutputSet)
				   {
					 if($line=~/CPU\sutilization/)
					 {
						  $flag=1;
						  $CurrentUtil=$line;
						  $var=substr($line,index($line,"five"));
						  @temp=split(";",$var);
							 foreach $line (@temp)
							   {
								  $line=~s/%//g;
								  @temp1=split(":",$line);
									  if(index($line,'/')!=-1)
										{
										   @temp2=split('/',$temp1[1]);
										   if (trim($temp2[0])>$Threshold)
											  {
												print $LogFileH GetDate." [LOG INFO]: CPU Threshold crossed for $temp1[0]. $CurrentUtil\n";
												$CPUStatus=1;
												last;
											  }  
										}
									   else
										{
										   if (trim($temp1[1])>$Threshold)
											  {
												print $LogFileH GetDate." [LOG INFO]: CPU Threshold crossed for $temp1[0]. $CurrentUtil\n";
												$CPUStatus=1;
												last;
											  }  
										}
								}
							  last;
						}  
				   }
				   
		    if(defined($flag))
			  {
			    if($CPUStatus==0)
			      {
				    print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";	
			      }
				else
				  {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					
				    my $i=0; my $j=0; 
			        my $index='';
			        my $max=0;
		 	        my $flag=0;	 
				    
                    # Get the top 5 CPU Processes if the CPU utilization is above threshold
 					
					 for($j=0;$j<5;$j++)
					   { 
						 $index = undef;
						 $max=0;
							for($i=0;$i<=$#RemoteOutputSet;$i++)
							  {
								next if($RemoteOutputSet[$i] =~ /CPU\sutilization/);
								next if(trim($RemoteOutputSet[$i]) eq "");
								next if(trim($RemoteOutputSet[$i]) =~ /show\sprocesses\scpu/);
						   
								if($RemoteOutputSet[$i]=~/PID/)
								  {
									if($flag==0)
									  {
										$flag=1;
										print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
										next;
									  }
									else
									  { 
										next;
									  }
								  }
								@temp=split(/\s+/,trim($RemoteOutputSet[$i]));
								
								next if($#temp < 5);
								next if(trim($temp[5])!~/^[0-9\.\%]+$/);
								
								$temp[5]=~s/%//g;
								if($max <= trim($temp[5])) 
								  {
									$max = trim($temp[5]);
									$index = $i;
								  }
							   }   
						 if(defined($index))
						    {
     						   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$index]."\n" if(trim($RemoteOutputSet[$index]) !~ /^$/);
						       $RemoteOutputSet[$index]="";
							}
					   }
					   
					 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  }
			  }
			 else
			  {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			  }
			return $CPUStatus;			
	     }
		 
	  case [@Checkpoint] 
         {
		   
		   if(trim(${$RemoteOutput}{'top -b -n 1'}) ne "")
			 {
			    #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
		     {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
		     }
			 
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'top -b -n 1'});
		   my @temp;
		   my $CurrentUtil;
		   my $flag1=0;
		   my $flag2=0;
		   my $CPUStatus=undef;
		   my $utilization;
		   
		   foreach(@RemoteOutputSet)
		     {
			   if(trim($_)=~/^cpu\(s\)/i)
			     {
				   $flag1=1;
				   $CurrentUtil=$_;
				   @temp = split(',',substr($_,index($_,':')+1));
				   foreach(@temp)
				     {
					   if($_=~/.*id/)
					     {
						   $flag2=1;
						   $_=~s/[a-z%]//g;
						   $utilization=100-trim($_);
						   if($utilization>$Threshold)
						     {
							   $CPUStatus=1;
							   print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold . $CurrentUtil\n";
							   print $LogFileH GetDate." [LOG INFO]: Current CPU utilization is $utilization%.\n";
							 }
							else
							 {
							   $CPUStatus=0;
							   print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";
							   print $LogFileH GetDate." [LOG INFO]: Current CPU utilization is $utilization%.\n";
							 }
					   last;
						 }
					 }
				   last;
				 }
			 }
			 
           if($flag1==1 and $flag2==1 and defined($CPUStatus))
		     {
			   if($CPUStatus==1)
			     {
				   my $startindex='';
				   my $i=0; my $j=0; 
			       my $index='';
			       my $max=0;
		 	       my $flag=0;
				   
				   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
				   
				   for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /^PID/)
						    {
							  $startindex=$i;
							  last;
							}
					   }
					
				   for($j=0;$j<5;$j++)
				      { 
						 $index = undef;
						 $max=0;
							for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
							  {
								next if(trim($RemoteOutputSet[$i]) =~ /^$/);
								if($RemoteOutputSet[$i]=~/PID/)
								  {
									if($j>0)
									  {
										last if($flag1==1);
										$flag1=1;
										next;
									  }
									if($flag==0)
									  {
										$flag=1;
										print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
										next;
									  }
									else
									  { 
										last;
									  }
								  }
								  
								@temp=split(/\s+/,trim($RemoteOutputSet[$i]));
								
								next if($#temp < 5);
								next if(trim($temp[8])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[8])) 
								  {
									$max = trim($temp[8]);
									$index = $i;
								  }
							   } 
						 $flag1=0;								   
						 if(defined($index))
						   {
							   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$index]."\n" if(trim($RemoteOutputSet[$index]) !~ /^$/);
							   $RemoteOutputSet[$index]="";
						   }
					  }
					   
					 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 }
			 }
           else
		     {
			   print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	           print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	           print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
			 }			 
		   return $CPUStatus;
		 }
      case [@F5Device]
         {
             if(trim(${$RemoteOutput}{'tmsh show sys cpu'}) ne "" and trim(${$RemoteOutput}{'top -b -n 1'}) ne "")
			   {
				 #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			   }
			 else
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys cpu'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
			   
			  my @RemoteOutputSet=split("\n",${$RemoteOutput}{'tmsh show sys cpu'});
			  my $flag=0;
			  my $utilization;
			  my $CurrentUtil;
			  my $CPUStatus=undef;
			  my $CurrentUtil;
			  
			  foreach(@RemoteOutputSet)
			    {
				  $CurrentUtil=$_;
				  if(trim($_)=~/^Utilization\s+([0-9]{1,3})\s.*/)
				    {
					  $flag=1;
					  $utilization=$1;
					  if($utilization > $Threshold)
					    {
						  $CPUStatus=1;
						  print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold.\n";
						  print $LogFileH GetDate." [LOG INFO]: Current utilization is $utilization%.\n";
						}
					  else
					    {
						  $CPUStatus=0;
						  print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now.\n";
						  print $LogFileH GetDate." [LOG INFO]: Current utilization is $utilization%.\n";
						}
					   last;
					}
				  
				}
			   
			   if(defined($CPUStatus) and $flag==1)
			     {
				   if($CPUStatus==1)
					 {
					   @RemoteOutputSet=split("\n",${$RemoteOutput}{'top -b -n 1'});
					   
					   #print join("\n",@RemoteOutputSet);
					   
					   my $startindex='';
					   my $i=0; my $j=0; 
					   my $index='';
					   my $max=0;
					   my $flag=0;
					   my $flag1=0;
					   my @temp;
					   
					   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					   
					   for($i=0;$i<=$#RemoteOutputSet;$i++)
						   {
							  if(trim($RemoteOutputSet[$i]) =~ /^PID/)
								{
								  $startindex=$i;
								  last;
								}
						   }
						
						for($j=0;$j<5;$j++)
						   { 
							 $index = undef;
							 $max=0;
								for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
								  {
									next if(trim($RemoteOutputSet[$i]) =~ /^$/);
									if($RemoteOutputSet[$i]=~/PID/)
									  {
									    if($j>0)
										  {
										    last if($flag1==1);
											$flag1=1;
											next;
										  }
										if($flag==0)
										  {
											$flag=1;
											print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
											next;
										  }
										else
										  { 
											last;
										  }
									  }
									  
									@temp=split(/\s+/,trim($RemoteOutputSet[$i]));
									
									next if($#temp < 5);
									next if(trim($temp[8])!~/^[0-9\.\%]+$/);
									
									if($max <= trim($temp[8])) 
									  {
										$max = trim($temp[8]);
										$index = $i;
									  }
								   } 
                             $flag1=0;								   
							 if(defined($index))
						       {
     						       print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$index]."\n" if(trim($RemoteOutputSet[$index]) !~ /^$/);
						           $RemoteOutputSet[$index]="";
							   }
						   }
						   
						print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					 }
				 }
			   else
		         {
				   print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys cpu'})." \n";
				   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
				   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				   print $LogFileH GetDate." [STATUS ]: Failure \n";
				   close $LogFileH;
				   exit 1;
			     }	
				 
			   return $CPUStatus;
         }
	  case [@Bluecoat]
	     {
		   if(trim(${$RemoteOutput}{'show status'}) ne "" and trim(${$RemoteOutput}{'show cpu-monitor'}) ne "")
			 {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
			 {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show status'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show cpu-monitor'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			 }
			 
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show status'});
		   my $utilization;
		   my $flag=0;
		   my $CPUStatus=undef;
		   my $CurrentUtil;
		   
		   foreach(@RemoteOutputSet)
		     {
			   $CurrentUtil=$_;
			   if(trim($_)=~/CPU\sutilization:\s+([0-9]{1,3})%.*/)
			     {
				   $utilization=$1;
				   $flag=1;
				   
				   if($utilization > $Threshold)
					 {
					   $CPUStatus=1;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold. $CurrentUtil\n";
					 }
				   else
					 {
					   $CPUStatus=0;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";
					 }
				   last;
				 }
			 }
			 
		   if(defined($CPUStatus) and $flag==1)
		     {
			   if($CPUStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'show cpu-monitor'});
					
					$RemoteOutputSet[$#RemoteOutputSet]='';
					
					foreach(@RemoteOutputSet)
					  {
					    chomp;
			            next if(trim($_)=~/show\scpu\-monitor/);
				        next if(trim($_)=~/^$/);
				        print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  }
					  
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 }
			 }
		   else
		     {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show status'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show cpu-monitor'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $CPUStatus;
		 }
	  case [@Fortinet]
	     {
		   
		   if(trim(${$RemoteOutput}{'get system performance status'}) ne "" and trim(${$RemoteOutput}{'diagnose sys top-summary'}) ne "")
			 {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
			 {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'get system performance status'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'diagnose sys top-summary'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			 }
			 
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'get system performance status'});
		   my $flag=0;
		   my $utilization;
		   my $CPUStatus=undef;
		   my $CurrentUtil;
		   
	   
		   foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
				if(trim($_)=~/CPU\sstates.*\s+([0-9]{1,3})%\s+idle/i)
				  {
					$flag=1;
					$utilization = 100-$1;
					
					if($utilization > $Threshold)
					 {
					   $CPUStatus=1;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold. $CurrentUtil\n";
					 }
				    else
					 {
					   $CPUStatus=0;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";
					 }
				    last;
				  }
			  }
			  
		    if(defined($CPUStatus) and $flag==1)
		     {
			   if($CPUStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'diagnose sys top-summary'});
					
					my $startindex;
		            my $i=0; my $j=0;
					my $index='';
					my $max=0;
					my $flag=0;
					my @temp;
					
					for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /^PID/)
						    {
							  $startindex=$i+1;
							  last;
							}
					   }
					
					for($j=0;$j<5;$j++)
					   { 
						 $index = undef;
						 $max=0;
							for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
							  {
								next if(trim($RemoteOutputSet[$i]) =~ /^$/);
								if(trim($RemoteOutputSet[$i]) =~ /^\*/)
								  {
								    $RemoteOutputSet[$i]=~s/^\*//i;
								  }
								if($RemoteOutputSet[$i]=~/PID/)
								  {
									if($flag==0)
									  {
										$flag=1;
										print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
										next;
									  }
									else
									  { 
										last;
									  }
								  }
								  
								next if(trim($RemoteOutputSet[$i])!~/^[0-9]+.*/);
								
								@temp=split(/\s+/,trim($RemoteOutputSet[$i]));
								
								next if($#temp < 5);
								next if(trim($temp[2])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[2])) 
								  {
									$max = trim($temp[2]);
									$index = $i;
								  }
							   }   
						 if(defined($index))
						    {
     						   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$index]."\n" if(trim($RemoteOutputSet[$index]) !~ /^$/);
						       $RemoteOutputSet[$index]="";
							}
					   }

                    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";					   
				 }
			 }
		   else
		     {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'get system performance status'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'diagnose sys top-summary'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $CPUStatus; 
			 
		 }		 
	  case [@CiscoASA]
	    {
		  if(trim(${$RemoteOutput}{'show cpu usage'}) =~ /Invalid\s+input\s+detected/i)
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get CPU usage.\n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show cpu usage'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
			   
			if(trim(${$RemoteOutput}{'show cpu usage'}) ne "" or trim(${$RemoteOutput}{'show processes cpu-usage sorted non-zero'}) ne "")
			   {
				 #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			   }
			 else
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show cpu usage'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu-usage sorted non-zero'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
			
            #print ${$RemoteOutput}{'show processes cpu'};
			
			my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show cpu usage'});
			
			my $var=""; my @temp=(); my @temp1=(); my @temp2=();
			my $CPUStatus=0;
			my $line='';
			my $flag=undef;
			my $CurrentUtil="";
			
			# Check if Current CPU utilization if above threshold
			
				 foreach $line (@RemoteOutputSet)
				   {
					 if($line=~/CPU\sutilization/)
					 {
						  $flag=1;
						  $CurrentUtil=$line;
						  $line=~s/\=/\:/g;
						  $var=substr($line,index($line,'5 seconds'));
						  @temp=split(";",$var);
							 foreach $line (@temp)
							   {
								  $line=~s/%//g;
								  @temp1=split(":",$line);
									  if(index($line,'/')!=-1)
										{
										   @temp2=split('/',$temp1[1]);
										   if (trim($temp2[0])>$Threshold)
											  {
												print $LogFileH GetDate." [LOG INFO]: CPU Threshold crossed for $temp1[0]. $CurrentUtil\n";
												$CPUStatus=1;
												last;
											  }  
										}
									   else
										{
										   if (trim($temp1[1])>$Threshold)
											  {
												print $LogFileH GetDate." [LOG INFO]: CPU Threshold crossed for $temp1[0]. $CurrentUtil\n";
												$CPUStatus=1;
												last;
											  }  
										}
								}
							  last;
						}  
				   }
				   
		    if(defined($flag))
			  {
			    if($CPUStatus==0)
			      {
				    print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";	
			      }
				else
				  {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					
					if(trim(${$RemoteOutput}{'show processes cpu-usage sorted non-zero'}) =~ /Invalid\s+input\s+detected/i)
					  {
						 print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get CPU processes.\n";
				         print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu-usage sorted non-zero'})." \n";
						 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
						 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
						 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
						 print $LogFileH GetDate." [STATUS ]: Failure \n";
						 close $LogFileH;
						 exit 1;
					   }
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'show processes cpu-usage sorted non-zero'});
					
				    my $i=0;
                    my $j=0;					
					my $startindex;
				    
                    # Get the top 5 CPU Processes if the CPU utilization is above threshold
 					
					 
					 for($i=0;$i<=$#RemoteOutputSet;$i++)
						   {
							  if(trim($RemoteOutputSet[$i]) =~ /^\bPC\b/)
								{
								  $startindex=$i;
								  last;
								}
						   }
						   
					 for($j=$startindex;$j<=$startindex+5;$j++)
					   { 
					      next if(trim($RemoteOutputSet[$j])=~/^$/);
						  print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$j]."\n";
					   }
					   
					 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  }
			  }
			 else
			  {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show cpu usage'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu-usage sorted non-zero'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			  }
			return $CPUStatus;			
		}
	  case [@CiscoNexus]
	    {
		  if(trim(${$RemoteOutput}{'show system resources'}) ne "" or trim(${$RemoteOutput}{'show processes cpu'}) ne "")
		    {
			   #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
		    }
		  else
		    {
			   print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system resources'})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu'})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	           print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	           print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
		    }
			
		  my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show system resources'});
		  my $flag=0;
		  my $utilization;
		  my $CPUStatus=undef;
		  my $CurrentUtil;
		   
		  foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
				if(trim($_)=~/^CPU\sstates.*\s+([0-9]{1,3}\.[0-9]{1,3})%\s+idle/i)
				  {
					$flag=1;
					$utilization = 100-$1;
					
					if($utilization > $Threshold)
					 {
					   $CPUStatus=1;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold. $CurrentUtil\n";
					 }
				    else
					 {
					   $CPUStatus=0;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";
					 }
				    last;
				  }
			  }
			  
		   if($flag==1 and defined($CPUStatus))
		     {
			   if($CPUStatus==1)
			     {
				   @RemoteOutputSet=split("\n",${$RemoteOutput}{'show processes cpu'});
				   
				   my $startindex='';
				   my $i=0; my $j=0; 
			       my $index='';
			       my $max=0;
		 	       my $flag=0;
				   my @temp;
				   
				   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
				   
				   for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /^PID/)
						    {
							  $startindex=$i;
							  last;
							}
					   }
					
					for($j=0;$j<5;$j++)
					   { 
						 $index = undef;
						 $max=0;
							for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
							  {
								next if(trim($RemoteOutputSet[$i]) =~ /^$/);
								if($RemoteOutputSet[$i]=~/PID/)
								  {
									if($flag==0)
									  {
										$flag=1;
										print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
										next;
									  }
									else
									  { 
										next;
									  }
								  }
								  
								@temp=split(/\s+/,trim($RemoteOutputSet[$i]));
								
								#next if($#temp < 5);
								next if(trim($temp[4])!~/^[0-9\.\%]+$/);
								
								$temp[4]=~s/%//g;
								
								if($max <= trim($temp[4])) 
								  {
									$max = trim($temp[4]);
									$index = $i;
								  }
							   }   
						 if(defined($index))
						    {
     						   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$index]."\n" if(trim($RemoteOutputSet[$index]) !~ /^$/);
						       $RemoteOutputSet[$index]="";
							}
					   }
					   
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 }
			 }
           else
		     {
			   print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system resources'})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes cpu'})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	           print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	           print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
			 }			 
		   return $CPUStatus;
		}
	  case [@JunOS]
	  {		   
		if(trim(${$RemoteOutput}{'show chassis routing-engine'}) ne "" and trim(${$RemoteOutput}{'show system processes extensive'}) ne "")
		{
			#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
		}
		else
		{
			print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
			print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show chassis routing-engine'})." \n";
			print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system processes extensive'})." \n";
			print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			print $LogFileH GetDate." [STATUS ]: Failure \n";
			close $LogFileH;
			exit 1;
		}
			 
		  my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show chassis routing-engine'});
		   my $flag=0;
		   my $utilization;
		   my $CPUStatus=undef;
		   my $CurrentUtil;
		   my $line;
		   my $var;
		   my @tempstore=();
			my $k=0;
	
				 	for(my $i=0;$i<$#RemoteOutputSet;$i++)
					{
						
						if($RemoteOutputSet[$i] =~ /User\s+([0-9]+)\s+percent/i)
						{	
							$flag=1;
							$tempstore[$i]=$1;
							
							if($tempstore[$i] > $Threshold)
								{
									$CPUStatus=1;
									print $LogFileH GetDate." [LOG INFO]: CPU utilization for Slot$k has crossed threshold. $tempstore[$i] % \n";
									next LOOP1
								}
								else
								{
									$CPUStatus=0;
									print $LogFileH GetDate." [LOG INFO]: CPU utilization for Slot$k is below threshold now.  $tempstore[$i] % \n";
									
								}
							$k++;
							#last;
							
						}
					}
					


		LOOP1:if(defined($CPUStatus) and $flag==1)
		    {
				if($CPUStatus==1)
			    {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'show system processes extensive'});
					
					my $startindex;
		            my $i=0; #my $j=0;
					my $index='';
					my $max=0;
					my $flag=0;
					my @temp;
					for($i=0;$i<$#RemoteOutputSet;$i++)
					{
						if($RemoteOutputSet[$i] =~ /PID\sUSERNAME/i)
						{
		
						     my $k=$i+6;
							 print $LogFileH GetDate." [LOG INFO]:Top Five processes: \n ";
							 for(my $j=$i;$j<$k;$j++)
							 {
								 print $LogFileH GetDate."$RemoteOutputSet[$j] \n";
							 }
							
						}
					}
			
                    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";					   
				}
			}
		   else
		    {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show chassis routing-engine'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system processes extensive'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			}
			return $CPUStatus; 
			 
	}
	  case [@Riverbed]
	  {		   
		   if(trim(${$RemoteOutput}{'show stats cpu'}) ne "" and trim(${$RemoteOutput}{'sh alarm cpu_util_indiv'}) ne "")
			 {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
			 {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show stats cpu'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh alarm cpu_util_indiv'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			 }
			 
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show stats cpu'});
		   my $flag=0;
		   my $utilization;
		   my $CPUStatus=undef;
		   my $CurrentUtil;
		   my $line;
		   my $var;
		   my @tempstore=();
		   
=pod	   
		   foreach(@RemoteOutputSet)
			  {
				for(my $k=0; $k<= $#RemoteOutputSet; $k++)
				{
					if($RemoteOutputSet[$k] =~ /CPU\s.*/)
					{
						$var= $RemoteOutputSet[$k];
						for(my $i=0; $i<=$#RemoteOutputSet; $i++)
							{
								$CurrentUtil=$_;
								if($RemoteOutputSet[$i] == $RemoteOutputSet[$k])
									{
										for(my $j=0; $j=4; $j++)
											{
												if(trim($RemoteOutputSet[$j]) =~ /Most\srecent\s.*([0-9]{1,3})%/)
													{				
														$flag=1;
														$utilization = $1;
														
														if($utilization > $Threshold)
														 {
														   $CPUStatus=1;
														   print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold. $CurrentUtil\n";
														 }
														else
														 {
														   $CPUStatus=0;
														   print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";
														 }
													last;
													}
											}
									}
							}
					}
				}
			}
=cut		   
			foreach my $var(@RemoteOutputSet) 
			{
				$flag=1;
				if($var =~/Most\sRecent/i)
				{
				 	for(my $i=0;$i<$#RemoteOutputSet;$i++)
					{
						if($var =~ /Most\srecent\saverage\:\s.*([0-9]+)%.*/i)
						{
							#print "\n CPU UTILI:".$1;
							$tempstore[$i]=$1;
							#print "\nTempstore:$tempstore[$i]";
							if($tempstore[$i] > $Threshold)
							
								# print "\n CPU Utilisation has crossed Threshold \n";
								# print $LogFileH GetDate." [LOG INFO]:  CPU [$i+1] Utilisation has crossed Threshold.\n";
								
								{
									$CPUStatus=1;
									print $LogFileH GetDate." [LOG INFO]: CPU utilization has crossed threshold. $CurrentUtil\n";
									next LOOP1
								}
								else
								{
									$CPUStatus=0;
									print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now.  $CurrentUtil \n";
									
								}
							
							last;
							
						}
					}
					#print "\n Output:$var";
					#$CPUStatus =1;
					
				}
				#last;
			}
			#exit 1;


		LOOP1:  if(defined($CPUStatus) and $flag==1)
		     {
			   if($CPUStatus==1)
			    {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the Overall error Threshold.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'sh alarm cpu_util_indiv'});
					foreach(@RemoteOutputSet)
					{
						$CurrentUtil=$_;
						if(trim($_)=~/Error\sthreshold\:\s+([0-9]+)/i)
						{
							$flag=1;
							$CurrentUtil=$1;
							
							
							   $CPUStatus=1;
							   print $LogFileH GetDate." [LOG INFO]: Error Threshold is  $CurrentUtil\n";
								
							#last;
						}
					
					}
				}
			 }
			
				else
				 {
					print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
					print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show stats cpu'})." \n";
					print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh alarm cpu_util_indiv'})." \n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
			return $CPUStatus; 
			}
      case [@Aerohive]
	  {	   
		   if(trim(${$RemoteOutput}{'sh cpu detail'}) ne "" and trim(${$RemoteOutput}{'sh system processes state'}) ne "")
			 {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
			 {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh cpu detail'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh system processes state'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			 }
			 
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'sh cpu detail'});
		   my $flag=0;
		   my $utilization;
		   my $CPUStatus=undef;
		   my $CurrentUtil;
		   
	   
		   foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
				if(trim($_)=~/CPU\suser.*\s+([0-9]{1,2})/i)
				  {
					$flag=1;
					$utilization = 100-$1;
					
					if($utilization > $Threshold)
					 {
					   $CPUStatus=1;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization crossed threshold. $CurrentUtil\n";
					 }
				    else
					 {
					   $CPUStatus=0;
					   print $LogFileH GetDate." [LOG INFO]: CPU utilization is below threshold now. $CurrentUtil \n";
					 }
				    last;
				  }
			  }
			  
		    if(defined($CPUStatus) and $flag==1)
		     {
			   if($CPUStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 CPU processes.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'sh system processes state'});
					
					my $startindex;
		            my $i=0; my $j=0;
					my $index='';
					my $max=0;
					my $flag=0;
					my @temp;
					
					for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /^PID/)
						    {
							  $startindex=$i+1;
							  last;
							}
					   }
					
					for($j=0;$j<5;$j++)
					   { 
						 $index = undef;
						 $max=0;
							for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
							  {
								next if(trim($RemoteOutputSet[$i]) =~ /^$/);
								if(trim($RemoteOutputSet[$i]) =~ /^\*/)
								  {
								    $RemoteOutputSet[$i]=~s/^\*//i;
								  }
								if($RemoteOutputSet[$i]=~/PID/)
								  {
									if($flag==0)
									  {
										$flag=1;
										print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
										next;
									  }
									else
									  { 
										last;
									  }
								  }
								  
								next if(trim($RemoteOutputSet[$i])!~/^[0-9]+.*/);
								
								@temp=split(/\s+/,trim($RemoteOutputSet[$i]));
								
								next if($#temp < 5);
								next if(trim($temp[2])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[2])) 
								  {
									$max = trim($temp[2]);
									$index = $i;
								  }
							   }   
						 if(defined($index))
						    {
     						   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$index]."\n" if(trim($RemoteOutputSet[$index]) !~ /^$/);
						       $RemoteOutputSet[$index]="";
							}
					   }

                    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";					   
				 }
			 }
		   else
		     {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current CPU utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh cpu detail'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh system processes state'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $CPUStatus; 
			 
	  }	 
	  else
	  {
	   print $LogFileH GetDate." [LOG ERROR]: DeviceType->$DeviceType not found. Exiting ...\n";
	   print $LogFileH GetDate." [STATUS ]: Failure \n";	   
	   close $LogFileH;
	   exit 1;
	  }
		 
	 }
	
  }
#####################################################################################################
# Create Log File and Validate the Inputs
#####################################################################################################

my $LogFile;

if("$^O"=~/MS/)
{
	$LogFile="C:\\NetworkAutomation\\".$AlertExecId."\.log";
}
else
{
	$LogFile="\/tmp\/NetworkAutomation\/".$AlertExecId."\.log";
} 

open($LogFileH,'>>',$LogFile) or die "Log file could not be created";

#print $LogFileH GetDate." [LOG INFO]: Logs for alert $AlertExecId initiating...\n";

print $LogFileH GetDate." [LOG INFO]: Actions Taken:\n";

my $DeviceType=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'DeviceType','fileptr'=>$LogFileH);
my $Threshold=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'CPUThrld','fileptr'=>$LogFileH);
my $Username=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'UserName','fileptr'=>$LogFileH);
my $EncrPass=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'Password','fileptr'=>$LogFileH);
my $EnablePasswd=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'EnablePassword','fileptr'=>$LogFileH);

if(trim($DeviceType) eq '' or trim($DeviceIP) eq '' or trim($Username) eq '' or trim($EncrPass) eq '' or trim($Threshold) eq '')
  { 
	print $LogFileH GetDate." [LOG ERROR]: Mandatory inputs for automation are missing. Exiting ... \n";
	print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	print $LogFileH GetDate." [STATUS ]: Failure \n";
	close $LogFileH;
	exit 1;   
  }

print $LogFileH GetDate." [LOG INFO]: Devicetype is ".$DeviceType."::Threshold is ".$Threshold."::DeviceIP is ".$DeviceIP."\n";


############################################################################################################
# Get CPU Utilization and Top 5 Processes based on the Device Type
############################################################################################################


#print $LogFileH GetDate." [LOG INFO]: Validating device type to proceed further.\n";

switch ($DeviceType)
{
   case [@CiscoRTSW] 
   {	 
     $Command="term len 0;show processes cpu"; 
   }  
   case [@CiscoASA] 
   {
     $Command="en;$EnablePasswd;show cpu usage;show processes cpu-usage sorted non-zero"; #Set the default login mode
   }
   case [@Checkpoint] 
   {
     $Command="top -b -n 1"; #Set the default login mode
   }
   case [@F5Device] 
   {
     $Command="bash;tmsh show sys cpu;top -b -n 1"; #Set the default login mode
   }
   case [@Bluecoat] 
   {
     $Command="show status;en;$EnablePasswd;configure terminal;diagnostics;cpu-monitor enable;show cpu-monitor"; #Set the default login mode
   }
    case [@Fortinet]
   {
     $Command="get system performance status;diagnose sys top-summary"; #Set the default login mode
   }
    case [@CiscoNexus] 
   {
     $Command="term len 0;show system resources;show processes cpu"; #Set the default login mode
	 }
	case [@JunOS] 
   {
     $Command="show chassis routing-engine;show system processes extensive"; #Set the default login mode
   }
   case [@Riverbed] 
   {
     $Command="show stats cpu;sh alarm cpu_util_indiv"; #Set the default login mode
   }
   case [@Aerohive] 
   {
     $Command="sh cpu detail;sh system processes state"; #Set the default login mode
   }
      	
   else 
   
   {
     print $LogFileH GetDate." [LOG ERROR]: DeviceType $DeviceType not found. Exiting ...\n";
	 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	 print $LogFileH GetDate." [STATUS ]: Failure \n";
	 close $LogFileH;
	 exit 1;   
   }
}

#Call "GetRemoteData' to Get the CPU Utilization

#print $LogFileH GetDate." [LOG INFO]: DeviceType->$DeviceType found and command set successfully.\n";

%RemoteOutput=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$Command,fileptr=>$LogFileH);

 # foreach my $key(keys %RemoteOutput)
 # {
    # print "$key => $RemoteOutput{$key}\n";
 # }
 
print $LogFileH GetDate." [LOG INFO]: ****************************************************\n";
print $LogFileH GetDate." [LOG INFO]: Output from the device:\n";
	   
#print $LogFileH GetDate." [LOG INFO]: Proceeding to check the current utilization of CPU.\n";

#Call "CheckCPUUtilization" to Check if CPU utilization is above threshold and obtain the top 5 CPU processes

$CPUStatus=CheckCPUUtilization(prostr=>\%RemoteOutput,devicetype=>$DeviceType,threshold=>$Threshold,fileptr=>$LogFileH);

if($CPUStatus==0)
  {
    print $LogFileH GetDate." [LOG INFO]: Closing the ticket.\n";
	print $LogFileH GetDate." [STATUS ]: Success \n";		    	
  }
else
  {
    print $LogFileH GetDate." [STATUS ]: Failure \n";
  }

close $LogFileH;

########################################################################################################
# End Of HighCPUUtilization.pl
########################################################################################################