############################################################################################################
# Script Name : DeviceHasStoppedRespondingToPolls.pl                                                       #
# Purpose     : This is the main script which gets triggered by TEM layer for Device has stopped respoding #
#               to polls Network Alerts. The inputs and the Device type are validated. This module performs# 
#				different checks such as Pinging and Polling the device, getting the traceroute results.   #
#               This module also gathers the CPU amd Memory utilization of the Device along with the       #
#				Uptime and interface logs. Result of each step is maintained in a log file.                #
#               Log file is created and updated for each step.                                             #                                
# Author      : Sujeet Kumar Padhi                                                                         #
# Date        : 31/01/2017                                                                                 #           
# Inputs      : DeviceType, Threshold, DeviceIP, Username, Encrypted Password, Ticket Number               #
############################################################################################################


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

my %Command=();
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
				 print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get CPU usage.\n";
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

########################################################################################################
# End Of CheckCPUUtilization
########################################################################################################

############################################################################################
# Subroutine Name : CheckMemoryUtilization                                                 #
# Description     : This subroutine reads the DeviceType, Memory Threshold and the Network #
#                   Device memory data fetched by the SSH protocol Processes the Memory data  #
#					and checks if current Memory utilization is above threshold. If yes,it #
#					obtains the top 5 Memory processes and writes to the log file. Returns #
#                   0 or 1 based on the memory utilization.                                #
############################################################################################


sub CheckMemoryUtilization
 {
	
	my %ProcessMemory=@_;
	my $DeviceType=$ProcessMemory{'devicetype'};
    my $Threshold=$ProcessMemory{'threshold'};
	my $LogFileH=$ProcessMemory{'fileptr'};
	
	my $RemoteOutput=$ProcessMemory{'prostr'};

    switch ($DeviceType)
     {
	  case [@CiscoRTSW] 
		 {			
		 
		     if(trim(${$RemoteOutput}{'show memory'}) =~ /Invalid\s+input\s+detected/i)
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get memory usage.\n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
			
		    if(trim(${$RemoteOutput}{'show memory'}) ne "")
			   {
				 #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			   }
			  else
			   {
				 print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			   }
			   
			my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show memory'});
			
			my @temp=();
			my $MemStatus=0;
			my $line='';
			my $flag=undef;
			my $utilization=undef;
			my $MemType;
			my $TotMem;
			my $UsedMem;

			# Check if Current memory utilization if above threshold
			
			foreach $line (@RemoteOutputSet)
			   { 
			      if(trim($line) =~ /Processor\smemory/i){ last; }
				  
				  next if(trim($line) =~ /^$/);
				  next if(trim($line) =~ /^head/i);	
                  next if(trim($line) =~ /show\smemory/);				  
				  				  
				  if (trim($line) =~ /^Processor/i){ $flag=1; }
				  
				  if(trim($line) =~ /(^[A-Z][a-z]+\s([a-z]+\s)+)/ or trim($line) =~ /(^[A-Z][a-z]+\s([A-Z][a-z]+\s)+)/)
					{
					  $MemType=$1;
					  $line=substr($line,index($line,$MemType)+length($MemType));
					  @temp=split(/\s+/,trim($line));
					  $UsedMem=$temp[2];
					  $TotMem=$temp[1];
					}
				   else
					{
					  @temp=split(/\s+/,trim($line));
					  $MemType=$temp[0];
					  $UsedMem=$temp[3];
					  $TotMem=$temp[2];
					}
					  
				  eval{
				        $utilization=sprintf ("%.2f",(trim($UsedMem)/trim($TotMem))*100);
					  };
					  
				  if($@)
				    {
					  print $LogFileH GetDate." [LOG ERROR]: Unable to find memory utilization.\n";
					  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				      print $LogFileH GetDate." [STATUS ]: Failure \n";
				      close $LogFileH;
				      exit 1;
					}
				  
				  if($utilization > $Threshold)
					{
					  $MemStatus=1;
					  print $LogFileH GetDate." [LOG INFO]: Utilization Exceeded threshold for ".trim($MemType)."\n";
					  print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					  last;
					}
				  else
					{
					  print $LogFileH GetDate." [LOG INFO]: Utilization is below threshold for ".trim($MemType)."\n";
					  print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					}
			   }
			if(defined($flag))
			  {
			    if($MemStatus==0)
			      {
				    print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold.\n";		
			      }
				else
				  {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
					
				    my $i=0; my $j=0; 
			        my $index='';
			        my $max=0;
			        my $flag=0;
					my $startindex='';
			 		
                    # Get the top 5 Memory Processes if the Memory utilization is above threshold
					
					for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /Processor\smemory/i)
						    {
							  $startindex=$i;
							  last;
							}
					   }
					   
					for($j=0;$j<5;$j++) 
						{ 
						  $index=undef;
						  $max=0;
						  for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
							 {
							   #next if(trim($RemoteOutputSet[$i]) =~ /^Head|^Processor|^I\/O|^$/i);
							   #next if(trim($RemoteOutputSet[$i]) =~ /show\smemory/);
							   
							   next if(trim($RemoteOutputSet[$i]) =~ /^$/);
							   
							   @temp=split(/\s+/,trim($RemoteOutputSet[$i]));
							   							   
							   if(trim($RemoteOutputSet[$i])=~/^Address/ and $flag==0)
								 {
								   $flag=1;
								   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
								   next;
								 }
							   
							   #next if ($#temp < 5);
							   next if(trim($temp[1])!~/^[0-9\.\%]+$/);
							   
							   if($max <= trim($temp[1]))
								 {
								   $max = trim($temp[1]);
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
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			  }
			return $MemStatus;	
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
		   my $flag=0;
		   my $MemStatus=undef;
		   my $TotMem;
		   my $UsedMem;
		   my $utilization;
		   
		   foreach(@RemoteOutputSet)
		     {
			   if(trim($_)=~/^Mem/)
			     {
				   $flag=1;
				   $CurrentUtil=$_;
				   
				   @temp = split(',',substr($_,index($_,':')+1)); 
				   
				   $temp[0]=~s/(total)//g;
                   $TotMem=trim($temp[0]);
				   $temp[1]=~s/(used)//g;
                   $UsedMem=trim($temp[1]);
				   
				   if(($TotMem =~ /k|K/ and $UsedMem=~/k|K/) or ($TotMem =~ /B/ and $UsedMem=~/B/) or ($TotMem =~ /M/ and $UsedMem=~/M/) or ($TotMem =~ /G/ and $UsedMem=~/G/))
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/trim($TotMem))*100);
					       };
					 }
				   elsif(($TotMem=~/G/ and $UsedMem=~/M/) or ($TotMem=~/M/ and $UsedMem=~/k|K/) or ($TotMem=~/k|K/ and $UsedMem=~/B/))
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/(trim($TotMem)*1024))*100);
					       };
					 }
				   elsif(($TotMem=~/G/ and $UsedMem=~/k|K/) or ($TotMem=~/M/ and $UsedMem=~/B/))
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/(trim($TotMem)*1024*1024))*100);
					       };
					 }
				   elsif($TotMem=~/G/ and $UsedMem=~/B/)
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/(trim($TotMem)*1024*1024*1024))*100);
					       };
					 }
				   elsif(($TotMem!~/[a-zA-Z]+/ and $UsedMem!~/[A-Za-z]+/))
					 {
					    eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/trim($TotMem))*100);
					       };
					 }
				   else
				     {
					    print $LogFileH GetDate." [LOG ERROR]: Unable to get the memory Utilization. \n";
						print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			            print $LogFileH GetDate." [STATUS ]: Failure \n";
			            close $LogFileH;
			            exit 1;
					 }
					
					if($@)
				      {
					     print $LogFileH GetDate." [LOG ERROR]: Unable to get memory utilization.\n";
						 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                     print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                     print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				         print $LogFileH GetDate." [STATUS ]: Failure \n";
				         close $LogFileH;
				         exit 1;
					   }
					
					
				   if($utilization > $Threshold)
					{
					  $MemStatus=1;
					  print $LogFileH GetDate." [LOG INFO]: Utilization Exceeded threshold for Memory.\n";
					  print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					}
				  else
					{
					  $MemStatus=0;
					  print $LogFileH GetDate." [LOG INFO]: Utilization is below threshold for Memory.\n";
					  print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					}
					
				   last;				 
			     }
			 }
		   
           if($flag==1 and defined($MemStatus))
		     {
			   if($MemStatus==1)
			     {
				   my $startindex='';
				   my $i=0; my $j=0; 
			       my $index='';
			       my $max=0;
		 	       my $flag=0;
				   my $flag1=0;
				   
				   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
				   
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
								next if(trim($temp[9])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[9])) 
								  {
									$max = trim($temp[9]);
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
			   print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	           print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	           print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
			 }			 
		   return $MemStatus;
		 }
		 
	  case [@F5Device] 
         {
           if(trim(${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'}) ne "" and trim(${$RemoteOutput}{'top -b -n 1'}) ne "" and trim(${$RemoteOutput}{'cat /VERSION'}) ne "")
			 {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
			 {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			 }
		   
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'cat /VERSION'});
		   my $version='';
		   my $flag3=0;
		   
		   foreach(@RemoteOutputSet)
		     {
			   if($_=~/^Version:\s+([0-9]+\.[0-9]+)\.([0-9]+)\.*.*/i)
			     {
			       $flag3=1;
				   #print $1;
				   if($1<11.6)
				     {
					   $version=0;
					 }
				   elsif($1==11.6 and $2==0)
				     {
					   $version=1;
					 }
				   else
				     {
					   $version=1;
					 }
			     }
			 }
		   
		   if($flag3==0)
		     {
			    print $LogFileH GetDate." [LOG ERROR]: Unable to get the version og F5 Device.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			 }
			 
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'});
		   my $TotMem;
		   my $UsedMem;
		   my $flag1=0;
		   my $flag2=0;
		   my $MemStatus=undef;
		   my $utilization;
		   
		   if($version==0)
		     {
			   foreach(@RemoteOutputSet)
				 {
				   if(trim($_)=~/^TMM\sAlloc\sMemory\s+([0-9]+)\s.*/i)
					 {
					   $flag1=1;
					   $TotMem=$1;
					 }
				   if(trim($_)=~/^TMM\sUsed\sMemory\s+([0-9]+)\s.*/i)
					 {
					   $flag2=1;
					   $UsedMem=$1;
					 }
				 }
				 
			   if($flag1==1 and $flag2==1)
				 {
					  eval{
						 $utilization=sprintf ("%.2f",(trim($UsedMem)/trim($TotMem))*100);
						  };
					  if($@)
						{
						  print $LogFileH GetDate." [LOG ERROR]: Unable to get memory utilization.\n";
						  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                      print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                      print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
						  print $LogFileH GetDate." [STATUS ]: Failure \n";
						  close $LogFileH;
						  exit 1;
						}				   
				 }
			   else
				 {
				   print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	               print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	               print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				   print $LogFileH GetDate." [STATUS ]: Failure \n";
				   close $LogFileH;
				   exit 1;
				 }
		     }
		   else
		     {
		       foreach(@RemoteOutputSet)
				 {
				   if(trim($_)=~/^TMM\sMemory\sUsed\s+([0-9]{1,3})\s.*/i)
					 {
					   $flag1=1;
					   $utilization=$1;
					   last;
					 }
				 }
			   
			   if($flag1==0)
			     {
				   print $LogFileH GetDate." [LOG ERROR]: Failed to fetch current Memory utilization.\n";
				   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	               print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	               print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				   print $LogFileH GetDate." [STATUS ]: Failure \n";
				   close $LogFileH;
				   exit 1;
				 }
			 }
			 
		   if($utilization > $Threshold)
			 {
			   $MemStatus=1;
			   print $LogFileH GetDate." [LOG INFO]: Utilization Exceeded threshold for Memory.\n";
			   print $LogFileH GetDate." [LOG INFO]: Current Utilization is $utilization%.\n";
			 }
		   else
			 {
			   $MemStatus=0;
			   print $LogFileH GetDate." [LOG INFO]: Utilization is below threshold for Memory.\n";
			   print $LogFileH GetDate." [LOG INFO]: Current Utilization is $utilization%.\n";
			 }
			 
		   if(defined($MemStatus))
		     {
			   if($MemStatus==1)
			     {
				   @RemoteOutputSet=split("\n",${$RemoteOutput}{'top -b -n 1'});
				   
				   my $startindex='';
				   my $i=0; my $j=0; 
			       my $index='';
			       my $max=0;
		 	       my $flag=0;
				   my $flag1=0;
				   my @temp;
				   
				   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
				   
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
								next if(trim($temp[9])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[9])) 
								  {
									$max = trim($temp[9]);
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
			   print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	           print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	           print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
			 }
		   return $MemStatus;
         }
		 
	  case [@Bluecoat]
	     {
		   if(trim(${$RemoteOutput}{'show status'}) ne "" and trim(${$RemoteOutput}{'show advanced-url /TM/Statistics'}) ne "" and trim(${$RemoteOutput}{'show ip-stats'}) ne "")
			 {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			 }
		   else
			 {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
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
		   my $MemStatus=undef;
		   my $CurrentUtil;
		   
			foreach(@RemoteOutputSet)
		     {
			   $CurrentUtil=$_;
			   if(trim($_)=~/Memory\sutilization:\s+([0-9]{1,3})%.*/)
			     {
				   $utilization=$1;
				   $flag=1;
				   if($utilization > $Threshold)
					 {
					   $MemStatus=1;
					   print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold. $CurrentUtil\n";
					 }
				   else
					 {
					   $MemStatus=0;
					   print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now. $CurrentUtil \n";
					 }
				   last;
				 }
			 }
			 
			if(defined($MemStatus) and $flag==1)
		     {
			   if($MemStatus==1)
			     {
				   @RemoteOutputSet=split("\n",${$RemoteOutput}{'show advanced-url /TM/Statistics'});
				   
				   $RemoteOutputSet[$#RemoteOutputSet]='';
				   
				   foreach(@RemoteOutputSet)
				     { 
					   chomp;
					   next if(trim($_)=~/^$/);
					   next if(trim($_)=~/show\sadvanced/i);
					   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					 }
					 
				   @RemoteOutputSet=split("\n",${$RemoteOutput}{'show ip-stats'});
				   
				   foreach(@RemoteOutputSet)
				     {
					   next if(trim($_)=~/^$/);
					   next if(trim($_)=~/show\sip\-stats/i);
					   last if(trim($_)=~/TCP\/IP\sInterface\sStatistics/i);
					   
					   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					 }
					 
				   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	               print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	               print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				   
				 }
			 }
		   else
		     {
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $MemStatus;
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
			my $MemStatus=undef;
			my $CurrentUtil;
		   
		    foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
			    if(trim($_)=~/^Memory\s+states:\s+([0-9]{1,3})%.*/)
				  {
				    $flag=1;
				    $utilization = $1;
				  
				    if($utilization > $Threshold)
					  {
					     $MemStatus=1;
					     print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold. $CurrentUtil\n";
					  }
				    else
					  {
					     $MemStatus=0;
					     print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now. $CurrentUtil \n";
					  }
				   last;
				  }
			  }
			  
			if(defined($MemStatus) and $flag==1)
		     {
			   if($MemStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
					
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
								next if(trim($temp[3])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[3])) 
								  {
									$max = trim($temp[3]);
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
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $MemStatus;			 
		 }
		 
	 case [@CiscoASA]
		 {
		 
		    if(trim(${$RemoteOutput}{'sh memory'}) =~ /Invalid\s+input\s+detected/i)
			  {
				  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get memory usage.\n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  print $LogFileH GetDate." [STATUS ]: Failure \n";
				  close $LogFileH;
				  exit 1;
			    }
			   
			if(trim(${$RemoteOutput}{'sh memory'}) ne "" and trim(${$RemoteOutput}{'sh processes memory'}) ne "")
			  {
				 #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			  }
		   else
			  {
				 print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			  }
			  
			my @RemoteOutputSet=split("\n",${$RemoteOutput}{'sh memory'});
			my $flag=0;
			my $utilization;
			my $CurrentUtil;
			my $MemStatus=undef;
			
			foreach(@RemoteOutputSet)
			  {
				$CurrentUtil=$_;
				if(trim($_)=~/Used\s+memory:\s+.*\(\s*([0-9]{1,3})%\s*\).*/i)
				  {
					$flag=1;
					$utilization = $1;
			  
					if($utilization > $Threshold)
					  {
						 $MemStatus=1;
						 print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold\n";
						 print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					  }
					else
					  {
						 $MemStatus=0;
						 print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now.\n";
						 print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					  }
				   last;
				  }
			  }
			  
			if(defined($MemStatus) and $flag==1)
		     {
			   if($MemStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
					
					if(trim(${$RemoteOutput}{'sh processes memory'}) =~ /Invalid\s+input\s+detected/i)
					  {
						  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get memory usage.\n";
						  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                      print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                      print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
						  print $LogFileH GetDate." [STATUS ]: Failure \n";
						  close $LogFileH;
						  exit 1;
					  }
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'sh processes memory'});
					
					my $i=0; my $j=0; 
			        my $index='';
			        my $max=0;
			        my $flag=0;
					my $startindex='';
					my @temp=();
			 		
                    # Get the top 5 Memory Processes if the Memory utilization is above threshold
					
					for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /^Allocs\b/i)
						    {
							  $startindex=$i;
							  last;
							}
					   }
					   
					for($j=0;$j<5;$j++) 
						{ 
						  $index=undef;
						  $max=0;
						  for($i=$startindex;$i<=$#RemoteOutputSet;$i++)
							 {
							   # print "line\n";
                               # print $RemoteOutputSet[$i]."\n";
							   next if(trim($RemoteOutputSet[$i]) =~ /^-------/);							   
							   next if(trim($RemoteOutputSet[$i]) =~ /^$/);
							   next if(trim($RemoteOutputSet[$i]) =~ /sh\sprocesses\smemory/i);
							   
							   @temp=split(/\s+/,trim($RemoteOutputSet[$i]));
							   							   
							   if(trim($RemoteOutputSet[$i])=~/^Allocs/ and $flag==0)
								 {
								   $flag=1;
								   print $LogFileH GetDate." [LOG INFO]: ".$RemoteOutputSet[$i]."\n";
								   next;
								 }
							   
							   #next if ($#temp < 5);
							   next if(trim($temp[0])!~/^[0-9\.\%]+$/);
							   
							   if($max <= trim($temp[0]))
								 {
								   $max = trim($temp[0]);
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
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $MemStatus;	
				  
		 }
	  case [@CiscoNexus]
	     {
		   if(trim(${$RemoteOutput}{'show system resources'}) ne "" and trim(${$RemoteOutput}{'show processes memory'}) ne "")
			  {
				 #print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			  }
		   else
			  {
				 print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			     print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			     print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				 print $LogFileH GetDate." [STATUS ]: Failure \n";
				 close $LogFileH;
				 exit 1;
			  }
			  
		   my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show system resources'});
		   
		   my @temp;
		   my $CurrentUtil;
		   my $flag=0;
		   my $MemStatus=undef;
		   my $TotMem;
		   my $UsedMem;
		   my $utilization;
		   
		   foreach(@RemoteOutputSet)
		     {
			   if(trim($_)=~/^Memory\s+usage:\s+([0-9]+[a-zA-Z])\s+total,\s+([0-9]+[a-zA-Z])\s+used/)
			     {
				   $flag=1;
				   $CurrentUtil=$_;
				   
                   $TotMem=$1;
                   $UsedMem=$2;
				   
				   if(($TotMem =~ /k|K/ and $UsedMem=~/k|K/) or ($TotMem =~ /B/ and $UsedMem=~/B/) or ($TotMem =~ /M/ and $UsedMem=~/M/) or ($TotMem =~ /G/ and $UsedMem=~/G/))
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/trim($TotMem))*100);
					       };
					 }
				   elsif(($TotMem=~/G/ and $UsedMem=~/M/) or ($TotMem=~/M/ and $UsedMem=~/k|K/) or ($TotMem=~/k|K/ and $UsedMem=~/B/))
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/(trim($TotMem)*1024))*100);
					       };
					 }
				   elsif(($TotMem=~/G/ and $UsedMem=~/k|K/) or ($TotMem=~/M/ and $UsedMem=~/B/))
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/(trim($TotMem)*1024*1024))*100);
					       };
					 }
				   elsif($TotMem=~/G/ and $UsedMem=~/B/)
				     {
					    $TotMem=~s/[A-Za-z]+//g;
						$UsedMem=~s/[A-Za-z]+//g;
						
						eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/(trim($TotMem)*1024*1024*1024))*100);
					       };
					 }
				   elsif(($TotMem!~/[a-zA-Z]+/ and $UsedMem!~/[A-Za-z]+/))
					 {
					    eval{
				          $utilization=sprintf ("%.2f",(trim($UsedMem)/trim($TotMem))*100);
					       };
					 }
				   else
				     {
					    print $LogFileH GetDate." [LOG ERROR]: Unable to get the memory Utilization. \n";
						print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			            print $LogFileH GetDate." [STATUS ]: Failure \n";
			            close $LogFileH;
			            exit 1;
					 }
					
					if($@)
				      {
					     print $LogFileH GetDate." [LOG ERROR]: Unable to get memory utilization.\n";
						 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			             print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			             print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				         print $LogFileH GetDate." [STATUS ]: Failure \n";
				         close $LogFileH;
				         exit 1;
					   }
					
					
				   if($utilization > $Threshold)
					{
					  $MemStatus=1;
					  print $LogFileH GetDate." [LOG INFO]: Utilization Exceeded threshold for Memory.\n";
					  print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					}
				  else
					{
					  $MemStatus=0;
					  print $LogFileH GetDate." [LOG INFO]: Utilization is below threshold for Memory.\n";
					  print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
					}
					
				   last;				 
			     }
			 }
			 
		   if($flag==1 and defined($MemStatus))
		     {
			   if($MemStatus==1)
			     {
				   @RemoteOutputSet=split("\n",${$RemoteOutput}{'show processes memory'});
				   
				   my $startindex='';
				   my $i=0; my $j=0; 
			       my $index='';
			       my $max=0;
		 	       my $flag=0;
				   
				   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
				   
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
								next if(trim($RemoteOutputSet[$i]) =~ /^--/);
								
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
								
								next if($#temp < 3);
								next if(trim($temp[3])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[3])) 
								  {
									$max = trim($temp[3]);
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
			   print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
			 }			 
		   return $MemStatus;
		 }
case [@JunOS]
		{
		    
		    if(trim(${$RemoteOutput}{'show chassis routing-engine | match Memory'}) ne "" and trim(${$RemoteOutput}{'show system memory all-members'}) ne "")
			  {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			  }
		    else
			  {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show chassis routing-engine |match Memory'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system memory all-members'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			  }
			 
			 
			 
		    my @RemoteOutputSet=split("\n",${$RemoteOutput}{'show chassis routing-engine | match Memory'});
		    my $flag=0;
			my $utilization;
			my $MemStatus=undef;
			my $CurrentUtil;
		   
		    foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
			    if(trim($_)=~/Memory\s+utilization\s+([0-9]{1,2})/)
				  {
				    $flag=1;
				    $utilization = $1;
					#$MemStatus=1;
				    if($utilization > $Threshold)
					  {
					     $MemStatus=1;
					     print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold. $utilization %\n";
						
						 next LOOP1
					  }
				    else
					  {
					     $MemStatus=0;
					     print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now. $utilization % \n";
						 
					  }
				   #last;
				  }
			  }
			  #exit 1;
			LOOP1:if(defined($MemStatus) and $flag==1)
		     {
			   if($MemStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'show system memory all-members'});
					
					my $startindex;
		            my $i=0; #my $j=0;
					my $index='';
					my $max=0;
					my $flag=0;
					my @temp;

					for($i=0;$i<$#RemoteOutputSet;$i++)
					{
						if($RemoteOutputSet[$i] =~ /PID/i)
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
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show chassis routing-engine |match Memory'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system memory all-members'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $MemStatus;			 
		 }
		case [@Riverbed]
		{
				#print "\n".trim(${$RemoteOutput}{'sh version'});
	if(trim(${$RemoteOutput}{'sh version'}) =~ /Invalid\s+input\s+detected/i)
	  {
					  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get memory usage.\n";
					  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh version '})." \n";
					  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					  print $LogFileH GetDate." [STATUS ]: Failure \n";
					  close $LogFileH;
					  exit 1;
		}
				   
	if(trim(${$RemoteOutput}{'sh version'}) ne "")
	  {
					#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";              
	  }
	else
	  {
					print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
					print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh version'})." \n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
	  }
				  
	my @RemoteOutputSet=split("\n",${$RemoteOutput}{'sh version'});
	my $flag=0;
	my $utilization;
	my $usedMem;
	my $totalMem;
	my $CurrentUtil;
	my $MemStatus=undef;
	
	foreach(@RemoteOutputSet)
	  {
		$CurrentUtil=$_;
		if(trim($_)=~/System\smemory:\s(.*)\sMB\s+used/i)
		  {
			#$flag=1;
			$usedMem = $1;
						
		  }
	  }
	  foreach(@RemoteOutputSet)
	  {
		$CurrentUtil=$_;
		
		if(trim($_)=~/System\smemory\:\s.*\s+([0-9]+)\sMB\stotal/i)
		  {
			#$flag=1;
			$totalMem = $1;
		
		  }
	  }
	  eval
	  {
		 $utilization=sprintf ("%.2f",(trim($usedMem)/trim($totalMem))*100);
	  };
	  #print "\nValue:$utilization";
	  if($utilization > $Threshold)
	  {
		$MemStatus=1;
		$flag=1;
		print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold\n";
		print $LogFileH GetDate." [LOG INFO]: Current Memory Utilization is ".$utilization."%\n";
		#print $utilization;
	  }
	else
	  {
		$MemStatus=0;
		print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now.\n";
		print $LogFileH GetDate." [LOG INFO]: Current Memory utilization is ".$utilization."%\n";
		#print $utilization;
	  }
	  if(defined($MemStatus) and $flag==1)
	 {
	   if($MemStatus==1)
		 {
			print $LogFileH GetDate." [LOG INFO]: Memory utilization fetched.\n";
		 }
												
				
		else
		 {
			print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
						print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh version '})." \n";
						print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			print $LogFileH GetDate." [STATUS ]: Failure \n";
			close $LogFileH;
			exit 1;
		 }
   return $MemStatus;    
								  
	 }
}
	 case [@Aerohive] 
          {
		    
		    if(trim(${$RemoteOutput}{'sh memory detail'}) ne "" and trim(${$RemoteOutput}{'sh memory detail'}) ne "")
			  {
				#print $LogFileH GetDate." [LOG INFO]: Successfully obtained the command output from remote device.\n";	 
			  }
		    else
			  {
				print $LogFileH GetDate." [LOG ERROR]: Failed to get the details from remote device. Exiting ...\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				print $LogFileH GetDate." [STATUS ]: Failure \n";
				close $LogFileH;
				exit 1;
			  }
			 
		    my @RemoteOutputSet=split("\n",${$RemoteOutput}{'sh memory detail'});
		    my $flag=0;
			my $utilization;
			my $MemStatus=undef;
			my $CurrentUtil;
		   
		    foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
			    if(trim($_)=~/Used\sMemory:\s+([0-9]){1,8}\s+KB/)
				  {
				    $flag=1;
				    $utilization = $1;
				  
				    if($utilization > $Threshold)
					  {
					     $MemStatus=1;
					     print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold. $CurrentUtil\n";
					  }
				    else
					  {
					     $MemStatus=0;
					     print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now. $CurrentUtil \n";
					  }
				   last;
				  }
			  }
			  
			if(defined($MemStatus) and $flag==1)
		     {
			   if($MemStatus==1)
			     {
				    print $LogFileH GetDate." [LOG INFO]: Proceeding to get the top 5 Memory processes.\n";
					
					@RemoteOutputSet=split("\n",${$RemoteOutput}{'sh memory detail'});
					
					my $startindex;
		            my $i=0; my $j=0;
					my $index='';
					my $max=0;
					my $flag=0;
					my @temp;
					
					for($i=0;$i<=$#RemoteOutputSet;$i++)
					   {
						  if(trim($RemoteOutputSet[$i]) =~ /proc/)
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
								if($RemoteOutputSet[$i]=~/proc/)
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
								next if(trim($temp[3])!~/^[0-9\.\%]+$/);
								
								if($max <= trim($temp[3])) 
								  {
									$max = trim($temp[3]);
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
			    print $LogFileH GetDate." [LOG ERROR]: Failed to find current Memory utilization.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			    close $LogFileH;
			    exit 1;
			 }
		   return $MemStatus;			 
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

########################################################################################################
# End Of CheckMemoryUtilization
########################################################################################################

####################################################################################################
# Subroutine Name : PollDevice                                                                     #
# Description     : This subroutine reads the deviceip and polls it. Returns 1 or 0 based upon the # 
#                   poll result.                                                                   #
####################################################################################################

sub PollDevice
{
  my $result="";
  my ($session,$error) = Net::SNMP->session(Hostname => "$_[0]",Community => "$_[1]",Version=>'SNMPv2c');
  if(defined($session))
    {
	  $result = $session->get_request("$_[2]");
	  if(defined($result))
	    {
		  $session->close;
		  return 1;
		}
	}
   return 0; 
}

########################################################################################################
# End Of PollDevice
########################################################################################################

####################################################################################################
# Subroutine Name : PingDevice                                                                     #
# Description     : This subroutine reads the deviceip and pings it. Returns 1 or 0 based upon the # 
#                   ping result.                                                                   #
####################################################################################################

sub PingDevice
{
    my $i=0;
	my @RttArr=();
	my $total=0;
	
    my $net=Net::Ping->new("external");
	   $net->hires();
	
	for($i=0;$i<5;$i++)
	   {
		  my ($ret, $rtt, $ip) = $net->ping($_[0]);
		  if($ret and $rtt)
		    {
			  $RttArr[$i]=sprintf("%.2f",$rtt*1000);
			  $total+=$RttArr[$i];
		    }
		  else
		    {
			  return 0;
		    }
	   }
	   
	$RTT=sprintf("%.2f",$total/($#RttArr+1));
	
	return 1;
}

########################################################################################################
# End Of PollDevice
########################################################################################################

#######################################################################################################
# Subroutine Name : TraceRouteAndLastHop                                                              #
# Description     : This subroutine reads the deviceip and gets the traceroute results along with the #
#                   last hop details.                                                                 # 
#######################################################################################################

sub TraceRouteAndLastHop
{
   print $LogFileH GetDate." [LOG INFO]: Proceeding to get the traceroute for the Device $DeviceIP.\n";
   
   my $traprg="";
   my $trout="";
   my @temp=();
   my $i=0;
   
   if("$^O"=~/MS/)
     {
	   $traprg='tracert';
	 }
   else
	 {
	   $traprg='traceroute';
	 }

	$trout=`$traprg $_[0]`;
	
	if(trim($trout))
	  {
	    #print $LogFileH GetDate." [LOG INFO]: Output logs for alert $AlertExecId initiating...\n";
	    print $LogFileH GetDate." [LOG INFO]: Successfully obtained traceroute result for the Device $DeviceIP.\n\n";
	    @temp=split("\n",$trout);
	  }
	 else
	  {
	    print $LogFileH GetDate." [LOG ERROR]: Failed to obtain traceroute result for the Device $DeviceIP.\n";
		print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		print $LogFileH GetDate." [STATUS ]: Failure \n";
        close $LogFileH;
	    exit 1;
	  }	

	foreach (@temp)
	  {
	    print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
	  }
	  
}

########################################################################################################
# End Of TraceRouteAndLastHop
########################################################################################################

#########################################################################################

sub GetInterfaceLogs
 {
   my %OutSet=@_;  
  
   switch ($DeviceType)
    {
      case [@CiscoRTSW] 
        { 
		  my @temp=();
		  my $month;
		  my $date;
		  my $flag=0;
		  
		  if(trim($OutSet{'show clock'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{'show log | in UPDOWN'}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  # print $OutSet{'show log | in UPDOWN'};
		  
		  # print $OutSet{'show clock'};
		  
		  if($OutSet{'show clock'}=~/.*((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}).*/)
		    {
	          @temp=split(/\s+/,$1);
			  $month=trim($temp[0]);
	          $date=trim($temp[1]);
			  
			  if($month eq "" or $date eq "")
			    {
				  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	              print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	              print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	              print $LogFileH GetDate." [STATUS ]: Failure \n";
	              close $LogFileH;
			      exit 1;
				}
	        }
		  else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{'show log | in UPDOWN'});
		  
		  foreach (@temp)
		    {
			  if(/($month\s+$date)|($month\s+0$date)/)
			    {
				  $flag=1;
                  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";	
                }
			}
		  if($flag==0)
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs for the current date : ".$month." ".$date."\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			  print $LogFileH GetDate." [STATUS ]: Failure \n";
			}
		  else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			  print $LogFileH GetDate." [STATUS ]: Failure \n";
			}
		}
		case [@CiscoASA] 
        { 
		  my @temp=();
		  my $month;
		  my $date;
		  my $flag=0;
		  
		  if(trim($OutSet{'show clock'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{'show log | in UPDOWN'}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  # print $OutSet{'show log | in UPDOWN'};
		  
		  # print $OutSet{'show clock'};
		  
		  if($OutSet{'show clock'}=~/.*((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}).*/)
		    {
	          @temp=split(/\s+/,$1);
			  $month=trim($temp[0]);
	          $date=trim($temp[1]);
			  
			  if($month eq "" or $date eq "")
			    {
				  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	              print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	              print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	              print $LogFileH GetDate." [STATUS ]: Failure \n";
	              close $LogFileH;
			      exit 1;
				}
	        }
		  else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{'show log | in UPDOWN'});
		  
		  foreach (@temp)
		    {
			  if(/($month\s+$date)|($month\s+0$date)/)
			    {
				  $flag=1;
                  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";	
                }
			}
		  if($flag==0)
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs for the current date : ".$month." ".$date."\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			  print $LogFileH GetDate." [STATUS ]: Failure \n";
			}
		  else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			  print $LogFileH GetDate." [STATUS ]: Failure \n";
			}
		}
		case [@CiscoNexus]
        { 
		  my @temp=();
		  my $month;
		  my $date;
		  my $flag=0;
		  
		  if(trim($OutSet{'show clock'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{'show log | in UPDOWN'}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  # print $OutSet{'show log | in UPDOWN'};
		  
		  # print $OutSet{'show clock'};
		  
		  if($OutSet{'show clock'}=~/.*((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}).*/)
		    {
	          @temp=split(/\s+/,$1);
			  $month=trim($temp[0]);
	          $date=trim($temp[1]);
			  
			  if($month eq "" or $date eq "")
			    {
				  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	              print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	              print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	              print $LogFileH GetDate." [STATUS ]: Failure \n";
	              close $LogFileH;
			      exit 1;
				}
	        }
		  else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{'show log | in UPDOWN'});
		  
		  foreach (@temp)
		    {
			  if(/($month\s+$date)|($month\s+0$date)/)
			    {
				  $flag=1;
                  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";	
                }
			}
		  if($flag==0)
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs for the current date : ".$month." ".$date."\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			  print $LogFileH GetDate." [STATUS ]: Failure \n";
			}
		  else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			  print $LogFileH GetDate." [STATUS ]: Failure \n";
			}
		}
	  case [@Checkpoint] 
        { 
          my @temp=();
		  my @temp1=();
		  my $flag1=0;
		  my $flag2=0;
		  my $flag3=0;
		  my $tempstr;
		  my $intstr='';
		  my $line;
		  
		  if($OSName eq 'IPSO')
		    {
			  if(trim($OutSet{'show interfacemonitor'}) eq "")
				{
				  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  print $LogFileH GetDate." [STATUS ]: Failure \n";
				  close $LogFileH;
				  exit 1;
				}
			   
			   $tempstr=trim($OutSet{'show interfacemonitor'});
			   $tempstr=~s/\bInterface:/#=#Interface:/gi;
			   
			   @temp=split('#=#',$tempstr);
			   
			   foreach(@temp)
				 {
				   if(trim($_)=~/^Interface/)
					 {
					   $flag1=1;
					   @temp1=split("\n",$_);
					   foreach(@temp1)
						 {
						   if($_=~/Up\sto\sDown\sTransitions\s+([0-9]+)/i)
							 {
							   $flag2=1;
							   if($1>0)
								 {
								   $flag3=1;
								   foreach(@temp1)
									 {
									   chomp;
									   trim($_);
									   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
									 }
								 }
							   last;
							 }
						 }
					 }
				 }
				 
			   if($flag1==0 or $flag2==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
			   
			   if($flag3==0)
				 {
					print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
				else
				 {
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
				 }
			}
			
	      elsif($OSName eq 'GAIA' or $OSName eq 'SPLAT')
		    {
			  if(trim($OutSet{'cat /var/log/messages | egrep -i "(\bup\b|\bdown\b)"'}) eq "")
				{
				  print $LogFileH GetDate." [LOG ERROR]: Automation could not find any interface flapping logs.\n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  print $LogFileH GetDate." [STATUS ]: Failure \n";
				  close $LogFileH;
				  exit 1;
				}
				
			   my $flag=0;
				
			   @temp=split("\n",trim($OutSet{'cat /var/log/messages | egrep -i "(\bup\b|\bdown\b)"'}));
				
			   foreach(@temp)
				  {
					chomp;					
					next if(trim($_)=~/^$/);
					$flag=1;
					print $LogFileH GetDate." [LOG INFO]: ".$_."\n";				
				  }
				
			   if($flag==0)
				  {
					print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				  }
			   else
				  {
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
				  }
			}
        }
	  case [@F5Device]
	    {
		   if(trim($OutSet{'cat /var/log/ltm | grep up | grep down'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Automation could not find any interface flapping logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
			my @temp=();
			my $flag=0;
		    
			@temp=split("\n",trim($OutSet{'cat /var/log/ltm | grep up | grep down'}));
			
			#$temp[$#temp]='';
			
			foreach(@temp)
			  {
			    chomp;
			    next if(trim($_)=~/cat\s\/var/);
				next if(trim($_)=~/^$/);
				$flag=1;
				print $LogFileH GetDate." [LOG INFO]: ".$_."\n";				
			  }
			
			if($flag==0)
			  {
			    print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	            print $LogFileH GetDate." [STATUS ]: Failure \n";
	            close $LogFileH;
			    exit 1;
			  }
			else
		      {
			    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			  }
		}
	  case [@Bluecoat]
	    {
		  if(trim($OutSet{'show ip-stats'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		   
		   my @temp=();
		   my @temp1=();
		   my $flag1=0;
		   my $flag2=0;
		   my $flag3=0;
		   my $flag4=0;
		   my $flag5=0;
		   my $i=0; my $j=0;
		   my $startindex;
		   my $endindex;
		   my $tempstr;
		    
		   @temp=split("\n",trim($OutSet{'show ip-stats'}));
		   
		   for($i=0;$i<=$#temp;$i++)
		      {
			    chomp $temp[$i];
			    if(trim($temp[$i])=~/TCP\/IP\s+Interface\s+Statistics\s+ALL/i)
				  {
				    $flag1=1;
					$startindex=$i;
				  }
				 elsif(trim($temp[$i])=~/TCP\/IP\s+IP\s+Statistics$/i)
				  {
				    $flag2=1;
					$endindex=$i;
					last;
				  }
			  }
		   
		   if($flag1==1 and $flag2==1)
		     {
			   for($i=$startindex+1;$i<$endindex;$i++)
		          {
				    $temp1[$j]=$temp[$i];
					$j++;
				  }
			   
           	   $tempstr=join("\n",@temp1);	   
			   
			   $tempstr=~s/\bInterface:/#=#Interface:/gi;
		   
			   @temp=split('#=#',$tempstr);
			   
			   foreach(@temp)
				 {
				   if(trim($_)=~/^Interface/)
					 {
					   $flag3=1;
					   @temp1=split("\n",$_);
					   foreach(@temp1)
						 {
						   if($_=~/Number\sof\stimes\sinterface\swas\sdown\s+([0-9]+)/i)
							 {
							   $flag4=1;
							   if($1>0)
							     {
								   $flag5=1;
								   foreach(@temp1)
									 {
									   chomp;
									   trim($_);
									   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
									 }
								 }
							   last;
							 }
						 }
					 }
				 }
				 
			   if($flag3==0 or $flag4==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
			   
			   if($flag5==0)
				 {
					print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
			   else
		         {
				    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	                print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	                print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			        print $LogFileH GetDate." [STATUS ]: Failure \n";
			     }
			 }
		   else
		     {
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	           print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	           print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	           print $LogFileH GetDate." [STATUS ]: Failure \n";
	           close $LogFileH;
			   exit 1;
			 }
		}
	  case [@Fortinet]
	    {
		   if(trim($OutSet{'execute log display'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		   my @temp=();
		   my $flag=0;
		    
		   @temp=split("\n",trim($OutSet{'execute log display'}));
			
		   $temp[$#temp]='';
			
		   foreach(@temp)
			  {
			    chomp;
			    next if(trim($_)=~/execute\slog\display/);
				next if(trim($_)=~/^$/);
				next if(trim($_)=~/logs\s+found/i);
				next if(trim($_)=~/logs\s+returned/i);
				
				$flag=1;
				print $LogFileH GetDate." [LOG INFO]: ".$_."\n";				
			  }
			
		   if($flag==0)
			  {
			    print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
				print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	            print $LogFileH GetDate." [STATUS ]: Failure \n";
	            close $LogFileH;
			    exit 1;
			  }
		   else
		      {
			    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	            print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	            print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			    print $LogFileH GetDate." [STATUS ]: Failure \n";
			  }
		}
	case [@JunOS]
		{
			my @temp=();
			if(trim($OutSet{'show log messages'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			else
			{
					print $LogFileH GetDate." [LOG INFO]: Log of the device:\n";
						  @temp=split("\n",$OutSet{"show log messages"});
						  foreach (@temp)
							{
								print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
							}
						  #print $LogFileH GetDate." [LOG INFO]: Log of the device:".trim($OutSet{"show log messages"});
						  print $LogFileH GetDate." [STATUS ]: Success \n";

			}
		}
	case [@Riverbed]
		{
			my @temp=();
			if(trim($OutSet{'sh log'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Error:".trim($OutSet{'sh log'})."\n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			else
			{
						
				@temp=split("\n",$OutSet{"sh log"});
				foreach (@temp)
				{
					print $LogFileH GetDate." [LOG INFO]: Log of the device:\n";
					print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					print $LogFileH GetDate." [STATUS ]: Success \n";
				}
						  # print $LogFileH GetDate." [LOG INFO]: Log of the device:".trim($OutSet{'sh log'});
						  # print $LogFileH GetDate." [STATUS ]: Success \n";

			}
		}  
	case [@Aerohive]
		{
			if(trim($OutSet{'sh log flash'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			else
			{
			  print $LogFileH GetDate." [LOG INFO]: Log of the device:".trim($OutSet{"sh log flash"});
			  print $LogFileH GetDate." [STATUS ]: Success \n";

			}
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
 }

#############################################################################################################
#Subroutine : GetRemoteData
#############################################################################################################

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

#print $LogFileH GetDate." [LOG INFO]: Logs for alert $AlertExecId initiating\n";

print $LogFileH GetDate." [LOG INFO]: Actions Taken:\n";

$DeviceType=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'DeviceType','fileptr'=>$LogFileH);
$CPUThreshold=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'CPUThrld','fileptr'=>$LogFileH);
$MemThreshold=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'MEMThrld','fileptr'=>$LogFileH);
$Username=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'UserName','fileptr'=>$LogFileH);
$EncrPass=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'Password','fileptr'=>$LogFileH);
$EnablePasswd=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'EnablePassword','fileptr'=>$LogFileH);
$Community=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'SNMPString','fileptr'=>$LogFileH);
$ObjID=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'ObjID','fileptr'=>$LogFileH);



if(trim($DeviceType) eq '' or trim($DeviceIP) eq '' or trim($Username) eq '' or trim($EncrPass) eq '' or trim($CPUThreshold) eq '' or trim($MemThreshold) eq '')
  { 
	print $LogFileH GetDate." [LOG ERROR]: Mandatory inputs for automation are missing. Exiting ... \n";
	print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	print $LogFileH GetDate." [STATUS ]: Failure \n";
	close $LogFileH;
	exit 1;    
  }

print $LogFileH GetDate." [LOG INFO]: Devicetype is ".$DeviceType."::CPUThreshold is ".$CPUThreshold."::MemoryThreshold is ".$MemThreshold."::DeviceIP is ".$DeviceIP."\n";

############################################################################################################

if(PollDevice($DeviceIP,$Community,$ObjID)==1)
	   {
	     print $LogFileH GetDate." [LOG INFO]: Polling successful to the Device $DeviceIP.\n";
	   }
	  else
	   {
	     print $LogFileH GetDate." [LOG ERROR]: Polling failed to the Device $DeviceIP.\n";
		 
	     if(PingDevice($DeviceIP)==1)
		   {
		     print $LogFileH GetDate." [LOG INFO]: Ping successful to the Device $DeviceIP.\n";
		   }
		  else
		   {
		     print $LogFileH GetDate." [LOG ERROR]: Ping failed to the Device $DeviceIP.\n";
			 
		     TraceRouteAndLastHop($DeviceIP);
			 
			 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	         print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	         print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			 print $LogFileH GetDate." [STATUS ]: Failure \n";
             close $LogFileH;
			 exit 1;
		   }
	   }
	   	   
print $LogFileH GetDate." [LOG INFO]: ****************************************************\n";
print $LogFileH GetDate." [LOG INFO]: Output from the device:\n";


switch ($DeviceType)
{
   case [@CiscoRTSW] 
   { 	 
	 %Command=('uptime'=>'term len 0;show version','memory'=>'term len 0;show memory','cpu'=>'term len 0;show processes cpu','interface'=>'term len 0;show clock;show log | in UPDOWN');	   
    }
   case [@CiscoASA] 
   {
     %Command=('uptime'=>"en;$EnablePasswd;sh ver | grep up",'memory'=>"en;$EnablePasswd;sh memory;sh processes memory",'cpu'=>"en;$EnablePasswd;show cpu usage;show processes cpu-usage sorted non-zero",'interface'=>"en;$EnablePasswd;show clock;show log | in UPDOWN");
   }
   case [@Checkpoint] 
   {
     my $OSCommand='cpstat os -f all';
	 
     $OSName=GetCheckpointOS(deviceip=>"$DeviceIP",username=>"$Username",password=>"$EncrPass",command=>"$OSCommand",fileptr=>$LogFileH);
	 
	 if($OSName eq 'GAIA' or $OSName eq 'SPLAT')
	   {
          %Command=('uptime'=>'top -b -n 1 | grep up','memory'=>'top -b -n 1','cpu'=>'top -b -n 1','interface'=>'cat /var/log/messages | egrep -i "(\bup\b|\bdown\b)"');
	   }
	 elsif($OSName eq 'IPSO')
	   {
          %Command=('uptime'=>'top -b -n 1 | grep up','memory'=>'top -b -n 1','cpu'=>'top -b -n 1','interface'=>'clish;show interfacemonitor');
	   }
	 else
	   {
	     print $LogFileH GetDate." [LOG ERROR]: Unable to identify the OS Name for checkpoint device.\n";
		 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		 print $LogFileH GetDate." [STATUS ]: Failure \n";
		 close $LogFileH;
		 exit 1;
	   }
   }
   case [@F5Device] 
   {
     %Command=('uptime'=>'bash;top -b -n 1 | grep up','memory'=>'bash;cat /VERSION;tmsh show sys memory raw| head | grep TMM;top -b -n 1','cpu'=>'bash;tmsh show sys cpu;top -b -n 1','interface'=>'bash;cat /var/log/ltm | grep up | grep down');
   }
   case [@Bluecoat]
   {
     %Command=('uptime'=>'show clock;show status','memory'=>'show status;show advanced-url /TM/Statistics;show ip-stats','cpu'=>"show status;en;$EnablePasswd;configure terminal;diagnostics;cpu-monitor enable;show cpu-monitor",'interface'=>'show ip-stats');
   }
   case [@Fortinet] 
   {
     %Command=('uptime'=>'config global;get system performance status','memory'=>'config global;get system performance status;diagnose sys top-summary;q','cpu'=>'config global;get system performance status;diagnose sys top-summary;q','interface'=>'config global;execute log filter category event;execute log filter view-lines 100;execute log filter field logdesc "Interface status changed";execute log display');
   }
   case [@CiscoNexus] 
   {
     %Command=('uptime'=>'term len 0;show system uptime','memory'=>'term len 0;show system resources;show processes memory','cpu'=>'term len 0;show system resources;show processes cpu','interface'=>'term len 0;show clock;show log | in UPDOWN');
   }
   case [@JunOS]
    {
	 %Command=('uptime'=>'show system uptime','memory'=>'show chassis routing-engine |match Memory;show system memory all-members','cpu'=>'show chassis routing-engine;show system processes extensive','interface'=>'show log messages');
	}
	case [@Riverbed]
    {
	 %Command=('uptime'=>'sh version','memory'=>'sh version','cpu'=>'show stats cpu;sh alarm cpu_util_indiv','interface'=>'sh log');
	}
	case [@Aerohive]
    {
	 %Command=('uptime'=>'sh version','memory'=>'sh memory detail','cpu'=>'sh cpu detail;sh system processes state','interface'=>'sh log flash');
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

  
if($Command{'uptime'} ne "")
  {
    my $CommandSet=$Command{'uptime'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH);
   
    # print "uptime\n";
    # print $OutputSet{'top -b -n 1'};  
    # print $LogFileH "show version output start\n#######################\n";
    # print$LogFileH $OutputSet{'show version'};
    # print $LogFileH "show version output end\n#########################\n";
   
    if(CheckDeviceUptime(prostr=>\%OutputSet,devicetype=>$DeviceType,fileptr=>$LogFileH)==0)
	  {
		 #print $LogFileH GetDate." [LOG INFO]: Device might have been rebooted recently.\n";
		 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		 print $LogFileH GetDate." [STATUS ]: Failure  \n";
		 close $LogFileH;
		 exit 1;
	  }
  }
else
  {
	 print $LogFileH GetDate." [LOG ERROR]: Failed to get the uptime command.\n";
	 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	 print $LogFileH GetDate." [STATUS ]: Failure \n";
	 close $LogFileH;
	 exit 1;
  }
 
########################################################################################
####### Get the CPU details ############################################################

sleep(5);

%OutputSet=();

if($Command{'cpu'} ne "")
  {
    my $CommandSet=$Command{'cpu'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH);
	
    # print $LogFileH "show process cpu output start\n###################\n";
    # print$LogFileH $OutputSet{'show processes cpu'};
    # print $LogFileH "show process output output end\n###################\n";
	 
    $flag=CheckCPUUtilization(prostr=>\%OutputSet,devicetype=>$DeviceType,threshold=>$CPUThreshold,fileptr=>$LogFileH);

    if($flag==1)
	  {
		 print $LogFileH GetDate." [STATUS ]: Failure \n";
		 close $LogFileH;
		 exit 1;			
	  }		  
  }
else
  {
	 print $LogFileH GetDate." [LOG ERROR]: Failed to get the cpu command.\n";
	 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	 print $LogFileH GetDate." [STATUS ]: Failure \n";
	 close $LogFileH;
	 exit 1;
  }

########################################################################################
####### Get the Memory details ############################################################

sleep(5);

$flag=0;
%OutputSet=();

if($Command{'memory'} ne "")
  {
    my $CommandSet=$Command{'memory'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH);
	
	# print $LogFileH "show memory output start\n###################\n";
    # print$LogFileH $OutputSet{'show memory'};
    # print $LogFileH "show memory output end\n######################\n";

    $flag=CheckMemoryUtilization(prostr=>\%OutputSet,devicetype=>$DeviceType,threshold=>$MemThreshold,fileptr=>$LogFileH);

    if($flag==1)
	  {
		print $LogFileH GetDate." [STATUS ]: Failure \n";
		 close $LogFileH;
		 exit 1;			
	  }		  
  }
else
  {
    print $LogFileH GetDate." [LOG ERROR]: Failed to get the memory command.\n";
    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
    print $LogFileH GetDate." [STATUS ]: Failure \n";
    close $LogFileH;
    exit 1;
 }

######################################################################################
####### Check for Latency ############################################################

 print $LogFileH GetDate." [LOG INFO]: Pinging $DeviceIP to measure the latency.\n";

 if(PingDevice($DeviceIP)==1)
   {
	 print $LogFileH GetDate." [LOG INFO]: Current Round Trip Time is $RTT ms.\n";
	
	 if($RTT>400)
	   {
		 print $LogFileH GetDate." [LOG INFO]: Latency is high to the device $DeviceIP.\n";
		 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		 print $LogFileH GetDate." [STATUS ]: Failure \n";
		 close $LogFileH;
		 exit 0;
	   }
	  else
	   {
		 print $LogFileH GetDate." [LOG INFO]: Latency is OK to the device $DeviceIP.\n";
	   }
   }
  else
   {
	 print $LogFileH GetDate." [LOG ERROR]: Ping failed to the Device $DeviceIP. Failed to obtain latency.\n";
	 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	 print $LogFileH GetDate." [STATUS ]: Failure \n";
	 close $LogFileH;
	 exit 1;
   }

########################################################################################
####### Get the Interface details #####################################################

sleep(5);

%OutputSet=();

print $LogFileH GetDate." [LOG INFO]: Proceeding to check the interface logs for the device $DeviceIP.\n";

if($Command{'interface'} ne "")
  {
	 
    my $CommandSet=$Command{'interface'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH); 
   
    # print $LogFileH "show clock output start\n####################################\n";
    # print$LogFileH $OutputSet{'show clock'};
    # print $LogFileH "show clock output end\n##########################\n";
   
    # print $LogFileH "show log output start\n########################\n";
    # print$LogFileH $OutputSet{'show log | in UPDOWN'};
    # print $LogFileH "show log output end\n#########################";
   

   GetInterfaceLogs(%OutputSet);
 }
else
 {
   print $LogFileH GetDate." [LOG ERROR]: Failed to get the Interface command.\n";
   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
   print $LogFileH GetDate." [STATUS ]: Failure \n";
   close $LogFileH;
   exit 1;
 }

 close $LogFileH;