####################################################################################
# Script Name : HighMemoryUtilization.pl                                           #
# Purpose     : This is the main script which gets triggered by TEM layer for      #
#               HIGH Memory UTILIZATION Network Alerts. The inputs and the Device  #
#				type are validated. Log file is created and updated for each step. #                                                                                  #
# Author      : Sujeet Kumar Padhi                                                 #
# Date        : 31/01/2017                                                         #           
# Inputs      : DeviceType, Threshold, DeviceIP, Username, Encrypted Password,     #
#               Ticket Number                                                      #
####################################################################################


use strict;
use Switch;
#use UtilityModule;    #User Defined Module for utility
use UtilityModule_V3;

my $AlertExecId = $ARGV[0];
my $DeviceIP = $ARGV[1];
my $Attributes = $ARGV[2];

my $Command='';
my $LogFileH;
my %RemoteOutput=();
my $MemStatus=0;

#my $Username='admin';
#my $EncrPass='admin';

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
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show memory'})." \n";
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
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show memory'})." \n";
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
					  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show memory'})." \n";
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
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show memory'})." \n";
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
						print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
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
						 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
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
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
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
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'top -b -n 1'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'cat /VERSION'})." \n";
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
			    print $LogFileH GetDate." [LOG ERROR]: Unable to get the version of F5 Device.\n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'cat /VERSION'})." \n";
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
						  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'})." \n";
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
				   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'})." \n";
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
				   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'})." \n";
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
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'tmsh show sys memory raw| head | grep TMM'})." \n";
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
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show status'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show advanced-url /TM/Statistics'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show ip-stats'})." \n";
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
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show status'})." \n";
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
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'get system performance status'})." \n";
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'diagnose sys top-summary'})." \n";
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
				  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh memory'})." \n";
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
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh memory'})." \n";
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
						  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh memory'})." \n";
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
				print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'sh memory'})." \n";
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
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system resources'})." \n";
				 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes memory'})." \n";
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
						print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system resources'})." \n";
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
						 print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system resources'})." \n";
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
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show system resources'})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim(${$RemoteOutput}{'show processes memory'})." \n";
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
					$flag=1;
					$usedMem = $1;
					
				  }
			  }
			  foreach(@RemoteOutputSet)
			  {
				$CurrentUtil=$_;
				
				if(trim($_)=~/System\smemory\:\s.*\s+([0-9]+)\sMB\stotal/i)
				  {
					$flag=1;
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
				 print $LogFileH GetDate." [LOG INFO]: Memory utilization crossed threshold\n";
				 print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
			  }
			else
			  {
				 $MemStatus=0;
				 print $LogFileH GetDate." [LOG INFO]: Memory utilization is below threshold now.\n";
				 print $LogFileH GetDate." [LOG INFO]: Current Utilization is ".$utilization."%\n";
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
			
		    
		    if(trim(${$RemoteOutput}{'sh memory detail'}) ne "")
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
			my $usedMem;
			my $totalMem;
			my $CurrentUtil;
		   
		    foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
			    if(trim($_)=~/Used\sMemory:\s+([0-9]){1,8}\s+KB/)
				  {
				    $flag=1;
				    $usedMem = $1;
					print "\nUsed Memory:$usedMem";
				  }
			  }
			  foreach(@RemoteOutputSet)
			  {
			    $CurrentUtil=$_;
			    if(trim($_)=~/Total\sMemory:\s+([0-9]){1,8}\s+KB/)
				  {
				    $flag=1;
				    $totalMem = $1;
					print "\nTotal Memory:$totalMem";
				  }
			  }
			  eval
			  {
				     $utilization=sprintf ("%.2f",(trim($usedMem)/trim($totalMem))*100);
			  };
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
my $Threshold=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'MEMThrld','fileptr'=>$LogFileH);
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

print $LogFileH GetDate." [LOG INFO]: Devicetype->".$DeviceType."::Threshold->".$Threshold."::DeviceIP->".$DeviceIP."\n";


############################################################################################################
# Get Memory Utilization and Top 5 Processes based on the Device Type
############################################################################################################


#print $LogFileH GetDate." [LOG INFO]: Validating device type to proceed further.\n";

switch ($DeviceType)
{
   case [@CiscoRTSW]  
   {
     $Command="term len 0;show memory"; 
   }
   
   case [@CiscoASA] 
   {
     $Command="en;$EnablePasswd;sh memory;sh processes memory"; #Set the default login mode
   }
   case [@Checkpoint] 
   {
     $Command="top -b -n 1"; #Set the default login mode
   }
   case [@F5Device] 
   {
     $Command="bash;cat /VERSION;tmsh show sys memory raw| head | grep TMM;top -b -n 1"; #Set the default login mode
   }
   case [@Bluecoat] 
   {
     $Command="show status;show advanced-url /TM/Statistics;show ip-stats"; #Set the default login mode
   }
   case [@Fortinet] 
   {
     $Command="get system performance status;diagnose sys top-summary"; #Set the default login mode
   }
   case [@CiscoNexus] 
   {
     $Command="term len 0;show system resources;show processes memory"; #Set the default login mode
   }
   case [@JunOS] 
   {
     $Command="show chassis routing-engine | match Memory;show system memory all-members"; #Set the default login mode
   }
   case [@Riverbed] 
   {
     $Command="sh version"; #Set the default login mode
   }
   case [@Aerohive] 
   {
     $Command="sh memory detail"; #Set the default login mode
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

%RemoteOutput=GetRemoteData(deviceip=>"$DeviceIP",username=>"$Username",password=>"$EncrPass",command=>"$Command",fileptr=>$LogFileH);
print "\n After the connection...";
print $LogFileH GetDate." [LOG INFO]: ****************************************************\n";
print $LogFileH GetDate." [LOG INFO]: Output from the device:\n";

#print $LogFileH GetDate." [LOG INFO]: Output logs for alert $AlertExecId initiating...\n";
#print $LogFileH GetDate." [LOG INFO]: Proceeding to check the current utilization of Memory.\n";

# foreach (keys %RemoteOutput){
  # print "$_ => $RemoteOutput{$_}";
# }

#Call "CheckMemoryUtilization" to Check if memory utilization is above threshold and obtain the top 5 memory processes
	 
$MemStatus=CheckMemoryUtilization(prostr=>\%RemoteOutput,devicetype=>$DeviceType,threshold=>$Threshold,fileptr=>$LogFileH);
	 
if($MemStatus==0)
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
# End Of HighMemoryUtilization.pl
########################################################################################################