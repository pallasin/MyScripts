##########################################################################################################
# Script Name : BadLinkDetected.pl                                                                       #
# Purpose     : This is the main script which gets triggered by TEM layer for Bad Link Detected          #
#               Network Alerts. The inputs and the Device type are validated. This module performs       # 
#				different checks such as Pinging the device, getting the traceroute results.             # 
#               This module also Uptime and interface logs. Result of each step is maintained in a log   #
#               file.                                                                                    #
#               Log file is created and updated for each step.                                           #                                
# Author      : Sujeet Kumar Padhi                                                                       #
# Date        : 21/03/2017                                                                               #           
# Inputs      : DeviceType, Threshold, DeviceIP, Username, Encrypted Password                            #
##########################################################################################################


use strict;
use Net::SSH2;
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
my $InterfaceCmd='';

my $InterfaceName=undef;

my $Username=undef;
my $EncrPass=undef;
my $Notes=undef;

my $EnablePasswd=undef;
my $DeviceType;
my $OSName=undef;

my %OutputSet=();

 
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
# End Of PingDevice
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
		print $LogFileH GetDate." [LOG ERROR]: Error: $trout.\n";
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
########################################################################################################
#
########################################################################################################
sub GetInterfaceError
 {
   my %OutSet=@_;  
  
   switch ($DeviceType)
    {
      case [@CiscoRTSW] 
        { 
		  my @temp=();
		  
		  if(trim($OutSet{"show interfaces $InterfaceName | I error"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName | I error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show interfaces $InterfaceName | I error"}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName | I error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  @temp=split("\n",$OutSet{"show interfaces $InterfaceName | I error"});
		  
		  my $flag1=0;
		  my $flag2=0;
		  my $inerr;
		  my $outerr;
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/^([0-9]+)\s+input\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag1=1;
				  $inerr=$1;
				}
			  if(trim($_)=~/^([0-9]+)\s+output\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag2=1;
				  $outerr=$1;
				}
			}
			
		  if($flag1==1 and $flag2==1)
		    {
			  if($inerr >0 or $outerr>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName | I error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		}
      case [@CiscoASA]
        { 
		  my @temp=();
		  
		  if(trim($OutSet{"show interface $InterfaceName | include error"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName | include error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show interface $InterfaceName | include error"}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName | include error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  @temp=split("\n",$OutSet{"show interface $InterfaceName | include error"});
		  
		  my $flag1=0;
		  my $flag2=0;
		  my $inerr;
		  my $outerr;
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/^([0-9]+)\s+input\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag1=1;
				  $inerr=$1;
				}
			  if(trim($_)=~/^([0-9]+)\s+output\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag2=1;
				  $outerr=$1;
				}
			}
			
		  if($flag1==1 and $flag2==1)
		    {
			  if($inerr >0 or $outerr>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName | include error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		}	
      case [@CiscoNexus]
        { 
		  my @temp=();
		  
		  if(trim($OutSet{"show interface $InterfaceName | include error"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName | include error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show interface $InterfaceName | include error"}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName | include error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  @temp=split("\n",$OutSet{"show interface $InterfaceName | include error"});
		  
		  my $flag1=0;
		  my $flag2=0;
		  my $inerr;
		  my $outerr;
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/^([0-9]+)\s+input\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag1=1;
				  $inerr=$1;
				}
			  if(trim($_)=~/^([0-9]+)\s+output\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag2=1;
				  $outerr=$1;
				}
			}
			
		  if($flag1==1 and $flag2==1)
		    {
			  if($inerr >0 or $outerr>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName | include error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		}		
	  case [@Checkpoint]
        { 		  
		  if(trim($OutSet{"ifconfig $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"ifconfig $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		   
		   my @temp=();
		   my $flag1=0;
		   my $flag2=0;
		   my $inerr;
		   my $outerr;
		    
		   @temp=split("\n",trim($OutSet{"ifconfig $InterfaceName"}));
			
		   foreach(@temp)
			  {
			     if(trim($_)=~/RX\s+packet.*error[s]*\s*:\s*([0-9]+)\s+/i)
				   {
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					 $flag1=1;
					 $inerr=$1;					 
				   }
				 if(trim($_)=~/TX\s+packet.*error[s]*\s*:\s*([0-9]+)\s+/i)
				   {
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					 $flag2=1;
					 $outerr=$1;					 
				   }
			  }
			
		   if($flag1==1 and $flag2==1)
		    {
			  if($inerr >0 or $outerr>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"ifconfig $InterfaceName"})." \n";
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
		   if(trim($OutSet{"show net interface $InterfaceName all-properties"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show net interface $InterfaceName all-properties"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
			my @temp=();
			my @interfaceprop;
			my $flag=0;
			my $inerr;
			my $outerr;
		    
			@temp=split("\n",trim($OutSet{"show net interface $InterfaceName all-properties"}));
			
			foreach(@temp)
			  {
                if(trim($_)=~/^$InterfaceName/)
				  {
					$flag=1;
					@interfaceprop=split(/\s+/,$_);
					$inerr=trim($interfaceprop[12]);
					$outerr=trim($interfaceprop[13]);
					if($inerr !~ /[0-9]+/ or $outerr !~ /[0-9]+/)
					  {
					    print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error details.\n";
						print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show net interface $InterfaceName all-properties"})." \n";
						print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	                    print $LogFileH GetDate." [STATUS ]: Failure \n";
	                    close $LogFileH;
			            exit 1;
					  }
					last;
				  }							
			  }
			
			if($flag==1)
		      {
				 if($inerr >0 or $outerr>0)
				   {
					  return 0;
				   }
				 else
				   {
					  return 1;
				   }
			   }
		    else
		      {
				  print $LogFileH GetDate." [LOG ERROR]: Failed to find the interface error.\n";
				  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show net interface $InterfaceName all-properties"})." \n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  print $LogFileH GetDate." [STATUS ]: Failure \n";
				  close $LogFileH;
				  exit 1;
			  }
		}
	  case [@Bluecoat]
	    {
		  if(trim($OutSet{'show ip-stats'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show ip-stats"})." \n";
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
		   my $inerr;
		   my $outerr;
		    
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
				   if(trim($_)=~/$InterfaceName/ and trim($_)=~/^Interface/)
					 {
					   $flag3=1;
					   @temp1=split("\n",$_);
					   foreach(@temp1)
						 {
						   if($_=~/Input\serror[s]*\s+([0-9]+).*/i)
							 {
							   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
							   $flag4=1;	
                               $inerr=$1;							   
							 }
						   if($_=~/Output\serror[s]*\s+([0-9]+).*/i)
							 {
							   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
							   $flag5=1;
							   $outerr=$1;							   
							 }
						 }
					   last;
					 }
				 }
				 
			   if($flag3==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
					print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show ip-stats"})." \n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }

			   if($flag4==1 and $flag5==1)
				 {
				   if($inerr >0 or $outerr>0)
					 {
					   return 0;
					 }
				   else
					 {
					   return 1;
					 }
				 }
			   else
				 {
				   print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
				   print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show ip-stats"})." \n";
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
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error3: ".trim($OutSet{"show ip-stats"})." \n";
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
		   if(trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName | grep error"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName | grep error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		   my @temp=();
		   my $flag1=0;
		   my $flag2=0;
		   my $inerr;
		   my $outerr;
		    
		   @temp=split("\n",trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName | grep error"}));
			
		   foreach(@temp)
			  {
			     if(trim($_)=~/Rx[\s_]+error[s]*\s*[:=]*\s*([0-9]+).*/i)
				   {
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					 $flag1=1;
					 $inerr=$1;					 
				   }
				 if(trim($_)=~/Tx[\s_]+error[s]*\s*[:=]*\s*([0-9]+).*/i)
				   {
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					 $flag2=1;
					 $outerr=$1;					 
				   }
			  }
			
		   if($flag1==1 and $flag2==1)
		    {
			  if($inerr >0 or $outerr>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName | grep error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		}
	  case [@HPSwitch]
	    {
		  my @temp=();
		  
		  if(trim($OutSet{"display interface $InterfaceName | I error"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"display interface $InterfaceName | I error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{"display interface $InterfaceName | I error"});
		  
		  my $flag1=0;
		  my $flag2=0;
		  my $inerr;
		  my $outerr;
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/^([0-9]+)\s+input\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag1=1;
				  $inerr=$1;
				}
			  if(trim($_)=~/^([0-9]+)\s+output\s+error.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag2=1;
				  $outerr=$1;
				}
			}
			
		  if($flag1==1 and $flag2==1)
		    {
			  if($inerr >0 or $outerr>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"display interface $InterfaceName | I error"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		}
	  case [@JunOS]
	    {
		  my @temp=();
		  
		  #if(trim($OutSet{"show interfaces $InterfaceName"}) eq "")
		  if(trim($OutSet{"show interfaces $InterfaceName extensive | match error"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		 # @temp=split("\n",$OutSet{"show interfaces $InterfaceName"});
		  @temp=split("\n",$OutSet{"show interfaces $InterfaceName extensive | match error"});
		  my $flag=0;
		  my $flag1=0;
		  my $flag2=0;
		  my $input_drops;
		  my $framing_errors;
		  my $car_trans;
		  my $output_drops;
		  my $crc_errors;
		 
		  
		  foreach (@temp)
		    {
			 
			  if(trim($_)=~/Errors\:.*\,\s+Drops\:\s+([0-9]+)\,\s+Framing\s+errors\:\s+([0-9]+)/i)
			    {
				 # print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag=1;
				  $input_drops=$1;
				  $framing_errors=$2;
				  #last;
				}
			}
			 foreach (@temp)
		    {
			
			  if(trim($_)=~/Carrier\s+transitions\:\s+([0-9]+)\,\s+Errors\:.*\,\s+Drops\:\s+([0-9]+)/i)
			    {
				 # print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag1=1;
				  $car_trans=$1;
				  $output_drops=$2;
				  #last;
				}
			}
			foreach (@temp)
		    {
			  
			  if(trim($_)=~/CRC\s+errors\:\s+([0-9]+)/i)
			    {
				 # print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag2=1;
				  $crc_errors=$1;
				  #$output_drops=$2;
				  last;
				}
			}
		  if($flag==1 and $flag1==1 and $flag2==1)
		    {
			  if($input_drops >0 or $framing_errors>0 or $car_trans>0 or $output_drops>0 or $crc_errors>0)
			    {
				 
				  print $LogFileH GetDate." [LOG INFO]:Input drops:$input_drops Framing errors:$framing_errors Carrier transitions:$car_trans Output Drops:$output_drops CRC errors:$crc_errors\n";
				  return 0;
				}
			   else
			    {
				  print $LogFileH GetDate." [LOG INFO]:Input drops:$input_drops Framing errors:$framing_errors Carrier transitions:$car_trans Output Drops:$output_drops CRC errors:$crc_errors\n";
				 
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
		}
	  case [@JunNetScreen]
	    {
		   my @temp=();
		  
		  if(trim($OutSet{"get counter statistics interface $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"get counter statistics interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{"get counter statistics interface $InterfaceName"});
		  
		  my $flag1=0;
		  my $flag2=0;
		  my $inerr1;
		  my $inerr2;
		  my $outerr;
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/in\s+coll\s+err\s+([0-9]+)\s*\|\s*out\s+coll\s+err\s+([0-9]+)\s*\|.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag1=1;
				  $inerr1=$1;
				  $inerr2=$2;
				}
			  if(trim($_)=~/in\s+crc\s+err\s+([0-9]+)\s*\|.*/i)
			    {
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  $flag2=1;
				  $outerr=$1;
				}
			}
			
		  if($flag1==1 and $flag2==1)
		    {
			  if($inerr1 >0 or $outerr>0 or $inerr2>0)
			    {
				  return 0;
				}
			   else
			    {
				  return 1;
				}
			}
		   else
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"get counter statistics interface $InterfaceName"})." \n";
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
           print $LogFileH GetDate." [LOG ERROR]: DeviceType is $DeviceType not found. Exiting ...\n";
		   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	       print $LogFileH GetDate." [STATUS ]: Failure \n";
	       close $LogFileH;
	       exit 1;
        }
    }
   
   
 }
#########################################################################################
#########################################################################################
########################################################################################################
#
########################################################################################################
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
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  if($OutSet{'show clock'}=~/.*((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}).*/)
		    {
	          @temp=split(/\s+/,$1);
			  $month=trim($temp[0]);
	          $date=trim($temp[1]);
			  
			  if($month eq "" or $date eq "")
			    {
				  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
				  print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show clock"})." \n";
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
			  print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{"show logging | include UPDOWN.*$InterfaceName"});
		  
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
              return 1;
			}
		  else
		    {
              return 0;
			}
		}
      case [@CiscoASA]
        { 
		  my @temp=();
		  my $month;
		  my $date;
		  my $flag=0;
		  
		  if(trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs for the current date. \n";
	          return 1;
			}
			
		  if(trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  if($OutSet{'show clock'}=~/.*((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}).*/)
		    {
	          @temp=split(/\s+/,$1);
			  $month=trim($temp[0]);
	          $date=trim($temp[1]);
			  
			  if($month eq "" or $date eq "")
			    {
				  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
				  print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show clock"})." \n";
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
			  print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{"show logging | include UPDOWN.*$InterfaceName"});
		  
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
              return 1;
			}
		  else
		    {
              return 0;
			}
        }
      case [@CiscoNexus]
        { 
		  my @temp=();
		  my $month;
		  my $date;
		  my $flag=0;
		  
		  if(trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs for the current date. \n";
	          return 1;
			}
			
		  if(trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"}) =~ /Invalid\s+input\s+detected/i or trim($OutSet{'show clock'}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show logging | include UPDOWN.*$InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
			
		  if($OutSet{'show clock'}=~/.*((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}).*/)
		    {
	          @temp=split(/\s+/,$1);
			  $month=trim($temp[0]);
	          $date=trim($temp[1]);
			  
			  if($month eq "" or $date eq "")
			    {
				  print $LogFileH GetDate." [LOG ERROR]: Unable to parse the Month and date.\n";
				  print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show clock"})." \n";
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
			  print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show clock"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  @temp=split("\n",$OutSet{"show logging | include UPDOWN.*$InterfaceName"});
		  
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
              return 1;
			}
		  else
		    {
              return 0;
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
				  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfacemonitor"})." \n";
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
					print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfacemonitor"})." \n";
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
					return 1;
				 }
				else
				 {
					return 0;
				 }
			}
			
	      elsif($OSName eq 'GAIA' or $OSName eq 'SPLAT')
		    {
			  if(trim($OutSet{'cat /var/log/messages | egrep -i "(\bup\b|\bdown\b)"'}) eq "")
				{
				  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
				  return 1;
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
					return 1;
				 }
			   else
				 {
					return 0;
				 }
			}
        }
	  case [@F5Device]
	    {
		   if(trim($OutSet{"cat /var/log/ltm | grep $InterfaceName | grep up | grep down"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
			  return 1;
			}
			
			my @temp=();
			my $flag=0;
		    
			@temp=split("\n",trim($OutSet{"cat /var/log/ltm | grep $InterfaceName | grep up | grep down"}));
			
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
			    return 1;
			  }
			else
			  {
				return 0;
			  }
		}
	  case [@Bluecoat]
	    {
		  if(trim($OutSet{'show ip-stats'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show ip-stats"})." \n";
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
				   if(trim($_)=~/$InterfaceName/ and trim($_)=~/^Interface/)
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
							       print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
							       return 0;
								 }
							   else
							     {
								   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
								   print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
								   return 1;
								 }
							 }
						 }
					   last;
					 }
				 }
				 
			   if($flag3==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface details.\n";
					print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show ip-stats"})." \n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
			   
			   if($flag4==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
					print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show ip-stats"})." \n";
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
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface flapping details.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error3: ".trim($OutSet{"show ip-stats"})." \n";
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
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"execute log display"})." \n";
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
			
		   foreach(@temp)
			  {
			    chomp;
			    next if(trim($_)=~/execute\slog\sdisplay/);
				next if(trim($_)=~/^$/);
				
				if(trim($_)=~/$InterfaceName/)
				  {
				     $flag=1;
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
                  }					
			  }
			
		   if($flag==0)
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
              return 1;
			}
		  else
		    {
              return 0;
			}
		}
	  case [@HPSwitch]
	    {
		   if(trim($OutSet{'display logbuffer reverse'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"display logbuffer reverse"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		   my @temp=();
		   my $flag=0;
		    
		   @temp=split("\n",trim($OutSet{'display logbuffer reverse'}));
			
		   foreach(@temp)
			  {
			    chomp;
			    next if(trim($_)=~/display\slogbuffer\sreverse/);
				next if(trim($_)=~/^$/);
				
				if(trim($_)=~/$InterfaceName/)
				  {
				     $flag=1;
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
                  }					
			  }
			
		   if($flag==0)
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
              return 1;
			}
		  else
		    {
              return 0;
			}
		}
	  case [@JunOS]
	    {
			#print "\nOutput of flap Logs: ".trim($OutSet{"show interfaces $InterfaceName | match flap"})."\n";
		  if(trim($OutSet{"show interfaces $InterfaceName | match flap"}) eq "")
	
		    {
			  #print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error:".trim($OutSet{"show interfaces $InterfaceName | match flap"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  return 1;
			  exit 1;
			}
			  my @temp=split("\n",$OutSet{"show interfaces $InterfaceName | match flap"});
			  foreach my $temp1 (@temp)
				{
				  if(trim($temp1)=~/Last\s+flapped/i)
				  {
					print $LogFileH GetDate."[LOG INFO]:Flapping Logs for interface $InterfaceName: ".trim($OutSet{"show interfaces $InterfaceName | match flap"})." \n";
					#print "\n Inside";
					return 0;
				  }
				}
			

		}
	  case [@JunNetScreen]
	    {
		  if(trim($OutSet{'get log tr ?'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"get log tr ?"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		   my @temp=();
		   my $flag=0;
		    
		   @temp=split("\n",trim($OutSet{'get log tr ?'}));
			
		   foreach(@temp)
			  {
			    chomp;
			    next if(trim($_)=~/get\slog\str/);
				next if(trim($_)=~/^$/);
				
				if(trim($_)=~/$InterfaceName/)
				  {
				     $flag=1;
				     print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
                  }					
			  }
			
		   if($flag==0)
		    {
			  print $LogFileH GetDate." [LOG INFO]: Automation could not find any interface flapping logs.\n";
              return 1;
			}
		  else
		    {
              return 0;
			}
		}
	  else 
        {
           print $LogFileH GetDate." [LOG ERROR]: DeviceType is $DeviceType not found. Exiting ...\n";
		   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	       print $LogFileH GetDate." [STATUS ]: Failure \n";
	       close $LogFileH;
	       exit 1;
        }
    }
   
   
 }
#########################################################################################
#########################################################################################

sub GetInterfaceStatus
 {
   my %OutSet=@_;  
  
   switch ($DeviceType)
    {
      case [@CiscoRTSW] 
        { 
		  my @temp=();
		  
		  if(trim($OutSet{"show interfaces $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show interfaces $InterfaceName"}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
					  			
		  @temp=split("\n",$OutSet{"show interfaces $InterfaceName"});
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/line\s+protocol/i)
			    {
				  if(trim($_)=~/\bdown\b/i)
				    {
					  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  return 0;
					}
                  else
				    {
					  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  return 1;
					}
                  last;					
				}
			}

		  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	      print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	      print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;
		}
      case [@CiscoASA]
	    {
		  my @temp=();
		  
		  if(trim($OutSet{"show interface $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show interface $InterfaceName"}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
					  			
		  @temp=split("\n",$OutSet{"show interface $InterfaceName"});
		  
		  foreach (@temp)
		    {
			   if(trim($_)=~/is\s+down/i)
				 {
					print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					return 0;
				 }
               if(trim($_)=~/is\s+up/i)
				 {
					print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					return 1;
				 }					
			}

		  print $LogFileH GetDate." [LOG INFO]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	      print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;
		}
    case [@CiscoNexus]
	    {
		  my @temp=();
		  
		  if(trim($OutSet{"show interface $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	          print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	          print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		  if(trim($OutSet{"show interface $InterfaceName"}) =~ /Invalid\s+input\s+detected/i)
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Invalid command executed to get device logs.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
		    }
					  			
		  @temp=split("\n",$OutSet{"show interface $InterfaceName"});
		  
		  foreach (@temp)
		    {
			   if(trim($_)=~/is\s+down/i)
				 {
					print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					return 0;
				 }
               if(trim($_)=~/is\s+up/i)
				 {
					print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					return 1;
				 }					
			}

		  print $LogFileH GetDate." [LOG INFO]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interface $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	      print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;
		}		
	  case [@Checkpoint]
        { 
          my @temp=();
		  my @temp1=();
		  my $flag1=0;
		  my $flag2=0;
		  my $tempstr;
		  my $intstr='';
		  my $line;
		  
		  if($OSName eq 'IPSO')
		    {
			  if(trim($OutSet{'show interfacemonitor'}) eq "")
				{
				  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
				  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfacemonitor"})." \n";
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
				   if(trim($_)=~/$InterfaceName/ and trim($_)=~/^Interface/)
					 {
					   $flag1=1;
					   @temp1=split("\n",$_);
					   foreach(@temp1)
						 {
							 if($_=~/.*Status\s+up.*/i)
							   {
								  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
								  return 1;
							   }
							 if($_=~/.*Status\s+down.*/i)
							   {
								  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
								  return 0;
							   }
						  }
					   last;
					  }
				 }
				 
			   if($flag1==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface details.\n";
					print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show interfacemonitor"})." \n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
				 
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface status details.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show interfacemonitor"})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
			   print $LogFileH GetDate." [STATUS ]: Failure \n";
			   close $LogFileH;
			   exit 1;
		    }
			
		   elsif($OSName eq 'GAIA' or $OSName eq 'SPLAT')
		    {
			  if(trim($OutSet{"ifconfig $InterfaceName"}) eq "")
				{
				  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
				  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"ifconfig $InterfaceName"})." \n";
				  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
				  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
				  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
				  print $LogFileH GetDate." [STATUS ]: Failure \n";
				  close $LogFileH;
				  exit 1;
				}
				
			   @temp=split("\n",trim($OutSet{"ifconfig $InterfaceName"}));
				
			   foreach(@temp)
				  {
					 if(trim($_)=~/^\bUP\b/)
					   {
						 print $LogFileH GetDate." [LOG INFO]: ".trim($_)."\n";
						 return 1;
					   }
				  }
							   
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface error.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"ifconfig $InterfaceName"})." \n";
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
		   if(trim($OutSet{"show net interface $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show net interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
			my @temp=();
		    
			@temp=split("\n",trim($OutSet{"show net interface $InterfaceName"}));
			
			foreach(@temp)
			  {
			    if(trim($_)=~/^$InterfaceName/)
				  {
					if(trim($_)=~/\bup\b/)
					  {
					    print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
						return 1;
					  }
					if(trim($_)=~/\bdown\b/)
					  {
					    print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
						return 0;
					  }
					 last;
				  }			
			  }
			
          print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show net interface $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;

		}
	  case [@Bluecoat]
	    {
		  if(trim($OutSet{'show ip-stats'}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show ip-stats"})." \n";
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
				   if(trim($_)=~/$InterfaceName/ and trim($_)=~/^Interface/)
					 {
					   $flag3=1;
					   @temp1=split("\n",$_);
					   foreach(@temp1)
						 {
						   if($_=~/.*Link\s+status\s+UP.*/i)
							 {
							   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
							   return 1;
							 }
						   if($_=~/.*Link\s+status\s+DOWN.*/i)
							 {
							   print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
							   return 0;
							 }
						 }
					   last;
					 }
				 }
				 
			   if($flag3==0)
				 {
					print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface status details.\n";
					print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show ip-stats"})." \n";
					print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
					print $LogFileH GetDate." [STATUS ]: Failure \n";
					close $LogFileH;
					exit 1;
				 }
				 
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
			   print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show ip-stats"})." \n";
			   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		       print $LogFileH GetDate." [STATUS ]: Failure \n";
		       close $LogFileH;
		       exit 1;
			  
			 }
		   else
		     {
			   print $LogFileH GetDate." [LOG ERROR]: Unable to find the Interface status details.\n";
			   print $LogFileH GetDate." [LOG ERROR]: Error3: ".trim($OutSet{"show ip-stats"})." \n";
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
		   if(trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
			
		   my @temp=();
		    
		   @temp=split("\n",trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName"}));
			
		   foreach(@temp)
			  {
			    if(trim($_)=~/Link\s*:*\s*up.*/i)
				  {
				    return 1;
				  }
                if(trim($_)=~/Link\s*:*\s*down.*/i)
				  {
				    return 0;
				  }					  
			  }
			
		   print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
		   print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"diagnose hardware deviceinfo nic $InterfaceName"})." \n";
		   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		   print $LogFileH GetDate." [STATUS ]: Failure \n";
		   close $LogFileH;
		   exit 1;

		}		
	  case [@HPSwitch]
	    {
		  my @temp=();
		  
		  if(trim($OutSet{"display interface $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"display interface $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
					  			
		  @temp=split("\n",$OutSet{"display interface $InterfaceName"});
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/line\s+protocol/i)
			    {
				  if(trim($_)=~/\bdown\b/i)
				    {
					  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  return 0;
					}
				  elsif(trim($_)=~/\bup\b/i)
				    {
					  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  return 1;
					}
                  else
				    {
					  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
					  print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"display interface $InterfaceName"})." \n";
					  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		              print $LogFileH GetDate." [STATUS ]: Failure \n";
		              close $LogFileH;
		              exit 1;
					}	
                  last;					
				}
			}

		  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"display interface $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;
		}
	  case [@JunOS]
	    {
		  my @temp=();
		  
		  if(trim($OutSet{"show interfaces $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
					  			
		  @temp=split("\n",$OutSet{"show interfaces $InterfaceName"});
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/Physical\s+link\s+is/i)
			    {
				  if(trim($_)=~/\bdown\b/i)
				    {
					  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  return 0;
					}
				  elsif(trim($_)=~/\bup\b/i)
				    {
					  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
					  return 1;
					}
                  else
				    {
					  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
					  print $LogFileH GetDate." [LOG ERROR]: Error1: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
					  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
					  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
					  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		              print $LogFileH GetDate." [STATUS ]: Failure \n";
		              close $LogFileH;
		              exit 1;
					}	
                  last;					
				}
			}

		  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error2: ".trim($OutSet{"show interfaces $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;
		}
	  case [@JunNetScreen]
	    {
		  my @temp=();
		  
		  
		  if(trim($OutSet{"get interfaces $InterfaceName"}) eq "")
		    {
			  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface data from device.\n";
			  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"get interfaces $InterfaceName"})." \n";
			  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
			  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
			  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	          print $LogFileH GetDate." [STATUS ]: Failure \n";
	          close $LogFileH;
			  exit 1;
			}
					  			
		  @temp=split("\n",$OutSet{"get interfaces $InterfaceName"});
		  
		  foreach (@temp)
		    {
			  if(trim($_)=~/link\s+up/i)
				{
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  return 0;
				}
			  elsif(trim($_)=~/link\s+down/i)
				{
				  print $LogFileH GetDate." [LOG INFO]: ".$_."\n";
				  return 1;
				}		
			}

		  print $LogFileH GetDate." [LOG ERROR]: Unable to find the interface status. \n";
		  print $LogFileH GetDate." [LOG ERROR]: Error: ".trim($OutSet{"get interfaces $InterfaceName"})." \n";
		  print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		  print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		  print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		  print $LogFileH GetDate." [STATUS ]: Failure \n";
		  close $LogFileH;
		  exit 1;
		}
	  else 
        {
           print $LogFileH GetDate." [LOG ERROR]: DeviceType is $DeviceType not found. Exiting ...\n";
		   print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		   print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		   print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	       print $LogFileH GetDate." [STATUS ]: Failure \n";
	       close $LogFileH;
	       exit 1;
        }
    }
   
   
 }

#########################################################################################
#########################################################################################


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

print $LogFileH GetDate." [LOG INFO]: Actions Taken:\n";

#print $LogFileH GetDate." [LOG INFO]: Logs for alert $AlertExecId initiating\n";

$DeviceType=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'DeviceType','fileptr'=>$LogFileH);
$Username=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'UserName','fileptr'=>$LogFileH);
$EncrPass=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'Password','fileptr'=>$LogFileH);
$EnablePasswd=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'EnablePassword','fileptr'=>$LogFileH);
$Notes=GetAttributeValue('attrlist'=>$Attributes,'attribute'=>'Notes','fileptr'=>$LogFileH);
 
if($Notes =~ /\_(.*)\stype/i)
  {
    if(index($1,'_')==-1)
	  {
         $InterfaceName=$1;
	  }
	else
	  {
	     $InterfaceName=substr($1,rindex($1,'_')+1);
	  }
  } 
elsif($Notes =~ /host:.*\_(.*?)\s/i)
	{
		$InterfaceName=trim($1);
	}
else
  {
    print $LogFileH GetDate." [LOG ERROR]: Unable find the Interface Details from the alert. Exiting ... \n";
	print $LogFileH GetDate." [LOG ERROR]: Error : $Notes \n";
	print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	print $LogFileH GetDate." [STATUS ]: Failure \n";
	close $LogFileH;
	exit 1;   
  }
 
################Printing the Interfacename############## 

#print "\nInterface Name : $InterfaceName\n";
  
if(trim($DeviceType) eq '' or trim($DeviceIP) eq '' or trim($Username) eq '' or trim($EncrPass) eq '')
  { 
	print $LogFileH GetDate." [LOG ERROR]: Please provide correct inputs. Exiting ... \n";
	print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	print $LogFileH GetDate." [STATUS ]: Failure \n";
	close $LogFileH;
	exit 1;   
  }

print $LogFileH GetDate." [LOG INFO]: Devicetype is ".$DeviceType."::DeviceIP is ".$DeviceIP."::Interface Name is ".$InterfaceName."\n";

############################################################################################################
	   	   
print $LogFileH GetDate." [LOG INFO]: ****************************************************\n";
print $LogFileH GetDate." [LOG INFO]: Output from the device:\n";


switch ($DeviceType)
{
   case [@CiscoRTSW] 
   {   
	 %Command=('uptime'=>'term len 0;show version','interfacestatus'=>"term len 0;show interfaces $InterfaceName",'interfacerr'=>"term len 0;show interfaces $InterfaceName | I error",'interfacelog'=>"term len 0;show clock;show logging | include UPDOWN.*$InterfaceName");	   
   }
   case [@CiscoASA] 
   {   
	 %Command=('uptime'=>'sh ver | grep up','interfacestatus'=>"en;$EnablePasswd;show interface $InterfaceName",'interfacerr'=>"en;$EnablePasswd;show interface $InterfaceName | include error",'interfacelog'=>"en;$EnablePasswd;show clock;show logging | include UPDOWN.*$InterfaceName");	   
   }
   case [@CiscoNexus] 
   {   
	 %Command=('uptime'=>'term len 0;show system uptime','interfacestatus'=>"term len 0;show interface $InterfaceName",'interfacerr'=>"term len 0;show interface $InterfaceName | include error",'interfacelog'=>"term len 0;show clock;show logging | include UPDOWN.*$InterfaceName");	   
   }
   case [@Checkpoint] 
   {
     
	 my $OSCommand='cpstat os -f all';
	 
     $OSName=GetCheckpointOS(deviceip=>"$DeviceIP",username=>"$Username",password=>"$EncrPass",command=>"$OSCommand",fileptr=>$LogFileH);
	 
	 if($OSName eq 'GAIA' or $OSName eq 'SPLAT')
	   {
          %Command=('uptime'=>'top -b -n 1 | grep up','interfacestatus'=>"ifconfig $InterfaceName",'interfacerr'=>"ifconfig $InterfaceName",'interfacelog'=>'cat /var/log/messages | egrep -i "(\bup\b|\bdown\b)"');
	   }
	 elsif($OSName eq 'IPSO')
	   {
          %Command=('uptime'=>'top -b -n 1 | grep up','interfacestatus'=>'clish;show interfacemonitor','interfacerr'=>"ifconfig $InterfaceName",'interfacelog'=>'clish;show interfacemonitor');
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
     %Command=('uptime'=>'bash;top -b -n 1 | grep up','interfacestatus'=>"show net interface $InterfaceName",'interfacerr'=>"show net interface $InterfaceName all-properties",'interfacelog'=>"bash;cat /var/log/ltm | grep $InterfaceName | grep up | grep down");
   }
   case [@Bluecoat]
   {
	 %Command=('uptime'=>'show clock;show status','interfacestatus'=>'show ip-stats','interfacerr'=>'show ip-stats','interfacelog'=>'show ip-stats');
   }
   case [@Fortinet]
   {
	 %Command=('uptime'=>'config global;get system performance status','interfacestatus'=>"config global;diagnose hardware deviceinfo nic $InterfaceName",'interfacerr'=>"config global;diagnose hardware deviceinfo nic $InterfaceName | grep error",'interfacelog'=>'config global;execute log filter category event;execute log filter field logdesc "Interface status changed";execute log display');	
   }
   case [@HPSwitch]
   {
     %Command=('uptime'=>'display version','interfacestatus'=>"display interface $InterfaceName",'interfacerr'=>"display interface $InterfaceName | I error",'interfacelog'=>'display logbuffer reverse');	
   }
   case [@JunOS]
   {
     #%Command=('uptime'=>'show system uptime','interfacestatus'=>"show interfaces $InterfaceName",'interfacerr'=>"show interfaces $InterfaceName",'interfacelog'=>'show log messages');
	%Command=('uptime'=>'show system uptime','interfacestatus'=>"show interfaces $InterfaceName",'interfacerr'=>"show interfaces $InterfaceName extensive | match error",'interfacelog'=>"show interfaces $InterfaceName | match flap");
   }
   case [@JunNetScreen]
   {
     %Command=('uptime'=>'get system','interfacestatus'=>"get interfaces $InterfaceName",'interfacerr'=>"get counter statistics interface $InterfaceName",'interfacelog'=>'get log tr ?');
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

####################################################################################
####### Get the current interface status #####################################################

#print $LogFileH GetDate." [LOG INFO]: Proceeding to check the interface status for the device $Hostname.\n";

if($Command{'interfacestatus'} ne "")
 {
    my $CommandSet=$Command{'interfacestatus'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH);
   
	# foreach (keys %OutputSet){
	# print "$_ -> $OutputSet{$_}\n";
	# }
   
   if(GetInterfaceStatus(%OutputSet)==0)
	 {
	   print $LogFileH GetDate." [LOG INFO]: Interface is currently down.\n";
	 }
   else
	 {
	   print $LogFileH GetDate." [LOG INFO]: Interface is currently up.\n";
	 }
 }
else
 {
	print $LogFileH GetDate." [LOG ERROR]: Failed to get the Interface Status command.\n";
	print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	print $LogFileH GetDate." [STATUS ]: Failure \n";
	close $LogFileH;
	exit 1;
 }
 

####################################################################################
####### Get the uptime details #####################################################

sleep(5);

if($Command{'uptime'} ne "")
  {
    my $CommandSet=$Command{'uptime'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH);
   
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
####### Get the Interface details #####################################################

sleep(5);

%OutputSet=();

#print $LogFileH GetDate." [LOG INFO]: Proceeding to check the interface logs for the device $Hostname.\n";

if($Command{'interfacelog'} ne "")
  {
     my $CommandSet=$Command{'interfacelog'};
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH);
   
    if(GetInterfaceLogs(%OutputSet)==0)
	  {
	    print $LogFileH GetDate." [LOG INFO ]: Interface might be flapping. \n";
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
    print $LogFileH GetDate." [LOG ERROR]: Failed to get the Interface log command.\n";
    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
    print $LogFileH GetDate." [STATUS ]: Failure \n";
    close $LogFileH;
    exit 1;
 }

########################################################################################
####### Get the Interface errors #####################################################

sleep(5);

%OutputSet=();

#print $LogFileH GetDate." [LOG INFO]: Proceeding to check the interface errors for the device $Hostname.\n";


if($Command{'interfacerr'} ne "")
  {
    my $CommandSet=$Command{'interfacerr'};
     
    %OutputSet=GetRemoteData(deviceip=>$DeviceIP,username=>$Username,password=>$EncrPass,command=>$CommandSet,fileptr=>$LogFileH); 
   
   if(GetInterfaceError(%OutputSet)==0)
	 {
		print $LogFileH GetDate." [LOG INFO ]: Interface log contains errors. \n";
		print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
		print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
		print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
		print $LogFileH GetDate." [STATUS ]: Failure \n";
		close $LogFileH;
		exit 1;				
	 }
   else
	 {
		print $LogFileH GetDate." [LOG INFO]: Interface log does not have any errors.\n";
	 }
  }
else
  {
    print $LogFileH GetDate." [LOG ERROR]: Failed to get the Interface error log command.\n";
    print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
    print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
    print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
    print $LogFileH GetDate." [STATUS ]: Failure \n";
    close $LogFileH;
    exit 1;
 }
		


if(PingDevice($DeviceIP)==1)
  {
	 print $LogFileH GetDate." [LOG INFO]: Ping successful to the Device $DeviceIP.\n";
	 print $LogFileH GetDate." [LOG ERROR]: ******************************************* \n";
	 print $LogFileH GetDate." [LOG ERROR]: Next Steps: \n";
	 print $LogFileH GetDate." [LOG ERROR]: Manual intervention needed.\n";
	 print $LogFileH GetDate." [STATUS ]: Failure \n";
	 close $LogFileH;
	 exit 1;
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
	    	   
close $LogFileH;
