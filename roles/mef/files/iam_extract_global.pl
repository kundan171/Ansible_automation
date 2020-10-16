#!/usr/bin/perl
#=========================================================================
# (C) Copyright 2006 IBM Corporation
#=========================================================================
# Script Name    : iam_extract.pl
# Script Purpose : extract iam data
# Parameters     : $1 IAM customer name (optional)
#                  $2 password file (optional)
#                  $3 group file (optional)
#                  $4 Output file name (optional)
#                  $5 Hostname (optional)
# Output         : file in IAM .mef format
# Dependencies   : Perl
#-------------------------------------------------------------------------------
# Version Date         # Author              Description
#-------------------------------------------------------------------------------
# V3.0.0  2006-04-28   # Matthew Waterfield  Ported from ksh and to .mef v2
# V3.1.0  2006-06-22   # Matthew Waterfield  Fix open issue on old perls
# V4.0.0  2006-10-18   # Matthew Waterfield  Enhance to get state
# V4.1.0  2006-10-25   # Matthew Waterfield  Add output file checks
# V4.2.0  2006-11-06   # Matthew Waterfield  Change to GetOptions and tidy
# V4.2.1  2006-11-06   # Matthew Waterfield  Check priv groups against URT list
# V5.0.0  2007-05-23   # iwong  Added parsing of gecos for IBM SSSSSS CCC, added 3-digit CC to 2-digit
#         Added parsing of sudoers, and sudoer group processing
#         Added --sudoers flag
#         update ouput to include:
#         usergecos = CC/I/SSSSSS//gecos - process gecos and pulls Serial and Country Code
#         usergroup =  list of groups which give this ID SUDO priviledges
#         userprivgroup = SUDO if found in sudoerReport, else blank
# V5.1.0  2007-07-18   # iwong  Updated code to default status=C, serial="", and  cc=US, if not IBM
#             Setup default customer, and added new customer flag
#                   Updated code adding hostname to default mef file name
# V5.1.1  2007-08-02   # iwong  Updated code to read URT format CCC/I/SSSSSS//gecos
# V5.1.2  2007-08-28   # iwong  Updated code to fix problem with -meffile flag
# V5.1.3  2007-09-13   # iwong  Updated code to warn if no sudoers files found
# V5.2.0  2007-09-26   # iwong  Updated code to generated scm formated output file
# V5.2.2  2007-11-07   # iwong  Updated code read in cust and comment fomr URT format CCC/I/SSSSSS/cust/comment
#                      #        Updated default user status state to enabled(0), if state unknown
# V5.2.3  2007-11-28   # iwong  Updated warning messages to indicated which files are missing
#          #        Updated code to indicate if SUDO priv is granted by a group(SUDO-GRP) or user(SUDO-USR)
#          #        Moved OS default file stanza to after arg assignments
# V5.2.4  2007-11-29   # iwong  Updated code output .scm9 format, which includes auditDATE
#                      #        Fixed problem accounts disabled with account_locked in SECUSER
# V5.2.5  2007-12-05   # iwong  Updated code to check for HP-UX systems(TCB and non-TCB)
# V5.2.6  2007-12-11   # leduc  If comments contain IBM flag = I
# V5.2.7  2008-01-25   # iwong  Updated code changing SUDO-USR to SUDO and SUDO-GRP to list of sudo groups
# V5.2.8  2008-02-21   # iwong  Updated code output .mef format
# V5.2.9  2008-02-21   # iwong  getprpw command to properly report HP disabled users
# V5.2.10 2008-02-21   # iwong  Bypass disabled check for * in passwd field in passwd file on hpux TCB systems
#             Updated output file name, if customer different from default IBM
#             added debug flag
# V5.2.11 2008-02-21   # iwong  Created new parsespw_hpux subroutine to check getprpw or shadow file
# V6.0    2008-04-11   # iwong  Added -scm flag, to output scm9 format, changed meffile flag to outfile
#             Output OS type in scm formated files
#             Recognize OSR privileged user and groups per OS type
#             Updated groups and privileges fields include OSR ans SUDO privs
#             Add script integrity cksum check
#             Uniquify group and SUDO group lists
#             Remove 3-digit CC conversion
#             Added -privfile flag to read in additional priv groups from a file
#             Updated code output .mef3 format
# V6.1    2008-04-18   # iwong  Updated code group field output to list all groups a user is a member
#             Commented out cksum check
# V6.2    2008-04-18   # iwong  Removed description matching for URT/CIO/IBM formats
# V6.3    2008-04-23   # iwong  Fixed problem with primary groups, not shown for ids not in any groups
#             Add wheel to Linux default priv group list
#             Fixed problem with reading in additional priv group
# V6.4    2008-05-01   # iwong  Added code to skip Defaults in sudoers file
#               Added code to fix problem with lines with spaces/tabs after \ in sudoers file
#               Added additional debug statement for sudoers processing
#               Added additional processing of ALL keyword in sudoers
# V6.5    2008-05-13   # iwong  Commented out cksum code
# V6.6    2008-05-15   # iwong  Added -mef flag, to output mef2 format
# V6.7    2008-06-03   # iwong  Added code to process groups in the User_Alias
# V6.8    2008-06-11   # iwong  Added code ignore netgroup ids +@user, any id starting with +
# V6.9    2008-06-20   # iwong  Added code adding dummy record to end of output file with date and versioning information
# V6.10   2008-07-28   # iwong  Updated dummy record to include 000 cc
# V7.0    2008-10-09   # iwong  Added code to process/recognize Host_Aliases in sudoers file
#                               Added code to process/recognize User_Aliases only if they are used
#                               Added code to list Linux groups with gid < 99 as privileged
#                               Updated code for processing primary groups
# V7.1    2008-01-09   # iwong  Added code to get sudo version
#                               Updated signature record to include FN= amd SUDO =
#                               Update Version removing date
# V7.2    2008-01-09   # iwong  Fixed problem with exiting sudoers processing on invalid group
# V7.3    2009-04-02   # M Ram  Added code to Ignore SUDOALL if "ALL=!SUDUSUDO" rule found
#               Updated code to recognize FQDN in sudoers hostlist
#               Added code to make same output Perl & KSH
# V7.4    2009-04-15   # M Ram  Added code to print custom signature for dummy id
#               Added code to check SSH public key authentation status for users having password "*" in passwd file
# V7.5    2009-08-24   # M Ram  Added code to fetch IDs from NIS
#     2009-08-24   # M Ram  Added code to process Netuser and Netgroup IDs ( start with + )
#     2009-08-25   # M Ram  Added code to print user last logon date for AIX
#     2009-09-23   # M Ram  Fixed the problem with disabled id has password like *LK*{crypt} in solaris
#     2009-09-24   # M Ram  Updated code to process PRIV file in linux environment
#         2010-01-13   # Anatoly Bondyuk    Added code to get of the support of reception of the list of users (including services LDAP, NIS, NIS +) by help of system functions getent and lsuser (lsgroup)
#         2010-02-01   # Anatoly Bondyuk    Fixed the issue with the checking of the passwd file
#         2010-02-24   # Anatoly Bondyuk    Fixed the issue with the operator of matching of strings (eq, ne instead !=, ==) for checking on the SSH-status
#         2010-02-25   # Anatoly Bondyuk    Fixed the issue with storing of data in a hash on processing of group members
#         2010-03-03   # Anatoly Bondyuk    Added correction of transferred value of paths in functions of processing of users and groups
#         2010-03-05   # Anatoly Bondyuk    Added the cleaning of hashes after working of NIS-piece of the code
#         2010-03-09   # Anatoly Bondyuk    Added the fix for the checking SUDO-aliases by the hostname with the help of a long hostname
#         2010-03-09   # Anatoly Bondyuk    Added the fix for checking SUDO-privileges for NIS's accounts
#         2010-03-11   # Anatoly Bondyuk    Added the possibility to analyze the alternative SSHD file and the SUDO file on SunOS
# V7.6    2010-04-01   # Vladislav Tembekov Added code to fetch Ids from LDAP
#         2010-05-03   # Vladislav Tembekov Added new option (--fqdn) to support FQDN format in MEF file
# V7.6.2  2010-05-21   # Vladislav Tembekov Fixed code to Ignore SUDOALL if "ALL=!somewhat" rule found
#         2010-05-26   # Vladislav Tembekov Added more default paths for search sudoers file
# V7.6.3  2010-06-15   # Vladislav Tembekov Fixed the issue with --hostname option.
#         2010-06-16   # Vladislav Tembekov Fixed the issue with --passwd and --group options. Added --noautoldap option
# V7.6.4  2010-07-05   # Vladislav Tembekov Added NIS+ support
# V7.6.5  2010-08-04   # Vladislav Tembekov Fixed host name bug. Changed logging. Fixed some minor bugs.
# V7.6.6  2010-09-07   # Vladislav Tembekov Changed checksum algorithm. Updated processing LDAP userids.
# V7.6.7  2010-09-15   # Vladislav Tembekov Fixed possible issue with user state
# V7.6.8  2010-10-15   # Vladislav Tembekov Changed default output file directory.
# V7.6.9  2010-12-02   # Vladislav Tembekov Additional check of privileged groups was added
# V7.7    2010-12-14   # Vladislav Tembekov Added code to process include and includedir directives in sudoers file
# V7.7.1  2011-01-04   # Vladislav Tembekov Change level of some messages from error to warning
# V7.7.2  2011-01-19   # Vladislav Tembekov Change processing command line arguments, fixed issue on HPUNIX with hostname length limitation
# V7.7.3  2011-01-25   # Vladislav Tembekov Added --customerOnly and --ibmOnly options, fixed issue with fetching groups from LDAP in autoldap mode
# V7.7.4  2011-01-28   # Vladislav Tembekov Added code to print user last logon date for Linux, Solaris
# V7.7.5  2011-02-02   # Vladislav Tembekov Added code to filter LDAP users on AIX
# V7.7.6  2011-02-15   # Vladislav Tembekov Changed trim function
# V7.7.7  2011-02-21   # Vladislav Tembekov Fixed hostname issue
# V7.7.8  2011-02-24   # Vladislav Tembekov Fixed cycling call in ProcessUserAlias and add_name functions
# V7.7.9  2011-03-03   # Vladislav Tembekov Added --owner flag to change output file permission, remove "|" in gecos filed
# V7.8    2011-03-10   # Vladislav Tembekov Added code to filter LDAP users by host attribute in case of PAM authentication,fixed HP Unix OS name
# V7.8.1  2011-03-16   # Vladislav Tembekov Fixed issue with last logon date on SanOS
# V7.8.2  2011-03-29   # Vladislav Tembekov Added --dlld flag to disable print last logon date 
# V7.8.3  2011-04-04   # Vladislav Tembekov Added check for LDAP IDs in passwd file
# V7.8.4  2011-04-06   # Vladislav Tembekov Added code to print IDs SUDO-aliases
# V7.8.5  2011-04-20   # Vladislav Tembekov Improved AIX LDAP filter
# V7.8.6  2011-05-19   # Vladislav Tembekov Changed code to get FQDN
# V7.8.7  2011-06-03   # Vladislav Tembekov Improved LDAP groups processing
# V7.8.8  2011-06-07   # Vladislav Tembekov Changed code to get sudo version
# V7.8.9  2011-06-14   # Vladislav Tembekov Added code to Ignore SUDOALL if "ALL=NOEXEC" rule found
# V7.9    2011-06-17   # Vladislav Tembekov Added code to set CMD_ENV=xpg4 if TRU64 is found
# V7.9.1  2011-08-03   # Vladislav Tembekov Added code to parsing local groups while processing LDAP/NIS IDs
# V7.9.2  2011-08-16   # Vladislav Tembekov Additional check of privileged ID was added
# V7.9.3  2011-08-30   # Vladislav Tembekov Improved LDAP ID processing
# V7.9.4  2011-09-05   # Vladislav Tembekov Improved debug logging functionality
# V7.9.5  2011-09-14   # Vladislav Tembekov Changed regexp for correct macthing IBM SSSSSS CCC GECOS record format 
# V7.9.6  2011-09-21   # Vladislav Tembekov Fixed issue in getfqdn function
# V7.9.7  2011-09-23   # Vladislav Tembekov Added --dev switch, only for developer 
# V7.9.8  2011-10-18   # Vladislav Tembekov Fixed issue when hostname command returns fqdn
# V7.9.9  2011-10-19   # Vladislav Tembekov Improved code to check SSH public key authentation status for locked users 
# V8      2011-11-16   # Vladislav Tembekov Fixed directory name issue while parsing #includedir sudoers directive
# V8.1    2011-11-22   # Vladislav Tembekov Added additional LDAP users checking on AIX
# V8.1.1  2011-11-30   # Vladislav Tembekov Added GSA functionality, --nogsa switch
# V8.1.2  2012-01-05   # Vladislav Tembekov Added check authorized_keys2 file
# V8.1.3  2012-01-16   # Vladislav Tembekov Added using idsldapsearch cmd on AIX if ldapserach cmd is not available
# V8.1.4  2012-01-16   # Vladislav Tembekov Disable ID on HPUX when shadow file doesn't exist and password field contains "*"
# V8.1.5  2012-01-25   # Vladislav Tembekov Disable printing SUDO_userid and SUDO_ALIAS(ALIANAME) in the same time
# V8.1.6  2012-02-02   # Vladislav Tembekov Added check hostalias if ALL rule found 
# V8.1.7  2012-02-09   # Vladislav Tembekov Rename script from urt_ to iam_
# V8.1.8  2012-04-13   # Vladislav Tembekov Fixed extraction GSA users from sudoers file issue
# V8.1.9  2012-04-13   # Vladislav Tembekov Fixed incorrect priv group assignment
# V8.2    2012-05-17   # Vladislav Tembekov Fixed incorrect SUDO privilege assignment
# V8.2.1  2012-07-24   # Vladislav Tembekov Added labeling LDAP IDS in autoldap mode
# V8.2.2  2012-08-30   # Vladislav Tembekov Added check user state on tru64
# V8.2.3  2012-09-18   # Vladislav Tembekov Added --ldapf switch
# V8.2.4  2012-09-28   # Vladislav Tembekov Added check belonging user to a group 
# V8.2.5  2012-09-28   # Vladislav Tembekov Added filter of NIS users
# V8.2.6  2012-11-16   # Vladislav Tembekov Improved check user state on AIX
# V8.2.7  2012-11-16   # Vladislav Tembekov Fixed parsing sudoers include directive
# V8.2.8  2013-02-01   # Vladislav Tembekov Improved GSA identification
# V8.2.9  2013-02-12   # Vladislav Tembekov Added processing wildcards in host_alias name of sudoers files
# V8.3.0  2013-03-01   # Vladislav Tembekov Added new pattern for account_locked values "yes" and "always"
# V8.3.1  2013-03-13   # Vladislav Tembekov Changed checking existence of ldapsearch on AIX
# V8.3.2  2013-03-28   # Vladislav Tembekov Fixed incorrect SUDO privilege issue 
# V8.3.3  2013-05-15   # Vladislav Tembekov Changed regexp to determine if user is an IBM user, fixed printing user ID as privileged if GID < 100 on Linux
# V8.3.4  2013-05-28   # Vladislav Tembekov Extended list of privileged users and groups
# V8.3.5  2013-06-05   # Vladislav Tembekov Fixed issue with "ALL" hostname in sudoers file
# V8.3.6  2013-07-15   # Vladislav Tembekov Added trim #includedir directive of sudoers file 
# V8.3.7  2013-07-18   # Vladislav Tembekov Additional check of ssh
# V8.3.8  2013-08-21   # Vladislav Tembekov Fixed incorrect argument assignment of --nis switch  
# V8.3.9  2013-11-04   # Vladislav Tembekov Improved GSA identification
# V8.4.0  2013-11-05   # Vladislav Tembekov mef4 support implemented
# V8.4.1  2013-11-18   # Vladislav Tembekov Added Vintela support
# V8.4.2  2013-11-27   # Vladislav Tembekov Changed privilege user check for RedHat and Debian
# V8.4.3  2014-02-18   # Vladislav Tembekov Rewrite code to check user state on AIX
# V8.4.4  2014-04-04   # Vladislav Tembekov Added Vintela check user state
# V8.4.5  2014-04-09   # Vladislav Tembekov Fixed compare hostnames while parsing sudoers file issue 
# V8.4.6  2014-05-03   # Vladislav Tembekov Improved Vintela check user state
# V8.4.7  2014-05-15   # Vladislav Tembekov Fixed incorrect assignment LDAP user prefix
# V8.4.8  2014-05-26   # Vladislav Tembekov Centrify support implemented
# V8.4.9  2014-06-26   # Vladislav Tembekov Added processing local users in vintela mode
# V8.5.0  2014-08-04   # Vladislav Tembekov Added timezone info in output file
# V8.5.1  2014-09-04   # Christopher Short  Added regex statements to remove the prefix that are returned during the vastool user 
#                      #                    and group lists from the ABC environment. Changed "vastool list users" command to "vastool list users-allowed"
#                      #                    so the list of users fetched from AD contain only the users relevant to the host the script is executed on.
#                      #                    also added sed statement to strip out prefix when the tmp sudoers file is created
# V8.5.2  2014-09-10   # Vladislav Tembekov Added Centrify user state checking
# V8.5.3  2014-09-29   # Vladislav Tembekov Improved GSA groups extraction form sudo file
# V8.5.4  2014-11-13   # Vladislav Tembekov Fixed incorrect variable name
# V8.5.5  2014-11-17   # Vladislav Tembekov Added possibility to change user filter in LDAP query 
# V8.5.6  2014-11-25   # Vladislav Tembekov Added code to avoid replace gecos fileld when description field has data
# V8.5.7  2014-12-10   # Vladislav Tembekov Changed regexp to check existence of user password on AIX
# V8.5.8  2015-01-12   # Vladislav Tembekov Update UNIX Extractors to report sudo privilege *access* using "user token(s)" from command allocation stanza.
# V9.0.1  2015-01-26   # Vladislav Tembekov Update version for all OS scripts. Realign numbering of perl, korn shell and bash scripts.
# V9.0.2  2015-02-23   # Vladislav Tembekov Changed vastool cmdline to list all groups from AD
# V9.0.3  2015-02-26   # Vladislav Tembekov Changed regexp to check GSA config
# V9.0.5  2015-03-06   # Vladislav Tembekov Fixed timezone issue on HP
# V9.0.6  2015-04-09   # Vladislav Tembekov Added path to ldapsearch command to LDAPPARAM file
# V9.0.7  2015-04-09   # Vladislav Tembekov Remove Case sensitivity compare LDAP host attribute
# V9.0.8  2015-06-04   # Vladislav Tembekov Fixed issue reporting user state on AIX
# V9.0.9  2015-07-02   # Vladislav Tembekov Added --signature switch for custom signature
# V9.1.0  2015-08-06   # Vladislav Tembekov Hide LDAP password
# V9.1.1  2015-08-12   # Vladislav Tembekov Add error code to the signature record of MEF3/MEF4
# V9.1.2  2015-08-13   # Vladislav Tembekov Added duplicate userid and group check
# V9.1.3  2015-08-21   # Vladislav Tembekov Fixed issue in istheredir function
# V9.1.4  2015-09-24   # Vladislav Tembekov Optimized LDAP connection check
#==========================================================================================================================

# Modules
use File::Basename;
use Cwd qw(abs_path);
use POSIX qw(strftime);
use IO::File;
use Time::Local;

# Version
$VERSION='V9.1.4';

$ErrCnt=0;

#===============================================================================
# logging 
#===============================================================================
use constant INFO  => 0;
use constant DEBUG => 1;
use constant WARN  => 2;
use constant ERROR => 3;

use constant YES   => "yes";
use constant NO    => "no";

use constant EXTRACTOR_NAME => "IAM Global";

use constant EXEC_OK    => 0;
use constant EXEC_WARN  => 1;
use constant EXEC_ERR   => 2;
use constant EXEC_ABORT => 9;

use constant SEC_PER_DAY=> 86400;

my @msgType =("INFO", "DEBUG", "WARN", "ERROR");
my $STARTTIME = `date +%Y-%m-%d-%H.%M.%S`;
my $knowpar;
my $unknowpar;
my $CKSUM="";
my $OSNAME="";

sub chksum
{
  my $oldEnv="";
  if ( $OSNAME =~ /tru64/i || $OSNAME =~ /OSF1/i)
  {
    $oldEnv = $ENV{'CMD_ENV'};
    $ENV{'CMD_ENV'}='xpg4';
  }
    
  open (CS, "cksum $0|");
  while (<CS>)
  {
    chomp();
    $CKSUM = $_;  
  }
  if ( $CKSUM =~ m/^[0-9]+/ )
  {
    $CKSUM = $&
  } 
  
  if ($OSNAME =~ /tru64/i || $OSNAME =~ /OSF1/i)
  {
    $ENV{'CMD_ENV'}=$oldEnv;
  }
}

sub logMsg
{
  my $level=shift;
  my @msg=@_;
  if(INFO <= $level && $level <= ERROR)
  {
    print "[$msgType[$level]] ";
    print @msg;
    print "\n";
  }
  else
  {
    print "Wrong message level\n";
  }
  
  if( $level == WARN )
  {
    $EXIT_CODE = EXEC_WARN;
  }
}

sub logDebug
{
  if($DEBUG)
  {
    logMsg(DEBUG,@_);
  }
}

sub logInfo
{
  logMsg(INFO,@_);
}

sub logDiv
{
  logMsg(INFO, "===========================================");
}

sub logMsgVerNotSupp
{
  logMsg(ERROR, "The found version of the Sub System is not supported by the given script.");
}

sub logMsgToolNotFound
{
  logMsg(ERROR, "The following file has not been found: @_");
}

sub logAbort
{
    logMsg(ERROR,@_);
    $EXIT_CODE=EXEC_ABORT;
    logFooter();
    exit $EXIT_CODE;
}

sub logKnownArg
{
  my $optname = shift;
  my $optval =  shift;
  
  $knowpar=$knowpar."$optname $optval# ";
}

sub logUnknownArg
{
  my $optname = shift;
  if(defined $unknowpar)
  {
    $unknowpar=$unknowpar.", ";
  }
  $unknowpar=$unknowpar."$optname";
}

sub logHeader
{
  chksum;
  chomp($STARTTIME);  
  
  logMsg(INFO,"UID EXTRACTOR EXECUTION - Started");
  
  logMsg(INFO,"START TIME: $STARTTIME");
  logDiv;
  logMsg(INFO,EXTRACTOR_NAME," Extractor");
  logDiv;
}

sub logPostHeader
{
  if(defined ($knowpar))
  {
    logMsg(INFO,"Following parameters will be processed: $knowpar");
  }
  if(defined ($unknowpar))
  {
    logMsg(WARN,"Following unknown parameters will not be processed: $unknowpar");
  }
  logDiv;

  logMsg(INFO,"SCRIPT NAME: $0");
  logMsg(INFO,"SCRIPT VERSION: $VERSION");
  logMsg(INFO,"CKSUM(unix): $CKSUM");
  logMsg(INFO,"PERL VERSION(unix,pl): $]");
  logMsg(INFO,"OS CAPTION: $OSNAME");
  my $OSVER=`uname -v`;
  my $SUBVER=`uname -r`;
  chomp($OSVER);
  chomp($SUBVER);
  if($OSNAME =~/AIX/)
  {
    logMsg(INFO,"OS VERSION: $OSVER.$SUBVER");
  }
  else
  {
    logMsg(INFO,"OS VERSION: $SUBVER");
  }
  logMsg(INFO,"HOSTNAME: $HOSTNAME");
  logMsg(INFO,"CUSTOMER: $URTCUST");
  logMsg(INFO,"OUTPUTFILE: $OUTFILE");
  my $SIG="";
  if($SIG_TSCM)
  {
    $SIG="TSCM";
  }
  
  if($SIG_SCR)
  {
    $SIG="SCR";
  }
  
  if($SIG_TCM)
  {
    $SIG="TCM";
  }
  
  if($SIG_FUS)
  {
    $SIG="FUS";
  }

  logMsg(INFO,"SIGNATURE: $SIG");
  logMsg(INFO,"IS_AG: no");
  logMsg(INFO,"IS_ALLUSERIDS: YES");
  logMsg(INFO,"IS_FQDN: ", $FQDN==0 ? NO : YES);
  logMsg(INFO,"IS_DEBUG: ",$DEBUG==0 ? NO : YES);
  logDiv;
  logMsg(INFO,"EXTRACTION PROCESS - Started");
  if($DEBUG)
  {
    logDiv();
  }
}

sub logFooter
{
  if($DEBUG)
  {
    logDiv();
  }
  logMsg(INFO,"EXTRACTION PROCESS - Finished");
  logDiv;
  my $diff = time() - $^T;
  logMsg(INFO,"Time elapsed: $diff second", $diff > 1 ? "s" : "" );
  logDiv;
  logMsg(INFO,"The report has been finished with",$EXIT_CODE > EXEC_WARN ? "out" : ""," success"); 
  logMsg(INFO,"General return code: ", $EXIT_CODE);
  logMsg(INFO,"UID EXTRACTOR EXECUTION - Finished");
  if($EXIT_CODE > EXEC_WARN)
  {
    `rm -f $OUTFILE`
  }
}

sub removeIt
{
  print("-------------------------Debug code, remove it-----------------------------------\n"); 
}

sub glob2pat
{
 my $globstr = shift;
 my %patmap = (
    '*' => '.*',
    '?' => '.',
    '[' => '[',
    ']' => ']',
    );
 $globstr =~ s{(.)} { $patmap{$1} || "\Q$1" }ge;
 return '^' . $globstr . '$';
}

#args MM DD YY
sub formatDate
{
  my $MM=shift;
  my $DD=shift;
  my $YY=shift;
  my %mnames = ('01','Jan', '02','Feb', '03','Mar', '04','Apr',
                '05','May', '06','Jun', '07','Jul', '08','Aug', '09','Sep',
                '10','Oct', '11','Nov', '12', 'Dec');
  my $MMM=$mnames{$MM};
  
  return "$DD $MMM 20$YY";
}

sub CleanHashes
{
  # cleaning of hashes
  while(($key, $value) = each %user_privuser){
    delete($user_privuser{$key});
  };

  while(($key, $value) = each %user_gid){
    delete($user_gid{$key});
  };

  while(($key, $value) = each %user_uid){
    delete($user_uid{$key});
  };

  while(($key, $value) = each %user_gecos){
    delete($user_gecos{$key});
  };

  while(($key, $value) = each %user_state){
    delete($user_state{$key});
  };

  while(($key, $value) = each %scm_user_state){
    delete($scm_user_state{$key});
  };

  while(($key, $value) = each %gmembers){
    delete($gmembers{$key});
  };

  while(($key, $value) = each %primaryGroupUsers){
    delete($primaryGroupUsers{$key});
  };

  while(($key, $value) = each %group){
    delete($group{$key});
  };

  while(($key, $value) = each %ggid){
    delete($ggid{$key});
  };

  while(($key, $value) = each %user_allgroups){
    delete($user_allgroups{$key});
  };

  while(($key, $value) = each %user_privgroups){
    delete($user_privgroups{$key});
  };
  
  while(($key, $value) = each %user_home){
    delete($user_home{$key});
  };
  
  while(($key, $value) = each %AliasList){
    delete($AliasList{$key});
  };

  while(($key, $value) = each %UserAliasList){
    delete($UserAliasList{$key});
  };

  while(($key, $value) = each %AliasOfAlias){
    delete($AliasOfAlias{$key});
  };

  while(($key, $value) = each %User_List){
    delete($User_List{$key});
  };

  while(($key, $value) = each %UserAlias){
    delete($UserAlias{$key});
  };
}
#===============================================================================
# Main process flow
#===============================================================================
$EXIT_CODE=EXEC_OK;
$OSNAME=`uname`;
chomp($OSNAME);
logHeader();
&init();
&openout();
logPostHeader();

$ADMENTPASSWD = "/tmp/adment_passwd";
$ADMENTGROUP = "/tmp/adment_group";
$ADMENTSPASSWD = "/tmp/adment_spasswd";

$PROCESSLDAP=0;
$PROCESSNIS=0;

$GSACONF="/usr/gsa/etc/gsa.conf";
$LDAPCONF="/etc/ldap.conf";

if($DEV == 1)
{
  $GSACONF="cfg/gsa.conf";
  $LDAPCONF="cfg/ldap.conf";
}

&get_group_info;
&get_passwd_ids;

if($NOGSA == 0 && &checkGSAconfig() == 1)
{
  if($OSNAME =~ /aix/i || $OSNAME =~ /solaris/i || $OSNAME =~ /sunos/i)
  {
    $LDAPCMD = "/usr/gsa/bin/ldapsearch";
  }
  else
  {
    $LDAPCMD = "/usr/bin/ldapsearch -x";
  }
  
  $NOAUTOLDAP=1;
  $LDAPPASSWD="/tmp/ldappasswd";
  $LDAPGROUP="/tmp/ldapgroup";

  &collectGSAusers();
  $PROCESSLDAP=1;
  $LDAP=1;  
  &parsepw();
  &parsegp();
  
  if($OSNAME !~ /aix/i)
  {
    $LDAP=0;
    $PROCESSLDAP=0;
    &parsegp();
    $LDAP=1;
    $PROCESSLDAP=1;
  }

  &parsegp();
  &parsesudoers();
  &report();
  
  $LDAP=0;  
  
  `rm -f $LDAPPASSWD`;
  `rm -f $LDAPGROUP` ;

  CleanHashes();

  $NIS=0;
  $LDAP=0;
}

if ($NIS)
{
  $IS_NISPLUS = &check_nisplus();
  if($DEBUG)
  {
    if($IS_NISPLUS)
    {
      logInfo("Processing NIS+");
    }
    else
    {
      logInfo("Processing NIS");
    }
  }
  
  $PROCESSNIS = 1;
  if ($IS_NISPLUS)
  {
    $NISPASSWD = "niscat passwd.org_dir$NISPLUSDIR |";
    $NISGROUP = "niscat group.org_dir |";
  }
  else
  {
    $NISPASSWD = "ypcat passwd |";
    $NISGROUP = "ypcat group |";
  }
  
  &parsepw();
  &parsegp();
  
  $NIS=0;
  $PROCESSNIS=0;
  &parsegp();
  $NIS=1;
  $PROCESSNIS=1;
  
  &parsesudoers(); # for NIS's accounts we must extract all data from SUDO-settings
  &report();

  CleanHashes();
}

$PROCESSNIS = 0;
if ($LDAP == 1 && $IS_ADMIN_ENT_ACC == 1)
{
  if(&checkforldappasswd())
  {  
  $PROCESSLDAP=1;
  $LDAPPASSWD="/tmp/ldappasswd";
  $LDAPGROUP="/tmp/ldapgroup";
  
  logInfo("Processing LDAP");
  
  collect_LDAP_users_aix();  
  &process_LDAP_users();
  &parsepw();
  get_ldgrp();
  &parsegp();

  if($OSNAME !~ /aix/i)
  {
    $LDAP=0;
    $PROCESSLDAP=0;
    &parsegp();
    $LDAP=1;
    $PROCESSLDAP=1;
  }
  &parsesudoers();
  &report();
  `rm -f $LDAPPASSWD`;
  `rm -f $LDAPGROUP` ;
  
  CleanHashes();  
}
}
$PROCESSLDAP=0;

logInfo("Processing local IDs");

&parsepw();
&parsegp();
&parsesudoers();
if ($OSNAME =~ /aix/i)
{
  logDebug("running as aix");
  &parsespw_aix();
}
elsif ($OSNAME =~ /hpux/i || $OSNAME =~ /hp-ux/i)
{
  logDebug("running as hpux");
  &parsespw_hpux();
}
else
{
  &parsespw($OSNAME);
}
&get_vintela_state();
&get_centrify_state();

logInfo("Reporting...");
&report();
&printsig();
logFooter();
CleanHashes();
#===============================================================================
# Subs
#===============================================================================
sub help
{
print "Options Help:\n";
print "Version: $VERSION\n";
print "Optional overrides:\n";
print "--customer <customer name>\n";
print "--passwd   <passwd_file>\n";
print "--shadow   <shadow_passwd_file>\n";
print "--group    <group_file>\n";
print "--secuser  <aix_security_user_file>\n";
print "--hostname <hostname>\n";
print "--os       <operating_system_name>\n";
print "--outfile  <output_file>\n";
print "--sudoers  <sudoers_file>\n";
print "--scm\n";
print "--mef\n";
print "--privfile  <additional _priv_group_file>\n";
print "--tscm\n";
print "--scr\n";
print "--tsm\n";
print "--fus\n";
print "--ldap  <LDAP SERVER Name/IP:port:BASE_DN>\n";
print "--ldapf <filename>\n";
print "--nis <directory>\n";
print "--vintela <regexp>\n";
print "--fqdn\n";
print "--noautoldap\n";
print "--customerOnly\n";
print "--ibmOnly\n";
print "--owner <owner IDs>\n";
print "--dlld\n";
print "--nogsa\n";
print "\n";
print "Options Notes:\n";
print "--passwd, --shadow, --group, --secuser, --sudoers\n";
print "Use these options for running the extract\n";
print "against files copied from one system\n";
print "to another.\n";
print "You might do this if perl is not available\n";
print "on the target system. Or for testing.\n";
print "\n";
print "--customer\n";
print "Specify the customer name\n";
print "\n";
print "--hostname\n";
print "Specify the hostname to appear in the outfile.\n";
print "This is useful when system is known\n";
print "by a name different to the system hostname.\n";
print "Or when extract is run on a different\n";
print "system e.g. when files have been copied.\n";
print "\n";
print "--os\n";
print "Use when extract is run on a system with\n";
print "a different operating system to the input\n";
print "files.(aix|hpux|sunos|linux|tru64)\n";
print "e.g. --os aix\n";
print "\n";
print "--outfile\n";
print "The default outfile is /tmp/<iam_customer_name>_<date>_<hostname>.mef3\n";
print "You can change the path/name if required.\n";
print "\n";
print "--scm\n";
print "Change output file format to scm9, instead of mef3\n";
print "\n";
print "--mef\n";
print "Change output file format to mef2, instead of mef3\n";
print "\n";
print "--mef4\n";
print "Change output file format to mef4, instead of mef3\n";
print "\n";
print "--privfile\n";
print "Additional Privilege Group file(One group per line in file)\n";
print "\n";
print "--tscm\n";
print "Uses the TSCM signature\n";
print "\n";
print "--scr\n";
print "Uses the SCR signature\n";
print "\n";
print "--tsm\n";
print "Uses the TSM signature\n";
print "\n";
print "--fus\n";
print "Uses the FUS signature\n";
print "\n";
print "--ldap\n";
print "To fetch the User IDs from LDAP Server\n";
print "\n";
print "--ldapf\n";
print "To fetch the User IDs from LDAP Server\n";
print "\n";
print "--nis\n";
print "To fetch the User IDs from NIS Server\n";
print "\n";
print "--vintela\n";
print "To fetch the User IDs from LDAP Server using Vintela\n";
print "\n";
print "--centrify\n";
print "To fetch the User IDs from LDAP Server using Centrify\n";
print "\n";
print "--fqdn\n";
print "FQDN format will be used in the MEF output\n";
print "\n";
print "--noautoldap\n";
print "To fetch only local User IDs when server is LDAP connected (Linux and Solaris)\n";
print "--customerOnly\n";
print "Flag to indicate if only Customer userID's should be written to the output\n";
print "--ibmOnly\n";
print "Flag to indicate if only IBM userID's should be written to the output\n";
print "--owner\n";
print "Flag to set the owner of the output file\n";
print "--dlld\n";
print "Disable last logon date\n";
print "--nogsa\n";
print "Disable GSA check\n";
print "\n";
print "General Notes:\n";
print " Output is mef3 or scm9 or mef2 format including privilege data.\n";
print " List of privileged groups is hardcoded in the script\n";
print "(easy to change if required by person running the script)\n";
print " User 'state' (enabled/disabled) is extracted if possible.\n";
print " Only tested on perl v5.\n";
exit 9;
}

sub init()
{
  if ( -e "/bin/sudo" ){
    $SUDOCMD="/bin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  elsif ( -e "/usr/bin/sudo" ){
    $SUDOCMD="/usr/bin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  elsif ( -e "/usr/local/bin/sudo" ){
    $SUDOCMD="/usr/local/bin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  elsif ( -e "/usr/local/sbin/sudo" ){
    $SUDOCMD="/usr/local/sbin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  else{
    $SUDOVER="NotAvailable";
    logMsg(WARN, "unable to get Sudo Version:$SUDOVER.");
  }

  $DEV=0;
  
  # System details
  chomp($HOST=`hostname`);
  $LONG_HOST_NAME=lc $HOST;
  ($HOST,@_)= split(/\./,$HOST);
  $HOSTNAME=lc $HOST;
  if(scalar(@_) == 0)
  {
    $LONG_HOST_NAME=&getfqdn($HOST);
  }
  chomp($DATE=`date +%d%b%Y`);
  $DATE=uc($DATE);
  $DEBUG=0;
  $SCMFORMAT=0;
  $MEF2FORMAT=0;
  $MEF4FORMAT=0;

  #auditdate is the date of the last scm collector run corresponding to this
  #hostname in the format yyyy-mm-dd-hh.mm.ss (2006-04-02-00.00.00)..
  #yyyy-mm-dd-hh.mm.ss
  chomp($myAUDITDATE=`date +%Y-%m-%d-%H.%M.%S`);

  $uname=`uname`;
  chomp($uname);

  # Default file locations which dont depend on OS
  $URTCUST="IBM";
  $PASSWD="/etc/passwd";
  $GROUP="/etc/group";
  $SUDOERS="";
  $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOST.mef3";
  $NEWOUTFILE = "";
  $PRIVFILE = "";
  $SSHD_CONFIG="/etc/ssh/sshd_config";
  $LDAP=0;
  $NIS=0;
  $FQDN=0;
  $ENABLEFQDN=1;
  $tmpfile="/tmp/iamtemp";
  $NOAUTOLDAP=0;
  $USERCC="897";
  $ibmonly=0;
  $customeronly=0;
  $OWNER="";
  $LDAPARG="";
  $DLLD=0;
  $NOGSA=0;
  $LDAPFILE="";
  $LDAPBASEGROUP="";
  $LDAPGROUPOBJCLASS="";
  $LDAPADDITIONAL="";
  $NISPLUSDIR="";
  $USERSPASSWD=0;
  $USEROSNAME=0;
  $VPREFIX="";
  $SIGNATURE="";
  $IS_ADMIN_ENT_ACC=0;
  
  findSudoersFile();
  
  while(@ARGV)
  {
    my $opt=shift @ARGV;
    if($opt eq "--customer") {$URTCUST=shift @ARGV; logKnownArg($opt, $URTCUST); next;}
    if($opt eq "--passwd") {$PASSWD=shift @ARGV;$NOAUTOLDAP=1; logKnownArg($opt, $PASSWD); next;}
    if($opt eq "--shadow") {$SPASSWD=shift @ARGV; $USERSPASSWD=1; logKnownArg($opt, $SPASSWD); next;}
    if($opt eq "--group")  {$GROUP=shift @ARGV;$NOAUTOLDAP=1;logKnownArg($opt, $GROUP); next;}
    if($opt eq "--sudoers"){$SUDOERS=shift @ARGV;logKnownArg($opt, $SUDOERS); next;}
    if($opt eq "--secuser"){$SUSER=shift @ARGV; logKnownArg($opt, $SUSER); next;}
    if($opt eq "--hostname")
    {
      $HOSTNAME=$LONG_HOST_NAME=lc shift @ARGV;
      logKnownArg($opt, $HOSTNAME);
      $ENABLEFQDN=0;
      ($HOST,@_)= split(/\./,$LONG_HOST_NAME);
      next;
    }
    if($opt eq "--os"){$OSNAME=shift @ARGV;$USEROSNAME=1;logKnownArg($opt, $OSNAME);next;}
    if($opt eq "--debug"){logKnownArg($opt);$DEBUG=1; next;}
    if($opt eq "--scm"){logKnownArg($opt);$SCMFORMAT=1; next;}
    if($opt eq "--mef"){logKnownArg($opt);$MEF2FORMAT=1; next;}
    if($opt eq "--mef4"){logKnownArg($opt);$MEF4FORMAT=1; next;}
    if($opt eq "--privfile"){$PRIVFILE=shift @ARGV; logKnownArg($opt, $PRIVFILE);next;}
    if($opt eq "--outfile"){$NEWOUTFILE=shift @ARGV; logKnownArg($opt, $NEWOUTFILE); next;}
    if($opt eq "--tscm"){logKnownArg($opt);$SIG_TSCM=1; next;}
    if($opt eq "--scr"){logKnownArg($opt);$SIG_SCR=1; next;}
    if($opt eq "--tcm"){logKnownArg($opt);$SIG_TCM=1; next;}
    if($opt eq "--fus"){logKnownArg($opt);$SIG_FUS=1; next;}
    if($opt eq "--signature"){$SIGNATURE=shift @ARGV; logKnownArg($opt, $SIGNATURE);next;}
    if($opt eq "--nis")
    {
      $NISPLUSDIR=shift @ARGV;
      $NISPLUSDIR=trim($NISPLUSDIR);
      if($NISPLUSDIR =~ /^--/ || $NISPLUSDIR eq "")
      {
        unshift @ARGV, $NISPLUSDIR;
        $NISPLUSDIR="";
        logKnownArg($opt);
      }
      else
      {
        logKnownArg($opt, $NISPLUSDIR);
        $NISPLUSDIR=".$NISPLUSDIR";
      }
      $NIS=1;
      $NOAUTOLDAP=1;
      next;
    }
    if($opt eq "--ldap")
    {
      $LDAP=1;
      $NOAUTOLDAP=1;
      $LDAPARG=shift @ARGV;
      my $KARG=$LDAPARG;
      $KARG=~ s/-w\s+\S+(\s|$)/-w \*\*\*\*\*\*\*\* /;
      logKnownArg($opt, $KARG);
      next;
    }
    if($opt eq "--ldapf"){$LDAP=1;$NOAUTOLDAP=1;$LDAPFILE=shift @ARGV; logKnownArg($opt, $LDAPFILE);next;}
    if($opt eq "--fqdn"){logKnownArg($opt);$FQDN=1; next;} 
    if($opt eq "--noautoldap"){logKnownArg($opt);$NOAUTOLDAP=1; next;}
    if($opt eq "--ibmOnly"){logKnownArg($opt);$ibmonly=1; next;}
    if($opt eq "--customerOnly"){logKnownArg($opt);$customeronly=1; next;}
    if($opt eq "--owner"){$OWNER=shift @ARGV; logKnownArg($opt, $OWNER);next;}
    if($opt eq "--dlld"){logKnownArg($opt);$DLLD=1; next;}# disable last logon date
    if($opt eq "--help"){ help(); next;}
    if($opt eq "--nogsa"){ logKnownArg($opt); $NOGSA=1; next;}
    if($opt eq "--dev"){ $DEV=1; next;}
    if($opt eq "--vintela")
    {
      $IS_ADMIN_ENT_ACC=2;
      $VPREFIX=shift @ARGV;
      $VPREFIX=trim($VPREFIX);
      if($VPREFIX =~ /^--/ || $VPREFIX eq "")
      {
        unshift @ARGV, $VPREFIX;
        $VPREFIX="";
        logKnownArg($opt);
      }
      else
      {
        logKnownArg($opt, $VPREFIX);
        $VPREFIX=$VPREFIX.'[\\92\\|\\92\\92]';
      }
      next;
    }
    if($opt eq "--centrify")
    {
       logKnownArg($opt); $IS_ADMIN_ENT_ACC=3; next;
    }
    
    logUnknownArg($opt);
  }
  
  &is_adminent_accessible();
  
  $DISTRNAME=&getdistrname();
    
  if($IS_ADMIN_ENT_ACC == 3)
  {
    logInfo("Flush the Centrify and nscd cache");
    `/usr/sbin/adflush >/dev/null 2>&1`;
    logInfo("Flush completed, exit code $?"); 
  }
    
  if($DEV == 1)
  {
    logInfo("Developer mode");
  }
    
  if ($FQDN == 1 && $ENABLEFQDN == 1) {
    $HOSTNAME=$LONG_HOST_NAME;
  }
  
  logDebug("init: host $HOST:$LONG_HOST_NAME");
  
  if($LDAP == 1)
  {
    $LDAPCMD="";
    if ( $LDAPARG =~ /\S+:\d+:\S+/ )
    {
      ($LDAPSVR ,$LDAPPORT,$LDAPBASE )  = split(/\:/,$LDAPARG);
    }
    elsif($LDAPFILE ne "" )
    {
        $LDAPSVR=&getFromThere($LDAPFILE,"^LDAPSVR:\\s*(.*)\$");
        $LDAPBASE=&getFromThere($LDAPFILE,"^LDAPBASEPASSWD:\\s*(.*)\$");
        $LDAPBASEGROUP=&getFromThere($LDAPFILE,"^LDAPBASEGROUP:\\s*(.*)\$");
        $LDAPPORT=&getFromThere($LDAPFILE,"^LDAPPORT:\\s*(.*)\$");
        $LDAPGROUPOBJCLASS=&getFromThere($LDAPFILE,"^LDAPGROUPOBJCLASS:\\s*(.*)\$");
        $LDAPADDITIONAL=&getFromThere($LDAPFILE,"^LDAPADDITIONAL:\\s*(.*)\$");
        $LDAPUSERFILTER=&getFromThere($LDAPFILE,"^LDAPUSERFILTER:\\s*(.*)\$");
        $LDAPCMDTMP=&getFromThere($LDAPFILE,"^LDAPCMD:\\s*(.*)\$");
        
        if($LDAPCMDTMP ne "")
        {
          $LDAPCMD=$LDAPCMDTMP;
        }
        
        if($LDAPUSERFILTER eq "")
        {
          $LDAPUSERFILTER="uid=*";
        }

        if($LDAPSVR eq "" || $LDAPBASE eq "" || $LDAPPORT eq "" || $LDAPGROUPOBJCLASS eq "" || $LDAPBASEGROUP eq "")
        {
          logAbort("Invalid $LDAPFILE, exiting");
        }
    }
    else
    {
      logAbort("Invalid LDAPSVR, LDAPPORT and LDAP BASE");
    }
  }
  
  if( $LDAPCMD eq "")
  {
    if($OSNAME =~ /aix/i || $OSNAME =~ /solaris/i || $OSNAME =~ /sunos/i)
    {
      $LDAPCMD = "ldapsearch";
      if($OSNAME =~ /aix/i)
      {
        $attr=`$LDAPCMD 2>/dev/null`;
        if ( $? == 127 )
        {
          $LDAPCMD = "idsldapsearch";
        }
      }
    }
    else
    {
      $LDAPCMD = "ldapsearch -x";
    }
  }
  
  if($DEV == 1)
  {
    $LDAPCMD = "./ldapsearch";
    $SUSER="cfg/user";
  }
  
  # File locations which depend on OS
  for ($OSNAME)
  {
    if (/aix/i)
    {
      logDebug("Found AIX");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/security/passwd";
      $SUSER = $SUSER ? $SUSER : "/etc/security/user";
      # Define priv groups - this is an extended regex ie pipe separated list of things to match
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^lpd$|^imnadm$|^ipsec$|^ldap$|^lp$|^snapp$|^invscout$|^nobody$|^notes$';
      $PRIVGROUPS='^system$|^security$|^bin$|^sys$|^adm$|^uucp$|^mail$|^printq$|^cron$|^audit$|^shutdown$|^ecs$|^imnadm$|^ipsec$|^ldap$|^lp$|^haemrm$|^snapp$|^hacmp$|^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^SSHD$|^sshd$';
    }
    elsif (/hpux/i || /hp-ux/i)
    {
      logDebug("Found HPUX");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^lp$|^nuucp$|^hpdb$|^imnadm$|^nobody$|^notes$';
      $PRIVGROUPS='^root$|^other$|^bin$|^sys$|^adm$|^daemon$|^mail$|^lp$|^tty$|^nuucp$|^nogroup$|^imnadm$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^notes$|^SSHD$|^sshd$';
    }
    elsif (/sunos/i || /solaris/i)
    {
      logDebug("Found SunOS");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";

      if (-e "/usr/local/etc/sshd_config"){
        $SSHD_CONFIG = "/usr/local/etc/sshd_config";
      }

      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^imnadm$|^lp$|^smmsp$|^listen$|^nobody$|^notes$|^lpd$|^ipsec$|^snapp$|^invscout$';
      $PRIVGROUPS='^system$|^security$|^bin$|^sys$|^uucp$|^mail$|^imnadm$|^lp$|^root$|^other$|^adm$|^tty$|^nuucp$|^daemon$|^sysadmin$|^smmsp$|^nobody$|^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^SSHD$|^sshd$|^printq$|^cron$|^audit$|^ecs$|^shutdown$|^ipsec$|^ldap$|^haemrm$|^snapp$|^hacmp$';
    }
    elsif (/linux/i)
    {
      logDebug("Found Linux");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^nobody$|^notes$';
      $PRIVGROUPS='^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^wheel$|^SSHD$|^sshd$';
    }
    elsif (/tru64/i || /OSF1/i)
    {
      logDebug("Found TRU64");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
      $PRIVUSERS='^adm$|^auth$|^bin$|^cron$|^daemon$|^inmadm$|^lp$|^nuucp$|^ris$|^root$|^sys$|^tcb$|^uucp$|^uucpa$|^wnn$|^audit$|^hpdb$|^invscout$|^ipsec$|^ldap$|^listen$|^lpd$|^nobody$|^notes$|^snapp$|^smmsp$';
      $PRIVGROUPS='^adm$|^auth$|^backup$|^bin$|^cron$|^daemon$|^inmadm$|^kmem$|^lp$|^lpr$|^mail$|^mem$|^news$|^operator$|^opr$|^ris$|^sec$|^sysadmin$|^system$|^tape$|^tcb$|^terminal$|^tty$|^users$|^uucp$|^1bmadmin$|^dba$|^db2admin$|^db2iadm1$|^ecs$|^hacmp$|^haemrm$|^ibmadmin$|^ipsec$|^ldap$|^mqm$|^nogroup$|^nuucp$|^nobody$|^notes$|^other$|^printq$|^root$|^sapsys$|^security$|^SSHD$|^sshd$|^shutdown$|^smmsp$|^snapp$|^sudo$|^suroot$|^sys$|^sysad$|^wheel$';
    }
    else
    {
      logDebug("Found Unknown OS");
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^lpd$|^imnadm$|^ipsec$|^ldap$|^lp$|^snapp$|^invscout$|^nobody$|^notes$|^hpdb$|^smmsp$|^listen$';
      $PRIVGROUPS='^1bmadmin$|^adm$|^audit$|^bin$|^cron$|^daemon$|^db2admin$|^db2iadm1$|^dba$|^ecs$|^hacmp$|^haemrm$|^ibmadmin$|^imnadm$|^ipsec$|^ldap$|^lp$|^mail$|^mqm$|^nobody$|^nogroup$|^notes$|^nuucp$|^other$|^printq$|^root$|^sapsys$|^security$|^shutdown$|^smmsp$|^snapp$|^suroot$|^sys$|^sysadm$|^system$|^tty$|^uucp$|^wheel$|^SSHD$|^sshd$|^sudo$|^sysad$|^sysadmin$';
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
    }
  } # end for
  logDebug("PRIVUSERS: $PRIVUSERS");
  logDebug("PRIVGROUPS: $PRIVGROUPS");

  if($PRIVFILE ne "")
  {
    logDebug("Reading PRIVFILE: $PRIVFILE");
    open(PRIVFILE, $PRIVFILE) || logAbort("Can't open PRIVFILE: $PRIVFILE : $!");
    while($line=<PRIVFILE>)
    {
      chomp $line;
      $readgroup="";
      ($readgroup)=$line=~/^\s*(\S+)\s*$/;
      if($readgroup ne "")
      {
        $PRIVGROUPS.="|^".$readgroup."\$";
        logDebug("Adding privgroup: $readgroup\n");
      }
      else
      {
        logDebug("Skipping privgroup: $line");
      }
    }
    logDebug("Additional PRIVGROUPS: $PRIVGROUPS");
  }

  ## check to see if given a specfic outfile name
  if ($NEWOUTFILE eq "")
  {
    # update default outfile if scm
    if ($SCMFORMAT)
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.scm9";
    }
    elsif ($MEF2FORMAT)
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.mef";
    }
    elsif ($MEF4FORMAT)
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.mef4";
    }
    else
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.mef3";
    }
  }
  else
  {
    if($NEWOUTFILE =~ /\//)
    {
      $OUTFILE = $NEWOUTFILE;
    }
    else
    {
      $OUTFILE = "/tmp/"."$NEWOUTFILE";
    }
  }
  
  if($DEV == 1)
  {
    $OUTFILE = "./perl.mef3";
  }
  
  if($SUDOERS eq "/dev/null")
  {
    logMsg(WARN,"unable to find sudoers file.  Account SUDO privileges will be missing from extract");
  }
} # end init sub

sub findSudoersFile
{
  $SUDOERS="/dev/null";
  my $SUDOERS1="/etc/sudoers";
  my $SUDOERS2="/opt/sfw/etc/sudoers";
  my $SUDOERS3="/usr/local/etc/sudoers";
  my $SUDOERS4="/opt/sudo/etc/sudoers";
  my $SUDOERS5="/opt/sudo/etc/sudoers/sudoers";
  my $SUDOERS6="/usr/local/etc/sudoers/sudoers";
  my $SUDOERS7="/opt/sudo/sudoers";

  if(-r $SUDOERS1)
  {
    $SUDOERS=$SUDOERS1
  }
  else
  {
    if(-r $SUDOERS2)
    {
      $SUDOERS=$SUDOERS2;
    }
    else
    {
      if(-r $SUDOERS3)
      {
        $SUDOERS=$SUDOERS3;
      }
      else
      {
        if(-r $SUDOERS4)
        {
          $SUDOERS=$SUDOERS4;
        }
        else
        {
          if(-r $SUDOERS5)
          {
            $SUDOERS=$SUDOERS5;
          }
          else
          {
            if(-r $SUDOERS6)
            {
              $SUDOERS=$SUDOERS6;
            }
            else
            {
              if(-r $SUDOERS7)
              {
                $SUDOERS=$SUDOERS7;
              }
            }
          }
        }
      }
    }
  }
}

sub getdistrname
{
  if($USEROSNAME == 0)
  {
    if ( -e "/etc/debian_version" ||  -e " /etc/debian_release")
    {
      logDebug("getdistrname: Debian");
      return "Debian";
    }
  
    if ( -e "/etc/redhat-release" ||  -e "/etc/redhat_version")
    {
      logDebug("getdistrname: RedHat");
      return "RedHat";
    }
  }
  return "";
}


sub checkforldappasswd()
{
  $FPASSWD = $PASSWD;
  my $retFlag=1;
  open(PASSWD_FILE, $FPASSWD) || logAbort("Can't open $FPASSWD : $!");
  while ($Line = <PASSWD_FILE>)
  {
    if($Line =~ /^\+/)
    {
      $retFlag=0;
      last;
    }
  }
  close PASSWD_FILE;
  logDebug("checkforldappasswd: $retFlag");
  return  $retFlag;
}

sub get_passwd_ids
{
  $passwd_users="";
  open(PASSWD_FILE, $PASSWD) || logAbort("Can't open $PASSWD : $!");
  while (<PASSWD_FILE>)
  {
    chomp;
    ($username, $passwd, $uid, $gid, $gecos, $home, $shell) = split(/:/);
    if($username eq "")
    {
      logDebug("get_passwd_ids: Skip empty user name");      
      next;  
    }
    $username=trim($username);
    if($passwd_users eq "")
    {
      $passwd_users="^".$username."\$";
    }
    else
    {
      if($username =~ /$passwd_users/)
      {
        close PASSWD_FILE;
        logAbort("User \"$username\" already exists in $PASSWD file");
      }
      $passwd_users=$passwd_users."|^".trim($username)."\$";
    }    
    logDebug("get_passwd_ids: added user $username");
  }
  close PASSWD_FILE;
  logDebug("get_passwd_ids: end");
}

# groupname gid
sub is_priv_group
{
  my $ret=0;
  my $groupname = shift;
  my $gid = shift;
  
  if ($OSNAME=~/linux/i)
  {
    if ($gid < 100 || $groupname =~ /$PRIVGROUPS/ || ( $DISTRNAME ne "" && $gid > 100 && $gid < 200))
    {
      logDebug("Found priv group $groupname gid < 100 || gid > 100 && gid < 200: $gid");
      $ret=1;
    }
  }
  elsif ($groupname =~ /$PRIVGROUPS/)
  {
    logDebug("Found priv group $groupname");
    $ret=1;
  }
  return $ret; 
}

sub get_group_info
{
  $group_names="";
  open(GROUP_FILE, $GROUP) || logAbort("Can't open $GROUP : $!");
  while (<GROUP_FILE>)
  {
    chomp;
    ($groupname, $passwd, $gid, $userlist) = split(/:/);
    logDebug("get_group_info: check user user $groupname");
    
    $groupname=trim($groupname);
    if($group_names eq "")
    {
      $group_names="^".$groupname."\$";
    }
    else
    {
      if($groupname =~ /$group_names/)
      {
        close GROUP_FILE;
        logAbort("Group \"$groupname\" already exists in $GROUP file");
      }
      $group_names=$group_names."|^".$groupname."\$";
    }
    
    if(is_priv_group($groupname, $gid) == 1 )
    {
      $privgroups{$groupname}=1;      
    }
  }
  close GROUP_FILE;
  logDebug("get_group_info: end");
}

sub parse_user_info
{
    logDebug("parse_user_info:$username:$passwd:$uid:$gid:$gecos");
    
    if($username eq "" || $uid eq "" || $gid eq "")
    {
      logDebug("parse_user_info: wrong ID $username");
      return;
    }
    
    $user_home{$username}=$home;
        
    if (exists $primaryGroupUsers{$gid})
    {
      $primaryGroupUsers{$gid} = $primaryGroupUsers{$gid} . "," . $username;
    }
    else
    {
      $primaryGroupUsers{$gid} = $username;
    } # end if

    if ($username =~ /$PRIVUSERS/ )
    {
      logDebug("parse_user_info: privuser found: id = $username");
      $user_privuser{$username} = $username;
    }
    $user_uid{$username} = $uid;
    $user_gid{$username} = $gid;
    $user_gecos{$username} = $gecos;
    chomp $shell;

    # check for user disabled by * in password field
    # Bypass if this is an TCB HPUX system
    if ($HPUX_TCB_READABLE == 0)
    {
      if ( $passwd =~ /^\*/ )
      {
        if ( -e $SPASSWD )
        {
          if ( $PUBKEYAUTH eq "yes" ) {                 # 7.4 Code to check SSH public key authentation status for users having password "*" in passwd file
            logDebug("Checking for public key file $home/$AUTHORIZEDKEYSFILE for user: $username");
            if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ))
            {
              $user_state{$username} = "SSH-Enabled";
              logDebug("SSH key file is found:$username");
            }
            else
            {
              $user_state{$username} = "Disabled";
              $scm_user_state{$username} = "1";
            }
          }
          else
          {
            $user_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            logDebug("$username Disabled: passwd=$passwd in passwd file");
          }
        }
        else
        {
          if($OSNAME =~ /hpux/i || $OSNAME =~ /hp-ux/i || PROCESSNIS)
          {
            $user_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            logDebug("$username Disabled: passwd=$passwd in passwd file");
          }
        }
      }
    }
    else
    {
      logDebug("$username Bypassing check for user disabled by * in password field");
    }
    
    if( (! defined($user_state{$username})) || $user_state{$username} ne "SSH-Enabled")
    {
      if ( $shell =~ /\/bin\/false/ )
      {
        $user_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("$username Disabled: shell=$shell in passwd file");
      }
      if ( $shell =~ /\/usr\/bin\/false/ )
      {
        $user_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("$username Disabled: shell=$shell in passwd file");
      }
    }

    ## add users to group memberlist  array if user is no listed in its primary group
    %gmemlist=();
    if ( ! defined $gmembers{$gid} )
    {
      $gmembers{$gid} = $username;
      logDebug("$username member of $gid");
    }
    else
    {
      # add user only user not in current list
      foreach $nlist (split(/\,/,$gmembers{$gid}))
      {
        $gmemlist{$nlist}=$nlist;
      }
      if(exists $gmemlist{$username})
      {
        ## already in list
      }
      else
      {
        $gmembers{$gid} = $gmembers{$gid}.",$username";
        logDebug("Adding $username to gid:$gid user list $gmembers{$gid}");
      }
    }
}

sub parsepw()
{
  $AUTHORIZEDKEYSFILE="";
  $AUTHORIZEDKEYSFILE2="";
  $PUBKEYAUTH="";
  # check to see if this is a TCB HPUX system
  # if getprpw is found, we assume this is a TCB machine
  $HPUX_TCB_READABLE=0;
  if($OSNAME =~ /hpux/i || $OSNAME =~ /hp-ux/i)
  {
    # check to see if command is executable
    if(-x "/usr/lbin/getprpw" && -d "/tcb" )
    {
      $HPUX_TCB_READABLE=1;
    }
  }
  logDebug("HPUX_TCB_READABLE: $HPUX_TCB_READABLE");

  # 7.4 Code to check SSH public key authentation status for users having password "*" in passwd file
  open(SSH_FILE, $SSHD_CONFIG) || logMsg(WARN,"Cannot open $SSHD_CONFIG file");
  while ($Line = <SSH_FILE>)
  {
    if ($Line =~ /^AuthorizedKeysFile\s*(\S+)\s$/)
    {
      $AUTHORIZEDKEYSFILE = $1;
      logDebug("parsepw:SSH Authkey file is $AUTHORIZEDKEYSFILE");
    }
    
    if ($Line =~ /^AuthorizedKeysFile2\s*(\S+)\s$/)
    {
      $AUTHORIZEDKEYSFILE2 = $1;
      logDebug("parsepw:SSH Authkey file is $AUTHORIZEDKEYSFILE2");
    }
    
    if ($Line =~ /^PubkeyAuthentication\s*(\w+)\s$/)
    {
      $PUBKEYAUTH = $1;
      logDebug("parsepw:SSH publickey authentication enabled is $PUBKEYAUTH");
    }
  }
  close(SSH_FILE);

  if ($AUTHORIZEDKEYSFILE eq "")
  {
    $AUTHORIZEDKEYSFILE=".ssh/authorized_keys";
  }

  if ($AUTHORIZEDKEYSFILE2 eq "")
  {
    $AUTHORIZEDKEYSFILE2=".ssh/authorized_keys2";
  }

  if ($PROCESSNIS)                  # V 4.5
  {
    $FPASSWD = $NISPASSWD;
  }

  if ($PROCESSLDAP)                 
  {
    $FPASSWD = $LDAPPASSWD;
  }
  
  if($PROCESSNIS ==0 && $PROCESSLDAP == 0)
  {
    $FPASSWD = $PASSWD;
  }

  if ( $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
  {
    if ($IS_ADMIN_ENT_ACC == 1 &&( $OSNAME =~ /linux/i || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i ))
    {
      `getent passwd > $ADMENTPASSWD`;
      $FPASSWD = $ADMENTPASSWD;
    }
    if ($IS_ADMIN_ENT_ACC == 2)
    {
      if( $VPREFIX eq "" )
      {
        `/opt/quest/bin/vastool list users-allowed > $ADMENTPASSWD`;
      }
      else
      {
        `/opt/quest/bin/vastool list users-allowed | sed \'s/$VPREFIX//g\' > $ADMENTPASSWD`;
      }
      logDebug("parsepw: vastool exitcode $?");
      `cat $PASSWD >> $ADMENTPASSWD`;
      $FPASSWD = $ADMENTPASSWD;
    }
    if ($IS_ADMIN_ENT_ACC == 3)
    {
      `adquery user > $ADMENTPASSWD`;
      `cat $PASSWD >> $ADMENTPASSWD`;
      logDebug("parsepw:  Centrify exitcode $?");
      $FPASSWD = $ADMENTPASSWD;
    }
  }

  logDebug("Processing $FPASSWD for users");
  open(PASSWD_FILE, $FPASSWD) || logAbort("Can't open $FPASSWD : $!");
  while (<PASSWD_FILE>)
  {
    $done_spasswd = 1;
    chomp;
    # parse passwd file
    ($username, $passwd, $uid, $gid, $gecos, $home, $shell) = split(/:/);
    logDebug("parsepw: read $username:$passwd:$uid:$gid:$gecos:$home:$shell");
    # store bits of user details in hashes
    # comment any we dont need to save memory !
    #$user_passwd{$username} = $passwd;
    #$user_uid{$username} = $uid;
    # only save priv groups
    
    if($username eq "")
    {
      logDebug("parsepw:Skip empty user name");      
      next;  
    }

    if($PROCESSNIS == 1 && $IS_NISPLUS == 1)
    {
      `groups $username >/dev/null 2>&1`;
      if( $? != 0 )
      {
        logDebug("parsepw:Skip NIS+ user");
        next;
      }
    }
    
    if($username =~ /^\+/)                                #V4.5
    {
      if ($LDAP == 0) {
        logInfo("User $username is excluded from output file, use --ldap option to lookup Netuser/Netgrp IDs");
        next;
      }
      if ($username =~ /^\+\@/) {
        logInfo("parsepw:Processing netgrp ID $username");
        Parse_LDAP_Netgrp($username);
        next;
      }
      ($username)= $username =~ /^\+(\S+)/;
      logInfo("parsepw:Processing netuser IDS $username");
      if(exists $user_gid{$username})
      {
        logDebug("parsepw:User $username already exist");
        next;
      }
      else
      {
        Parse_LDAP_Netusr($username);
      }
    }
    parse_user_info();

} # end while
close PASSWD_FILE;
`rm -f $ADMENTPASSWD`;
if ( $done_spasswd == 1 )
{
  $state_available = 1;
}

} # end sub parse

sub get_vintela_state()
{
  if( $IS_ADMIN_ENT_ACC == 2 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 )
  {
  logDebug("get_vintela_state: start");
  while ( (my $username, my $usergid) = each %user_gid)
  {
    if($username =~ /$passwd_users/)#skip local user
    {
      logDebug("get_vintela_state: $username is a local user, skipped");
      next;
    }
    my $attr=`/opt/quest/bin/vastool -u host/ attrs $username userAccountControl`;
    ($attr)=$attr =~ /(\d+)/;
    logDebug("get_vintela_state: LDAP user $username, attr is $attr");
    my $tmp=$attr & 2;
      if( $tmp == 0 )
    {
      $user_state{$username} = "Enabled";
      logDebug("get_vintela_state: $username is Enabled");
    }
    else 
    {
      $user_state{$username}="Disabled";
      logDebug("get_vintela_state: $username is Disabled");
    }  
  }  
  logDebug("get_vintela_state: end");    
 }
}

sub get_centrify_state()
{
  my $CENTRIFY_TMP="/tmp/centrify.tmp";
  
  if( $IS_ADMIN_ENT_ACC == 3 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 )
  {
    logDebug("get_centrify_state: start");
    my $attr=`adquery user --unixname --disabled  > $CENTRIFY_TMP`;
    
    open(CENTRIFY_FILE, $CENTRIFY_TMP) || logMsg(WARN,"Can't open $CENTRIFY_TMP : $!\nWARN:  Account state may be missing from extract");
    while (<CENTRIFY_FILE>)
    {
      ($username, $field1, $field2) = split(/:/);
      
      logDebug("get_centrify_state: read line - $username, $field1, $field2");
      
      if( $field1 =~ /unixname/ )
      {
        next;
      }
      
      if( $field2 =~ /false/ )
      {
        $user_state{$username} = "Enabled";
        if($OSNAME =~ /AIX/i) 
        {
          $AIX_passwd_state{$username} = "Enabled";
          $AIX_user_state{$username} = "Enabled";
        }
        logDebug("get_centrify_state: $username is Enabled");
      }
      else 
      {
        $user_state{$username}="Disabled";
        if($OSNAME =~ /AIX/i)
        {
          $AIX_passwd_state{$username} = "Disabled";
          $AIX_user_state{$username} = "Disabled";
        }
        logDebug("get_centrify_state: $username is Disabled");
      } 
    }  
    `rm -f CENTRIFY_TMP`;
    logDebug("get_centrify_state: end");    
 }
}

sub parsespw()
{
  my $FSPASSWD=$SPASSWD;
  
  if ( $IS_ADMIN_ENT_ACC == 1 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
  {
    if ($USERSPASSWD == 0 && ( $OSNAME =~ /linux/i ))
    {
      logDebug("parsespw: getent shadow");
      `getent shadow > $ADMENTSPASSWD`;
      $FSPASSWD = $ADMENTSPASSWD;
    }
  }

  open(SPASSWD_FILE, $FSPASSWD) || logMsg(WARN,"Can't open SPASSWD:$FSPASSWD : $!\nWARN:  Account state may be missing from extract");
  while (<SPASSWD_FILE>)
  {
    # set flag so we know what we've done
    $done_spasswd = 1;
    # parse shadow passwd file
    ($username, $crypt_passwd, $passwd_changed, $passwd_minage, $passwd_maxage, $passwd_war_period, $passwd_inactivity_period, $account_expiration, $reserved) = split(/:/);
    if($MEF4FORMAT)    
    {
      my $tmp;
      $PWNeverExpires_Arr{$username}="FALSE";
      if($passwd_changed eq "0")
      {
        $PWChg_Arr{$username}="01 Jan 1970";
      }
      else
      {
        if($passwd_changed eq "")
        {
          $PWNeverExpires_Arr{$username}="TRUE";
          $PWExp_Arr{$username}="31 Dec 9999";
        }
        else
        { 
          $PWChg_Arr{$username}=POSIX::strftime("%d %b %Y", localtime($passwd_changed * SEC_PER_DAY));
          if( $passwd_maxage ne "")
          {
            if($passwd_inactivity_period eq "" || $passwd_inactivity_period eq "99999")
            {
              $passwd_inactivity_period=0;
            }

            $tmp=$passwd_changed + $passwd_maxage + $passwd_inactivity_period;
            $tmp=POSIX::strftime("%d %b %Y", localtime($tmp * SEC_PER_DAY));
            $PWExp_Arr{$username}=$tmp;
          }
          else
          {
            $PWExp_Arr{$username}="";
          }
        }
      }
      $PWMinAge_Arr{$username}=$passwd_minage;
      $PWMaxAge_Arr{$username}=$passwd_maxage;
      if($passwd_maxage eq "99999" || $passwd_maxage eq "")
      {
        $PWNeverExpires_Arr{$username}="TRUE";
        $PWExp_Arr{$username}="31 Dec 9999";
      }
    }      
    
    # check for user disabled by NP, *LK*, !!, or * in password field
    if ( ($crypt_passwd eq "NP") or ($crypt_passwd =~ /\*LK\*/) or ($crypt_passwd =~ /^!/) or ($crypt_passwd =~ /^\*/))
    {
      $user_state{$username} = "Disabled";
      $scm_user_state{$username} = "1";
      logDebug("$username Disabled: crypt=$crypt_passwd in shadow");
    }
    if ( $crypt_passwd eq "LOCKED")
    {
      $user_state{$username} = "Disabled";
      $scm_user_state{$username} = "1";
      logDebug("$username Disabled: crypt=$crypt_passwd in shadow");
    }
    
    if (($user_state{$username} eq "Disabled") and ($PUBKEYAUTH eq "yes"))
    {
      logDebug("Checking for public key file $home/$AUTHORIZEDKEYSFILE for user: $username");
      $home=$user_home{$username};
      if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ))
      {
        $user_state{$username} = "SSH-Enabled";
        logDebug("SSH key file is found:$username");
      }
    }
    
    
  } # end while
  close SPASSWD_FILE;
  `rm -f $ADMENTSPASSWD`;

  # if we have processed the file set state_available flag
  if ( $done_spasswd == 1 )
  {
    $state_available = 1;
  }

} # end sub parse

sub hp_logins
{
  my $username = shift;
  
  logDebug("hp_logins:start");
  
  my ($F1,$F2,$F3,$F4,$F5,$F6,$F7,$F8,$F9,$F10,$F11,$F12,$F13,$F14) = split(/:/, `logins -axo -l $username`);
  
  if(($F11 eq "-1" && $F10 eq "-1") || $F9 eq "000000" || $F9 eq "")
  {
    $PWNeverExpires_Arr{$username}="TRUE";
  }
  else
  {
    $PWNeverExpires_Arr{$username}="FALSE";
  }
  
  if($F11 eq "-1")
  {
    $F11="99999";
  }

  if($F10 eq "-1")
  {
    $F10="0";
  }
  
  $PWMaxAge_Arr{$username}=$F11;
  $PWMinAge_Arr{$username}=$F10;
  
  if($F11 ne "99999" && $F9 ne "000000")
  {
    my $MM=substr("$F9",0,2);
    my $DD=substr("$F9",2,2);
    my $YY="1970";
    if($F9 ne "010170")
    {
      $YY=substr("$F9",4,2);
    }
    my $change=timelocal(0, 0, 0, $DD, $MM-1, $YY);
    $PWExp_Arr{$username}=POSIX::strftime("%d %b %Y", localtime($change+$F11*SEC_PER_DAY));
  }
  else
  {
    $PWExp_Arr{$username}="31 Dec 9999";
  }  
  
  if( $F9 eq "000000" || $F9 eq "" || $F9 eq "010170")
  {
    $F9="01 Jan 1970";
  }
  else
  {
    my $MM=substr("$F9",0,2);
    my $DD=substr("$F9",2,2);
    my $YY=substr("$F9",4,2);
    $F9=formatDate($MM, $DD, $YY);
  }
  $PWChg_Arr{$username}=$F9;
}

sub parsespw_hpux()
{
  # check to see if command is executable
  # if getprpw is found, we assume this is a TCB machine
    open(PASSWD_FILE, $PASSWD) || logAbort("Can't open $PASSWD : $!");
    while (<PASSWD_FILE>)
    {
      # set flag so we know what we've done
      $done_getprpw = 1;
      # parse passwd file
      ($username, $crypt_passwd, @rest) = split(/:/);
      
      logDebug("parsespw_hpux: username $username, crypt_passwd $crypt_passwd");
      if($MEF4FORMAT)      
      {
        hp_logins($username);
      }
      
      if(-x "/usr/lbin/getprpw" && -d "/tcb")
      {
        $getprpwdcmd="/usr/lbin/getprpw -m lockout $username|";
        #$getprpwdcmd="echo \"lockout=0010000\"|";
        open(GETPRPW, $getprpwdcmd) || logMsg(WARN, "Can't open $getprpwdcmd : $!\nAccount state may be missing from extract");
        $hpstatus=<GETPRPW>;
        chomp $hpstatus;
        # set flag so we know what we've done
        if($hpstatus =~ /1/)
        {
          $user_state{$username} = "Disabled";
          $scm_user_state{$username} = "1";
          logDebug("parsespw_hpux: $username Disabled hpstatus=$hpstatus returned from getprpw");
        }
        else
        {
          logDebug("parsespw_hpux: $username  hpstatus=$hpstatus");
        }
        close GETPRPW;
      }
      else
      {
        open (PP, "passwd -s $username 2>&1 |");
        while (<PP>)
        {
          logDebug("parsespw_hpux: $_"); 
          if( $_ =~ /LK/)
          {
            $user_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            last;
          }
        }  
        close PP;      
      }

      if(defined($user_state{$username}) && $user_state{$username} eq "Disabled")
      {
        if ( $PUBKEYAUTH eq "yes" )
        {
          $home=$user_home{$username};
          if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ) )
          {
            $user_state{$username} = "SSH-Enabled";
          }
        }
      } 
    }# end while
    close PASSWD_FILE;
    $state_available = 1;
} # end sub parse

sub store_aix_data
{
  if($username ne "")
  {
    my $maxage=$PWMaxAge_Arr{$username};
    my $maxexpired=$PWMaxExpired_Arr{$username};
    if( $maxage eq "0" || $maxexpired eq "-1")
    {
     $PWNeverExpires_Arr{$username}="TRUE";
     $PWExp_Arr{$username}="31 Dec 9999";
     $PWMaxAge_Arr{$username}="99999";
    }
    else
    {
      $PWNeverExpires_Arr{$username}="FALSE";
      my $LastUpdate=$PWLastUpdate{$username};
      if($LastUpdate ne "")
      {
        $PWExp_Arr{$username}=POSIX::strftime("%d %b %Y", localtime($LastUpdate + $maxage*SEC_PER_DAY + $maxexpired*7*SEC_PER_DAY));
      }
      else
      {
        $PWExp_Arr{$username}="01 Jan 1970";
      }
   }
 }    
}

sub parsespw_aix()
{
  my $tmp=0;
    
  # Now do user security/user file
  open(SUSER_FILE, $SUSER) || logMsg(WARN,"Can't open SECUSER:$SUSER : $!\nAccount state may be missing from extract");
  while (<SUSER_FILE>)
  {
    if(/^\*/)
    {
      next;
    }
    # set flag so we know what we've done
    $done_suser = 1;
    # parse security user file
    # Find the usernamne
    if (/(.+):/)
    {
      # $1 is the bit matched by (.+)
      $username = $1;
      logDebug("parsespw_aix: found user $username");
      if($MEF4FORMAT)
      {
        store_aix_data();
        if($username ne "default")
        {
          $PWMinAge_Arr{$username}=$PWMinAge_Arr{"default"};
          $PWMaxAge_Arr{$username}=$PWMaxAge_Arr{"default"};
          $PWExp_Arr{$username}=$PWExp_Arr{"default"};
          $PWMinLen_Arr{$username}=$PWMinLen_Arr{"default"};
          $PWNeverExpires_Arr{$username}=$PWNeverExpires_Arr{"default"};
          $PWMaxExpired_Arr{$username}=$PWMaxExpired_Arr{"default"};
        }
      } 
      next;
    }
    # Find the password
    if (/account_locked = (.+)/)
    {
      # $1 is the bit matched by (.+)
      # check for user disabled by true in account_locked field
      $account_locked = $1;
      if ($account_locked =~ /true|yes|always/i )
      {
        $AIX_user_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("parsespw_aix: $username Disabled: account_locked=$account_locked in security user");
      }
      else
      {
        $AIX_user_state{$username} = "Enabled";
        $scm_user_state{$username} = "1";
        logDebug("parsespw_aix: $username Enabled: account_locked=$account_locked in security user");
      }
      next;
    }

    if($MEF4FORMAT)    
    {
      if (/minage = (.+)/)
      {
        $tmp=$1*7;
        $PWMinAge_Arr{$username}=$tmp;
        next;
      }
      
      if (/maxage = (.+)/)
      {
        $tmp=$1*7;
        $PWMaxAge_Arr{$username}=$tmp;
        next;
      }
      
      if (/minlen = (.+)/)
      {
        $PWMinLen_Arr{$username}=$1;
        next;
      }
      
      if (/maxexpired = (.+)/)
      {
        $PWMaxExpired_Arr{$username}=$1;
        next;
      }
    }

  } # end while

  close SUSER_FILE;

  if($MEF4FORMAT)
  {
    store_aix_data();
  }
  
  $username="";
  # Do security/passwd file
  open(SPASSWD_FILE, $SPASSWD) || logMsg(WARN, "Can't open SPASSWD:$SPASSWD : $!\nAccount state may be missing from extract");
  while (<SPASSWD_FILE>)
  {
    # set flag so we know what we've done
    $done_spasswd = 1;
    # parse security passwd file
    # Find the usernane
    my $nextline = trim($_);
    if ( $nextline =~ /(.+):/)
    {
      # $1 is the bit matched by (.+)
      $username = $1;
      next;
    }
    # Find the password
    if ( $nextline =~ /password\s*=\s*(.+)/)
    {
      # $1 is the bit matched by (.+)
      # check for user disabled by * in password field
      $crypt_passwd = $1;
      if ($crypt_passwd =~ /^\*/ )
      {
        $AIX_passwd_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("$username Disabled: password=$crypt_passwd in security passwd");
      }
      else
      {
        $AIX_passwd_state{$username} = "Enabled";
        $scm_user_state{$username} = "0";
        logDebug("$username Enabled: password=$crypt_passwd in security passwd");
      }
    next;
  }

  if($MEF4FORMAT)    
  { 
    if ( $nextline =~ /lastupdate = (.+)/)
    { 
      $PWChg_Arr{$username}=POSIX::strftime("%d %b %Y", localtime($1));
      $PWLastUpdate{$username}=$1;
    }
   }
  }

  close SPASSWD_FILE;

  # if we have processed both files set state_available flag
  if ( $done_spasswd == 1 and $done_suser == 1 )
  {
    $state_available = 1;
  }
} # end sub parse

sub parsegp()
{
  if ($PROCESSNIS)                  # V 4.5
  {
    $FPASSWD = $NISPASSWD;
    $FGROUP = $NISGROUP;
  }

  if ($PROCESSLDAP)                 
  {
    $FPASSWD = $LDAPPASSWD;
    $FGROUP = $LDAPGROUP;
  }
  
  if($PROCESSNIS ==0 && $PROCESSLDAP == 0)  
  {
    $FPASSWD = $PASSWD;
    $FGROUP = $GROUP;
  }

  if ( $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
  {
    if ($IS_ADMIN_ENT_ACC == 1 && ( $OSNAME =~ /linux/i  || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i) )
    {
      logDebug("parsegp: getent");
      `getent passwd > $ADMENTPASSWD`;
      `getent group > $ADMENTGROUP`;

      $FPASSWD = $ADMENTPASSWD;
      $FGROUP  = $ADMENTGROUP;
    }
    
    if ($IS_ADMIN_ENT_ACC == 2 ) 
    {
      logDebug("parsegp: vastool");
      if( $VPREFIX eq "" )
      {
        `/opt/quest/bin/vastool list users-allowed > $ADMENTPASSWD`;
        `/opt/quest/bin/vastool list -a groups > $ADMENTGROUP`;
      }
      else
      {
        `/opt/quest/bin/vastool list users-allowed | sed \'s/$VPREFIX//g\' > $ADMENTPASSWD`;
        `/opt/quest/bin/vastool list -a groups | sed \'s/$VPREFIX//g\' > $ADMENTGROUP`;
      }
      `cat $GROUP >> $ADMENTGROUP`;
      $FPASSWD = $ADMENTPASSWD;
      $FGROUP  = $ADMENTGROUP;
    } 
    
    if ($IS_ADMIN_ENT_ACC == 3 ) 
    {
      logDebug("parsegp:  Centrify");
      `adquery user > $ADMENTPASSWD`;
      `adquery group > $ADMENTGROUP`;
      `cat $GROUP >> $ADMENTGROUP`;
      $FPASSWD = $ADMENTPASSWD;
      $FGROUP  = $ADMENTGROUP;
    } 
  }
  
  logDebug("Processing $FGROUP for privileges groups");
  open(GROUP_FILE, $FGROUP) || logAbort("Can't open $FGROUP : $!");
  while (<GROUP_FILE>)
  {
    # parse group file
    ($groupname, $passwd, $gid, $userlist) = split(/:/);
    chomp $userlist;
    chomp $groupname;
    logDebug("parsegp: read $groupname:$passwd:$gid:$userlist");    
    if($groupname eq "")
    {
      logDebug("Skip empty group name");      
      next;  
    }

    if($groupname =~ /^\+/)
    {
      logDebug("Skip group $groupname");
      next;
    }
    
    # store group-gid info in hash
    $group{$gid} = $groupname;
    $ggid{$groupname} = $gid;

    %gmemlist=();
    $allusers=$primaryGroupUsers{$gid}; 
    foreach $username (split(/\,/,$userlist))
    {
      if ( !defined $gmembers{$gid})
      {
        $gmembers{$gid} = $username;
      }
      else
      {
      # add user only user not in current list
      foreach $nlist (split(/\,/,$gmembers{$gid}))
      {
        $gmemlist{$nlist}=$nlist;
      }
      if($gmemlist{$username})
      {
        ## already in list
      }
      else
      {
        $gmembers{$gid} = $gmembers{$gid}.",$username";
      }
    }
  }

  #$gmembers{$gid} = $userlist;

  if($primaryGroupUsers{$gid})
  {
    if($userlist eq "")
    {
      $allusers=$primaryGroupUsers{$gid};
    }
    else
    {
      $allusers="$primaryGroupUsers{$gid},$userlist";
    }
  }
  else
  {
    $allusers="$userlist";
  }

    logDebug("parsegp: userlist: $userlist");
    logDebug("parsegp: allusers: $allusers");
    #uniquify the privgrouplist
    if($allusers ne "")
    {
      %hash=();
      @cases = split(/,/,$allusers);
      $allusers = "";
      %hash = map { $_ => 1 } @cases;
      $allusers = join(",", sort keys %hash);
    }
    logDebug("parsegp: UNIQUE allusers: $allusers");
    #uniquify the privgrouplist

    $FOUNDPG=is_priv_group($groupname, $gid);
  
    # store priv user groups info in hash
    foreach $username (split(/,/,$allusers))
    {
      if (exists $user_allgroups{$username})
      {
        my $is_founded_dublicate = 0;
        foreach my $usergroup (split(/,/,$user_allgroups{$username}))
        {
          if ($usergroup eq $groupname)
          {
            $is_founded_dublicate = 1;
          }
        }

        if (!$is_founded_dublicate)
        {
          $user_allgroups{$username} = $user_allgroups{$username} . "," . $groupname;
        }
      }
      else
      {
        $user_allgroups{$username} = $groupname;
      } # end if

    if ($FOUNDPG)
    # only save priv groups
    {
      logDebug("ADDING priv group $groupname, ID $username");
      if (exists $user_privgroups{$username})
      {
        my $is_founded_dublicate = 0;
        foreach my $userprivgroup (split(/,/,$user_privgroups{$username}))
        {
          if ($userprivgroup eq $groupname)
          {
            $is_founded_dublicate = 1;
          }
        }
        if (!$is_founded_dublicate)
        {
          $user_privgroups{$username} = $user_privgroups{$username} . "," . $groupname;
        }
      }
      else
      {
        $user_privgroups{$username} = $groupname;
      } # end if
    } # end if
  } # end foreach
} # end while
close GROUP_FILE;
`rm -f $ADMENTPASSWD`;
`rm -f $ADMENTGROUP`;
} # end sub parse

sub parsesudoers()
{
  my $tmp_sudo_file="/tmp/sudoersfile.tmp";
  `rm -f $tmp_sudo_file`;
  
  &preparsesudoers($SUDOERS, $tmp_sudo_file);
  
  $SUDOALL="2";
  open(SUDOERS_FILE, $tmp_sudo_file) || logMsg(WARN, "Can't open SUDOERS:$tmp_sudo_file : $!\nAccount SUDO privileges will be missing from extract");
  while ($nextline = <SUDOERS_FILE>)
  {
    chomp($nextline);
    logDebug("SUDOERS:read $nextline");
    chomp $nextline;
    ## concatenate line with next line if line ends with \
    if ( $nextline =~ /\\\s*$/ )
    {
      # process continuation line
      ($nline)=$nextline=~/(.*)\\\s*$/;
      chomp($nline);
      chop($nextline);
      $InputLine .= $nline;
      next;
    }
    $InputLine .= $nextline;

    ## trim out comment lines
    $cmt_ix = index( $InputLine, "#" );
    if ( $cmt_ix >= 0 )
    {
      $InputLine = substr( $InputLine, 0, $cmt_ix);
    }

    # split line into tokens (names and keywords)
    @Line = split /[,=\s]/, $InputLine;
    $ix = 0;

    # classify pieces of the input
    TOKEN: while ( $ix <= $#Line ) {
      if ( $Line[$ix] eq "" ) {  # ignore seperators
        $ix++;
        next TOKEN;
      }
      if ( $Line[$ix] eq "Cmnd_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Runas_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Defaults" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "ALL" ){     # v.7.3 ignore SUDOALL if ALL=!SUDOSUDO rule found *** start *****
        if ($InputLine =~ /!/ || $InputLine =~ /noexec/i ) {
          $SUDOALL="0";
          logInfo("Found ALL=!Cmnd_Alias :$InputLine");
        }
        else {
          if($SUDOALL eq "2") {
            if($InputLine =~ /ALL\s+(\S+)\s*=/)
            {
              if( defined $validHostAlias{$1} || $1 =~/ALL/)
              {
                logInfo("Found ALL :$InputLine");
                $SUDOALL="1";
              }
            }
            else
            {
              logInfo("Found ALL :$InputLine");
              $SUDOALL="1";
            }
          }
        }               # v.7.3 ignore SUDOALL if ALL=!SUDOSUDO rule found **** end *****
        last TOKEN;
      }

      if ( $Line[$ix] eq "Host_Alias" ){
        ($hostalias,$hostlist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $hostlist =~ s/\s//g;
        logDebug("SUDOERS: $InputLine");
        logDebug("SUDOERS: Found Host_Alias $hostalias");
        logDebug("SUDOERS: Found hostlist $hostlist");

        foreach $nextHost (split ',', $hostlist)
        {
          $nextHost=lc glob2pat($nextHost);
          if ( $HOST =~ /$nextHost/i || $LONG_HOST_NAME =~ /$nextHost/i || "ALL" =~ /$nextHost/i)
          {
            $validHostAlias{$hostalias}=$hostalias;
            logDebug("SUDOERS: Found VALID Host_Alias $hostalias");
          }
        }
        last TOKEN;
      }
      if ( $Line[$ix] eq "User_Alias" ){  # extract user names
        # User_Alias USERALIAS = user-list
        ($useralias,$aliaslist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $aliaslist =~ s/\s//g;

        # record useralias name so that it is not confused with a user name
        logDebug("SUDOERS: $InputLine");
        logDebug("SUDOERS: Found user_alias $useralias=$aliaslist");
        $AliasList{$useralias} = $aliaslist;        
        
        foreach $usr (split ',', $aliaslist)
        {
          if($UserAliasList{$usr})
          {
            $UserAliasList{$usr}.=",$useralias";
          }
          else
          {
            $UserAliasList{$usr}.="$useralias";
          }
        
          if ( exists $AliasList{$usr} )#is it an aliasname
          {
            logDebug("SUDOERS:Alias of Alias $useralias:$usr");
            
            if($AliasOfAlias{$useralias})
            {
              $AliasOfAlias{$useralias}.=",$usr";
            }
            else
            {
              $AliasOfAlias{$useralias}.="$usr";
            }
          }
        }  
        last TOKEN;
      }  # end if User_Alias

      # this line must be in "user access_group" format
      # e.g. root ALL = (ALL) ALL
      # e.g. root host = (ALL) ALL
      # e.g. root Host_Alias = (ALL) ALL
      # e.g. %grop ALL = (ALL) ALL
      ($userlist,$hostlist)=$InputLine=~/\s*([\w\,\%\+\@\/\s]+\w)\s+([\,\!\w\s]+)\s*\=/;
      $userlist =~ s/\s//g;
      $hostlist =~ s/\s//g;
      logDebug("SUDOERS: $InputLine");
      logDebug("SUDOERS: Found userlist $userlist");
      logDebug("SUDOERS: Found hostlist $hostlist");
      $PROCESSLINE=0;
      foreach $nextHost (split ',', $hostlist)
      {
        my $nextHost1=lc glob2pat($nextHost);

        if ( $HOST =~ /$nextHost1/i || $LONG_HOST_NAME =~ /$nextHost1/i)
        {
          logDebug("SUDOERS: PROCESSLINE=1, $nextHost = $HOST");
          $PROCESSLINE=1;
          last;
        }
        elsif ("ALL" =~ /$nextHost1/i)
        {
          logDebug("SUDOERS: PROCESSLINE=1, $nextHost = ALL");
          $PROCESSLINE=1;
          last;
        }
        elsif ($validHostAlias{$nextHost})
        {
          logDebug("SUDOERS: PROCESSLINE=1, $nextHost ValidHostALias");
          $PROCESSLINE=1;
          last;
        }
      }
      
      if ($PROCESSLINE)
      {
        if ($LDAP == 1 )
        {             #V7.5
          if ($userlist =~ /^\@\w+/ ) {
            ($userlist) = $userlist =~ /^\@(\S+)/;
            $userlist = $netgrouplist{$userlist};
            logDebug("Found Netgrp $userlist");
          }
          elsif ( $userlist =~ /^\+\w+/ ){
            ($userlist) = $userlist =~ /^\+(\S+)/;
            $userlist = $userlist;
            logDebug("Found Netusr $userlist");
          }
        }
        }
      foreach $next (split ',', $userlist)
      {
        logDebug("SUDOERS: add name $next");
        $User_List{$next}=$PROCESSLINE;
       }
       
      last TOKEN;
    }  # end TOKEN: while ix
    $InputLine= "";
  } # end while

  close SUDOERS_FILE;

  while(($key, $value) = each %User_List)
  {
    if($value == 1 )
    {
      add_name($key);
    }
  };
  
  if($SUDOALL eq "2") {
    $SUDOALL="0";
  }
  `rm -f $tmp_sudo_file`;
} # end sub parse

sub ProcessUserAlias
{
  my $useralias = $_[0];

  logDebug("ProcessserAlias: User_Alias: $useralias");
  my $aliaslst=$AliasList{$useralias};
  logDebug("ProcessserAlias: aliaslist: $aliaslst");
  
  foreach $nxt (split ',', $aliaslst)
  {
    # processing groups listed in User Alias
    if( $nxt =~ s/^%:*//)
    {
      if ($ggid{$nxt} eq "")
      {
        logMsg(WARN, "invalid group $nxt in $SUDOERS User_Alias");
      }
      else
      {
        my $Members;
        my $NewName;
        logDebug("ProcessUserAlias: Found group $nxt in User_Alias");
        # Swapped out function calls with access of the prepopulated associative arrays
        $Members = $gmembers{$ggid{$nxt}};
        foreach $NewName (split ',', $Members)
        {
          logDebug("ProcessUserAlias: Found user $NewName in group $nxt in User_Alias $useralias");
          make_alias_of_alias($NewName, $useralias, $nxt);
        }
      }
  }
  elsif ( $nxt ne "" )
  {
    if(exists $user_gid{$nxt})
    {
      logDebug("ProcessUserAlias: Add alias to user $nxt $useralias");
      make_alias_of_alias($nxt, $useralias, "");
    }
    else
    {
      if(exists $AliasList{$nxt})
      {
        ProcessSubAlias($useralias,$nxt);            
      }
      else
      {
        logMsg(WARN, "Invalid user $nxt in $SUDOERS $useralias");
      }
    }
  }  # if Line
 }  # end while each in useralias
} # end sub processuseralias

### Subroutine add_name - add name to list
#
# Call:
#   add_name(name)
#
# Arguments:
#   name - name to add to username alias list
#          ( %name if group name )
#
# User_Alias names are ignored.
# Group names are expanded to include all of the group members.
sub add_name
{
  my $Aname = $_[0];
  logDebug("add_name: Processing $Aname");

  if ( exists($AliasList{ $Aname }))
  {
    # ignore User_Alias names
    logDebug("SUDOERS: Found user alias $Aname");
    ProcessUserAlias($Aname);
    return 0;
  }
  # process user ids and group names
  if ( $Aname =~ /^%/ )
  {
    # trim leading "%:" to get group name
    $Aname =~ s/^%:*//;
    # get list of user ids
    if ($ggid{$Aname} eq "")
    {
      logMsg(WARN, "invalid group $Aname in $SUDOERS");
      return 1;
    }
    my $Members;
    my $NewName;
    logDebug("SUDOERS: Found group $Aname");
    # Swapped out function calls with access of the prepopulated associative arrays
    $Members = $gmembers{$ggid{$Aname}};
    foreach $NewName (split ',', $Members)
    {
      # add each user id
      # NO check to see if ID is in EXEMPT list of users?!
      ## only add to hash if user is added alone, not as part of group
      ##########  $UserList{ $NewName }++;
      if ($UserGroup{$NewName})
      {
        $UserGroup{$NewName}.=",$Aname";
      }
      else
      {
        $UserGroup{$NewName}.="$Aname";
      }
    }
  }
  else
  {
  # add a simple user id
    $UserList{ $Aname }++;
    logDebug("SUDOERS: Found user $Aname");
  }  # end if/else group name
  return 0;
}  # end subroutine add_name

sub openout()
{
  # Split out the path and filename portions
  my($filename, $directories, $suffix) = fileparse($OUTFILE);

  # path must exist
  if ( ! -e $directories )
  {
    logAbort("Output directory $directories does not exist");
  }

  # Resolve OUTFILE dirname to deferrence any symlinks
  # need to be absolutely sure what we are writing to !
  my $abs_path = abs_path($directories);

  # refuse to proceed if it looks like a system path
  # eg /usr /etc /proc /opt
  if ( $abs_path =~ /^\/usr/ or $abs_path =~ /^\/etc/ or $abs_path =~ /^\/proc/ or $abs_path =~ /^\/opt/)
  {
    logAbort("Output directory $abs_path not allowed");
  }

  # refuse to proceed output file exists and is not a plain file
  if ( -e $OUTFILE and ! -f $OUTFILE )
  {
    logAbort("Won't remove $OUTFILE not a normal file");
  }

  # and refuse if it is a symlink
  if ( -l $OUTFILE )
  {
    logAbort("Won't remove $OUTFILE is a symlink");
  }

  # If it exists and is a standard file remove it
  if ( -e $OUTFILE and -f $OUTFILE )
  {
    `rm -f $OUTFILE` ;
    if ($? != 0)
    {
      logAbort("Can't remove old $OUTFILE : $?");
    }
  }

  # Open the output file for writing
  open(OUTPUT_FILE, "> $OUTFILE") || logAbort("Can't open $OUTFILE for writing : $!");
} # end sub openout

sub remove_labeling_delimiter
{
    my $labellingData = shift;    
    $labellingData =~ s/\|/ /g;    
    return $labellingData;
}

sub get_urt_format{
    my $_usergecos = shift;
    
    my $_LCgecos=lc($_usergecos); 
    my $_userurt = 0;
    my $_userstatus = "";
    my $_usercust = "";
    my $_usercomment = "";
    my $_userserial = "";
    my $_userCCC = "";
    my $_userCC = "";
    
    logDebug("get_urt_format input: $_usergecos");
    if($_usergecos =~ /IBM\s+\S{6,6}\s+\S{3,3}($|\s)/)
    {
        $_userstatus="I";
        $_usercust="";
        $_usercomment=$_usergecos;
        ($_userserial, $_userCCC)= $_usergecos=~/IBM\s+(\S{6,6})\s+(\S{3,3})/;
        $_userCC=$_userCCC; 
    }
    elsif ($_usergecos =~ /\w{2,3}\/\w{1}\// )
    {
        $_userurt = 1;
    }
    elsif ($_LCgecos =~/s\=\S{9,9}/)
    {
        $_userstatus="I";
        $_usercust="";
        $_usercomment=$_usergecos;
        
        ($_userserial,$_userCCC)=$_LCgecos=~/s\=(\S{6,6})(\S{3,3})/;
        $_userCC=$_userCCC; 
    }
    else
    {
        $_userstatus="C";
        $_usercust="";
        $_usercomment=$_usergecos;
        $_userCC=$USERCC;
        $_userserial=""; 
    }
    
    my $_userinfo = "";
    
    if ($_userurt) {                                                                                                                             #7.4 Updated code to check URT format CCC/I/ in gecos field
        $_userinfo = "$_usergecos";
    }
    else {
        $_userinfo = "$_userCC/$_userstatus/$_userserial/$_usercust/$_usercomment";
    }
    logDebug("get_urt_format output: $_userinfo");    
    return remove_labeling_delimiter($_userinfo);
}

sub get_last_logon_user_id
{
  my $loginname=shift;
  my $str       = '';
  my $lastlogon = '';
  
  logDebug("retrieving last logon for user '$loginname' (OS - $OSNAME)");
  
  for ($OSNAME)
  {
      if(/linux/i)
      {
          $str = `lastlog -u $loginname 2>/dev/null`;
          $str=trim($str);
          if($str =~ /^$loginname[\s]*[^\s]*[\s]*[^\s]*[\s]*(\w+)[\s]+(\w+)[\s]+(\d+)[\s]+(\d+:\d+:\d+)[\s]+([^\s]*)[\s]+(\d+)/m)
          {
              $lastlogon = "$3 $2 $6";
          }
      }
      elsif(/aix/i)
      {
          $str = `lsuser -f $loginname 2>/dev/null`;
          $str=trim($str);
          logDebug("'$str'");
          if($str =~ /^[\s]*time_last_login=(\d+)/m)
          {
              $lastlogon = POSIX::strftime("%d %b %Y", localtime($1));
          }
      }
      else{
          $str = `finger -f $loginname 2>/dev/null`;
          $str=trim($str);
          logDebug("'$str'");
          
          my @buffer = split(/\n/, $str);
          my $currentYear = `date +%Y`;
          $currentYear=trim($currentYear);
          my $currentMonth = `date +%b`; chomp($currentMonth);
          my %mnames = ('Jul', 1, 'Aug', 2, 'Sep', 3, 'Oct', 4,
                  'Nov', 5, 'Dec', 6, 'Jan', 7, 'Feb', 8, 'Mar', 9,
                  'Apr', 10, 'May', 11, 'Jun', 12 );
          foreach (@buffer)
          {
            if ($_ =~ /On since\s+(\w+)\s+(\d+)\s+\d+:\d+/)
            {
            # current month before July and logon month before Jan
              --$currentYear if ($mnames{$currentMonth} > 6 && $mnames{$1} < 7);
              $lastlogon = "$2 $1 $currentYear";
              #last;
             }
             elsif($_ =~ /Last login\s+\w+\s+(\w+)\s+(\d+)\s+\d+:\d+/)
             {
               --$currentYear if ($mnames{$currentMonth} > 6 && $mnames{$1} < 7);
               $lastlogon = "$2 $1 $currentYear";
               last;
             }
             elsif($_ =~ /Last login\s+\w+\s+(\w+)\s+(\d+),\s+(\d+).*/)
             {
               $lastlogon = "$2 $1 $3";
               last;
             }               
           }
       }
  }
  logDebug("lastlogon = '$lastlogon'");
  chomp($lastlogon); 
  return $lastlogon;
}

sub report_group()
{
  my $remote_group="FALSE";
  my $privilege="";
  if ($PROCESSLDAP || $PROCESSNIS) 
  {
    $remote_group="TRUE";
  }
  
  while ( (my $groupgid, my $groupname) = each %group)
  {
    if( $IS_ADMIN_ENT_ACC != 0 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
    {
#      if ( $OSNAME =~ /linux/i || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i )
 #     {
        if($groupname !~ /$group_names/)
        {
          $remote_group="TRUE";
        }
        else
        {
          $remote_group="FALSE";
        }
#      }
    }    
    
    if($remote_group eq "FALSE")
    {
      if( exists $privgroups{$groupname})
      {
        $privilege="TRUE";
      }
      else
      {
        $privilege="FALSE";
      }
    }
    else
    {
      $privilege="";
    }
    
    print OUTPUT_FILE "G|$URTCUST|S|$HOSTNAME|$OSNAME|$groupname||$groupgid||$remote_group|$privilege\n";
  }
}

sub getTimeZone
{
    my $RAWTIMEZONE="";
    my $TIMEZONE="";
    my $sign="";
    my $hours="";
    my $minutes="";
    my $tz;

    # http://alma.ch/perl/perloses.htm
    if ( $OSNAME =~ /HPUX/i || $OSNAME =~ /HP-UX/i )
    {
        my $offset = "";

        my $time_zone_abbr;
        chomp($time_zone_abbr = `date +%Z`);
        return $offset if ($time_zone_abbr eq "");

        my $tztab_location = "/usr/lib/tztab";
        return $offset if (! -f $tztab_location);

        # need to get a list of lines that matches the time_zone_abbr
        my @offsets = ();

        open(TZ_HANDLER, "<$tztab_location") or do {
            warn "[WARN] Can't open file $tztab_location : $!\n";
            return $offset;
        };
        my $tz_var = $ENV{"TZ"};
        my $block = 0;

        while (<TZ_HANDLER>) {
            chomp;
            # remove comments
            s/#.*//;
            s/^\s*//;
            s/^\s*$//;
            # if tz_var exist
            if ($tz_var ne "") {
                # getting block
                if (/^$tz_var$/) {
                    $block = 1;
                    next;
                }
                next if ($block != 1);
                last if ($block == 1 && $_ eq "");
            }
            my @fields = split(/\s+/, $_);
            if (scalar(@fields) ge 7 && $fields[6] =~ /^$time_zone_abbr([0-9:-]+)$/) {
                push(@offsets, $1);
            }
        }
        while (@offsets) {
            # clear value
            $offset = "";
            my $last_value = pop @offsets;

            $sign = "-";
            $hours = "";
            $minutes = "";

            if ($last_value =~ /^(-?)(\d{1,2})(:(\d{1,2}))?(:.*)?$/) {

                $hours = defined $2 && $2 ne "" ? $2 : "0";
                $minutes = defined $4 && $4 ne "" ? sprintf("%0.2f", $4 / 60) : "0";
                $sign = "+" if ($1 eq "-" || $hours == 0 && $minutes == 0);
                $offset = $sign . ($hours + $minutes);
                last;
            }
        }
        close(TZ_HANDLER);
        $TIMEZONE = $offset;
    }
    else
    {
        $RAWTIMEZONE=`date +%z`;
        if($OSNAME =~/aix/i)
        {
            $sign=substr($RAWTIMEZONE,3,1);
            $hours=substr($RAWTIMEZONE,4,2);
            $minutes=substr($RAWTIMEZONE,7,2);
        }
        else
        {
            $sign=substr($RAWTIMEZONE,0,1);
            $hours=substr($RAWTIMEZONE,1,2);
            $minutes=substr($RAWTIMEZONE,3,2);
        }
        #print "'$sign' ... '$hours' ... '$minutes'\n";
        if($sign ne '+' && $sign ne '-')
        {
            $sign = '';
        }
        else
        {    
            $tz = ($minutes > 0) ? $hours+$minutes/60 : $hours+0;
        }
        $TIMEZONE="$sign$tz";
    }
    return trim($TIMEZONE);
}

sub ProcessSubAlias
{
  my $parent_alias=shift;
  my $alias = shift;

  my $aliaslst=$AliasList{$alias};
  logDebug("ProcesssSubAlias: parent $parent_alias, alias $alias, aliaslist $aliaslst");
  
  foreach $nxt (split ',', $aliaslst)
  {
    # processing groups listed in User Alias
    if( $nxt =~ s/^%:*//)
    {
      if ($ggid{$nxt} ne "")
      {
        my $Members;
        my $NewName;
        logDebug("ProcessSubAlias: Found group $next in $alias");
        my $Members = $gmembers{$ggid{$nxt}};
        foreach $NewName (split ',', $Members)
        {
          logDebug("ProcessSubAlias: Found user $NewName in group $nxt in $alias");
          store_user_alias($NewName, "$parent_alias:%$nxt");
        }
      } 
    }
    elsif ( $nxt ne "" )
    {
      if(exists $user_gid{$nxt})
      {
        logDebug("ProcessSubAlias: Add alias to user $nxt $useralias");
        store_user_alias($nxt, "$parent_alias:$alias");
      }
      else
      {
        if(exists $AliasList{$nxt})
        {
          logDebug("ProcessSubAlias: Found subalias user $NewName, alias $nxt");
          ProcessSubAlias($parent_alias,$nxt);            
        }
      }
    }  
  }  
} 

my $found="";
sub find_last_alias
{
  my $alias=shift;
  my $subalias=$AliasOfAlias{$alias};
    
  logDebug("find_last_alias: alias '$alias' subalias '$subalias'");
  
  if($subalias ne "" && $found eq "")
  {
    foreach $tempAlias (split(/,/,$subalias))
    {
      if($found eq "")
      {
        $subalias=find_last_alias($tempAlias);
        logDebug("find_last_alias:alias $tempAlias, found subalias $subalias");
        if($subalias eq "")
        {
          $found=$alias;
          break; 
        }
      }
    }
  }
  else
  {
    $found=$alias;
  }
  logDebug("find_last_alias: return subalias $found");
  return $found;
}

sub make_alias_of_alias
{
  my $user=shift;
  my $alias=shift;
  my $group=shift;
  my $str="";
  
  logDebug("make_alias_of_alias: user $user, alias $alias, group $group");
  
  $found="";
  my $subalias=find_last_alias($alias);
  logDebug("make_alias_of_alias: user $user, alias $alias subalias $subalias");
  if($subalias eq $alias)
  {
    $subalias="";
  }
  
  if( $subalias ne "")
  {
    store_user_alias($user, "$alias:$subalias");
    my $aliasgroup=&make_alias_of_group($user, $subalias);
    if($aliasgroup ne "")
    {
      store_user_alias($user, "$alias:%$aliasgroup");
    }
  }
  if( $group ne "" )
  {
    store_user_alias($user, "$alias:%$group");
  }
  else
  {
    store_user_alias($user, $alias);
  }
}

sub make_alias_of_group
{
  my $user=shift;
  my $alias=shift;
  
  my $aliaslist=$AliasList{$alias};
  my $usergroups=$user_allgroups{$user};
  
  logDebug("make_alias_of_group: user $user, alias $alias, aliaslist $aliaslist, usergroups $usergroups");
  
  foreach $aliasgroup (split(/,/,$aliaslist))
  {
    if( $aliasgroup =~ s/^%:*//) # if group
    {
      foreach $usergroup (split(/,/,$usergroups))
      {
        if($usergroup eq $aliasgroup)
        {
          logDebug("make_alias_of_group: user $user, alias $alias, found usergroup $usergroup");
          return $usergroup;
        }
      }
    }
  }
  return "";
}

sub store_user_alias
{
  my $user=shift;
  my $valstr=shift;
  
  if($valstr eq "")
  {
    return;
  }
  my $str=$UserAlias{$user};
  
  if ($str =~ /$valstr(,+|$)/)
  {
    logDebug("store_user_alias: $valstr is found");
    return;
  }
  
  logDebug("store_user_alias: user $user, value $valstr, sudostr $str");
  if($str eq "")
  {
    $UserAlias{$user}="SUDO_ALIAS($valstr";
  }
  else
  {
    $UserAlias{$user}="$str,$valstr";
  }
}

sub report()
{
  #==============================================================================
  # Produce the urt extract file
  #==============================================================================
  # URT .scm format is ....
  # hostname<tab>os<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
  #
  #print "INFO:  Writing report for customer: $URTCUST to file: $OUTFILE\n";

  my $UICmode="";
  my $UID="";
  my $PWMinLen="";
  my $PWChg="";
  my $PWMaxAge="";
  my $PWMinAge="";
  my $PWExp="";
  my $PWNeverExpires="FALSE";
  
  if($MEF4FORMAT)
  {
    if($OSNAME =~ /linux/i)
    {
      $PWMinLen=getFromThere("/etc/pam.d/system-auth","^password\\s*requisite\\s*pam_cracklib.so.*minlen=(\\d+).*");
      if($PWMinLen eq "")
      {
        $PWMinLen=getFromThere("/etc/login.defs","^PASS_MIN_LEN\\s*(\\d+).*");
      }
      logDebug("report:PWMinLen=$PWMinLen");
    }elsif( $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i ) 
    {
      $PWMinLen=getFromThere("/etc/default/passwd","^PASSLENGTH=(\\d+)\$");
      logDebug("report:PWMinLen=$PWMinLen");
    }elsif( $OSNAME =~ /HPUX/i || $OSNAME =~ /HP-UX/i ) 
    {
      $PWMinLen=getFromThere("/etc/default/security","^MIN_PASSWORD_LENGTH=(\\d+)\$");
      if($PWMinLen eq "")
      {
        $PWMinLen="6";
      }
    }
  }
  
  while ( (my $username, my $usergid) = each %user_gid)
  {
    $usergecos=$userllogon=$groupField=$privField=$userstate="";
    $UICmode="";
    $UID="";
    $PWChg="01 Jan 1970";
    $PWMaxAge="99999";
    $PWMinAge="0";
    $PWExp="31 Dec 9999";
    $PWNeverExpires="FALSE";

    ## skip id if  it preceded by +:
    if($username =~ /^\+/)
    {
      logInfo("User $username is excluded from output file, use --ldap option");
      next;
    }

    # gather the info
    $usergecos = $user_gecos{$username};
    $usergecos=remove_labeling_delimiter($usergecos);
    
    # set userstate depending on what we were able to extract
    if ( $state_available == 1 )
    {
      logDebug("report: $username check user state");
      # we have extracted all disabled accounts - rest must be enabled
      #if $user_state{username}=have value  the user_state=value
      #else user_state="Enabled"
      if($OSNAME !~ /AIX/i) 
      {
        $userstate = $user_state{$username} ? $user_state{$username} : "Enabled";
        $scm_userstate = defined $scm_user_state{$username} ? $scm_user_state{$username} : "0";
        logDebug("report: user state for $username is $userstate.");
      }
      else
      {
        $acclocked=$AIX_user_state{"default"};
        if(defined $AIX_user_state{$username})
        {
          $acclocked=$AIX_user_state{$username};
        }
        logDebug("report: User $username, account $acclocked"); 
        if( $acclocked eq "Enabled")
        {
          if( defined $AIX_passwd_state{$username})
          {
            $userstate=$AIX_passwd_state{$username};
            logDebug("report: User $username, passwdstate $userstate");
          }
        }
        if($acclocked eq "Disabled" || $userstate eq "")
          {
            $userstate="Disabled";
          }
        if( $acclocked eq "Enabled" && $userstate eq "Disabled")# && ($AIX_user_login{$username} eq "false" || $AIX_user_rlogin{$username} eq "false") )
        {
          if ( $PUBKEYAUTH eq "yes" )
          {
            $home=$user_home{$username};            
            if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ) )
            {
              $userstate = "SSH-Enabled";
              logDebug("Report: Found SSH Key for $username, user is $userstate");
            }
          }
        }
        logDebug("Report: User $username is $userstate");
      }
    }
    else
    {
      # we may have extracted some disabled accounts eg from passwd file but maybe not all
      # so default set blank
      $userstate = $user_state{$username} ? $user_state{$username} : "";
      $scm_userstate = $scm_user_state{$username} ne "" ? $scm_user_state{$username} : "0";
    }

  $gid=$user_gid{$username};
  $UID=$user_uid{$username};
  
  if ( ! exists $group{$gid})
  {
    logMsg(WARN,"user $username is in group $gid. Unable to resolve group $gid to a name");
    if($PROCESSNIS || $PROCESSLDAP)
    {
      logMsg("skip user $username");
      next;
    }
  }
  
  if (exists $user_allgroups{$username})
  {
    $groupField=$user_allgroups{$username};
  }
  else
  {
    logMsg(WARN,"no any group found for user $username");
  }
  
  if($DLLD == 0)
  {
    $userllogon = get_last_logon_user_id($username);
  }
  else
  {
    $userllogon = "";
  }
  
  $privField="";

  if($user_privuser{$username})
  {
    logDebug "Found privileged ID: $username";
    $privField=$username;
  }

  if($user_privgroups{$username})
  {
    $groupValue="GRP($user_privgroups{$username})";
    if($privField eq "")
    {
      $privField=$groupValue;
    }
    else
    {
      $privField=$privField.",".$groupValue;
    }
  }

  if ($SUDOALL eq "1")
  {
    if($privField eq "")
    {
      $privField="SUDO_ALL";
    }
    else
    {
      $privField=$privField.",SUDO_ALL";
    }
  }

  if ($UserGroup{$username})
  {
    $usersudogroups=$UserGroup{$username};
    logDebug("Report: userID $username, sudousergroup $usersudogroups");
    #uniquify the sudogrouplist
    %hash=();
    @cases = split(/,/,$usersudogroups);
    $usersudogroups = "";
    %hash = map { $_ => 1 } @cases;
    $usersudogroups = join(",", sort keys %hash);

    $SudoGroup="SUDO_GRP($usersudogroups)";
    if($privField eq "")
    {
      $privField=$SudoGroup;
    }
    else
    {
      $privField=$privField.",".$SudoGroup;
    }
  }
  
  if($UserAlias{$username})
  {
    if($privField eq "")
    {
      $privField=$UserAlias{$username};
    }
    else
    {
      $privField=$privField.",$UserAlias{$username}";
    }
    $privField=$privField.")";
  }

  $SudoValue="";
  if ($UserList{$username})
  {
    $SudoValue="SUDO\_$username";
    if($privField eq "")
    {
      $privField=$SudoValue;
    }
    else
    {
      $privField=$privField.",".$SudoValue;
    }
    delete $UserList{$username};
  }
  
  if($MEF4FORMAT)
  {
    my $tmpval="";
    if(defined $PWChg_Arr{$username})
    {
      $PWChg=$PWChg_Arr{$username};
    }
    
    if(defined $PWNeverExpires_Arr{$username})
    {
      $PWNeverExpires=$PWNeverExpires_Arr{$username};
    }
    
    if(defined $PWExp_Arr{$username})
    {
      $PWExp=$PWExp_Arr{$username};
    }
    
    $tmpval=$PWMaxAge_Arr{$username};
    if($tmpval ne "")
    {
      $PWMaxAge=$tmpval;
      if($OSNAME =~ /AIX/i && $tmpval eq "0")
      {
        $PWNeverExpires="TRUE";
        $PWExp="31 Dec 9999";
      }
    }
    
    if(defined $PWMinAge_Arr{$username})
    {
      $tmpval=$PWMinAge_Arr{$username};
      if($tmpval ne "")
      {
        $PWMinAge=$tmpval;
      }
    }
    
    if($OSNAME =~ /AIX/i)
    {
      $PWMinLen=$PWMinLen_Arr{$username};
    }
  }
  
  if ($PROCESSNIS)
  {
    $username = "NIS/" . $username;
  }

  if ($PROCESSLDAP)
  {
    $username = "LDAP/" . $username;
  }
  
  if ( $IS_ADMIN_ENT_ACC != 0 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
  {
    if($username !~ /$passwd_users/)
    {
      $username = "LDAP/" . $username;
    }
  }
  
  # Write the line
  if($SCMFORMAT)
  #SCM9 hostname<tab>os<tab>auditdate<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
  { 
    print OUTPUT_FILE "$HOSTNAME\t$OS\t$myAUDITDATE\t$username\t$usergecos\t$scm_userstate\t$userllogon\t$groupField\t$privField\n";
  }
  elsif($MEF2FORMAT)
  #MEF2 customer|system|account|userID convention data|group|state|l_logon|privilege
  {
    print OUTPUT_FILE "$URTCUST|$HOSTNAME|$username|$usergecos|$groupField|$userstate|$userllogon|$privField\n";
  }
  elsif($MEF4FORMAT)
  {
    print OUTPUT_FILE "U|$URTCUST|S|$HOSTNAME|$OSNAME|$username|$UICmode|$usergecos|$userstate|$userllogon|$groupField|$privField|$UID|$PWMaxAge|$PWMinAge|$PWExp|$PWChg|$PWMinLen|$PWNeverExpires\n";
  }
  else
  #MEF3 “customer|identifier type|server identifier/application identifier|OS name/Application name|account|UICMode|userID convention data|state|l_logon |group|privilege”
  #
  {
    print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField\n";
  }
  
} # end while
if($MEF4FORMAT)
{
  report_group();
}

while (($key,$value) = each %UserList) {
  $SudoValue="";
  logMsg(WARN,"invalid user name $key in $SUDOERS");
}
} # end sub report

sub printsig()
{
  # V7.4 Code to print custom signature for dummy id
  if ($SIG_TSCM) {
    $NOTREALID = "NOTaRealID-TSCM";
  }
  elsif ($SIG_SCR) {
    $NOTREALID = "NOTaRealID-SCR";
  }
  elsif($SIG_TCM) {
    $NOTREALID = "NOTaRealID-TCM";
  }
  elsif($SIG_FUS) {
    $NOTREALID = "NOTaRealID-FUS";
  }
  else {
    $NOTREALID = "NOTaRealID";
  }
  
  if($SIGNATURE ne "")
  {
    $NOTREALID = "NOTaRealID$SIGNATURE";
  }
  
  my $TIMEZONE=getTimeZone();
  
  ## Add dummy record to end of file
  if($SCMFORMAT)
  #SCM9 hostname<tab>os<tab>auditdate<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
  {
    print OUTPUT_FILE "$HOSTNAME\t$OS\t$myAUDITDATE\t$NOTREALID\t000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER\t1\t\t\t\n";
  }
  elsif($MEF2FORMAT)
  #MEF2 customer|system|account|userID convention data|group|state|l_logon|privilege
  {
    print OUTPUT_FILE "$URTCUST|$HOSTNAME|$NOTREALID|000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER||||\n";
  }
  elsif ($MEF4FORMAT)
  {
    print OUTPUT_FILE "S|$URTCUST|S|$HOSTNAME|$OSNAME|$NOTREALID||000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER||$TIMEZONE|$knowpar|$EXIT_CODE|||||||\n";
  }
  else
  #MEF3 “customer|identifier type|server identifier/application identifier|OS name/Application name|account|UICMode|userID convention data|state|l_logon |group|privilege”
  {
    print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$NOTREALID||000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER||$TIMEZONE|$knowpar|$EXIT_CODE\n";
    
  }

  logInfo("$ErrCnt errors encountered");

  close OUTPUT_FILE || logAbort("Problem closing output file : $!");
  
  &Filter_mef3();
  
  if($OWNER ne "")
  {
    `chown $OWNER $OUTFILE`;
  }
}

####### V 7.5 ###############
sub Parse_LDAP_Netusr
{
  logDebug("Parse_LDAP_Netusr: userID = $_[0]");
  if($LDAPFILE eq "")
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT uid=$_[0] uid userPassword uidNumber gidNumber loginShell gecos description`;
  }
  else
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT $LDAPADDITIONAL uid=$_[0] uid userPassword uidNumber gidNumber loginShell gecos description`;
  } 
   
  if ( $? != 0 )
  {
    logAbort("accessing LDAP server ($?)");
  }

  $username="";
  $passwd="";
  $uid="";
  $gid="";
  $gecos="";
  $shell="";
  
  foreach $line (split(/\n/,$attr))
  {
    logDebug("Parse_LDAP_Netusr: line = $line");
    if ( $line =~ /^uid:\s(\S+)/ ){
      $username =  $1 ;
      next;
    }
    if ( $line =~ /^userPassword::\s(\S+)/ ) {
      $passwd = $1;
      next;
    }
    if ( $line =~ /^uidNumber:\s(\d+)/ ) {
      $uid = $1;
      next;
    }
    if ( $line =~ /^gidNumber:\s(\d+)/ ) {
      $gid  = $1;
      next;
    }
    if ( $line =~ /^loginShell:\s(\S+)/ ) {
      $shell  = $1;
      next;
    }
    if ( $line =~ /^gecos:\s(.*)$/ && $gecos eq "") {
      $gecos = $1;
      next;
    }
    if ( $line =~ /^description:\s(.*)$/ && $gecos eq "") {
      $gecos = $1;
      next;
    }
    
  } #End foreach

  logDebug("Parse_LDAP_Netusr: user=$username:$passwd:$uid:$gid:$gecos");
  
  if($username ne "" && $gid ne "")
  {
    if (exists $primaryGroupUsers{$gid})
    {
      $primaryGroupUsers{$gid} = $primaryGroupUsers{$gid} . "," . $username;
    }
    else
    {
      $primaryGroupUsers{$gid} = $username;
    }
  }
  else
  {
    logDebug("Parse_LDAP_Netusr: no LDAP record for $_[0]");
  }
}

sub Parse_LDAP_Subnetgrp
{
  my $Netgrp = shift;
  my $memlist = "";
  my $tmpattr="";
  
  if($LDAPFILE eq "")
  {
    $tmpattr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  else
  {
    $tmpattr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  
  if ( $? != 0 )
  {
    logAbort("accessing LDAP server ($?)");
  }
 
  logDebug("Subgroup Found: $Netgrp: $tmpattr");

  foreach $line (split(/\n/,$tmpattr))
  {
    logDebug("Parse_LDAP_Subnetgrp: read = $line");
    if ($line =~ /^memberNisNetgroup:\s(\S+)/ )
    {
      my $tmpmemlist=Parse_LDAP_Subnetgrp($1);
      if ($memlist eq "" )
      {
        $memlist =  $tmpmemlist;
      }
      else
      {
        $memlist = $memlist .  ",$tmpmemlist";
      }
      next;
    }
    
    if ( $line =~ /^nisNetgroupTriple:\s\(,(\S+),/ ){
      if ($memlist eq "" ) {
        $memlist =  $1 ;
      }
      else {
        $memlist = $memlist .  ",$1" ;
      }
    }
  }
  return $memlist;
}

sub Parse_LDAP_Netgrp
{
  ($Netgrp) = $_[0] =~ /^\+\@(\S+)/;
  logDebug("Parse_LDAP_Netgrp: group = $Netgrp");
  $ldapmemlist = "";
  if($LDAPFILE eq "")
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  else
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  
  if ( $? != 0 )
  {
    logAbort("accessing LDAP server ($?)");
  }
  
  logDebug("Netgroup Found: $_[0], $Netgrp: $attr");

  foreach $line (split(/\n/,$attr))
  {
    if ($line =~ /^memberNisNetgroup:\s(\S+)/ )
    {
      my $tmpmemlist=Parse_LDAP_Subnetgrp($1);
      if ($ldapmemlist eq "" )
      {
        $ldapmemlist =  $tmpmemlist;
      }
      else
      {
        $ldapmemlist = $ldapmemlist .  ",$tmpmemlist";
      }
      next;
    }

    if ( $line =~ /^nisNetgroupTriple:\s\(,(\S+),/ )
    {
      if ($ldapmemlist eq "" )
      {
        $ldapmemlist =  $1 ;
      }
      else
      {
        $ldapmemlist = $ldapmemlist .  ",$1" ;
      }
    }
  }
  logDebug("Members of $Netgrp is $ldapmemlist");

  foreach $username (split(/,/,$ldapmemlist))
  {
    if(exists $user_gid{$username})
    {
      if(exists $netgrouplist{$Netgrp})
      {
        $netgrouplist{$Netgrp} = $netgrouplist{$Netgrp} . ",$username";
      }
      else
      {
        $netgrouplist{$Netgrp} = $username;
      }
      next;
    }
    else
    {
      Parse_LDAP_Netusr($username);
    }

    if(exists $netgrouplist{$Netgrp})
    {
      $netgrouplist{$Netgrp} = $netgrouplist{$Netgrp} . ",$username";
    }
    else
    {
      $netgrouplist{$Netgrp} = $username;
    }
    parse_user_info;
  }
}

sub parse_ldapgp
{
  logInfo("Processing LDAP groups");
  my $LDGHASH = get_ldgrp();
  for my $groupid ( keys %$LDGHASH )
  {
    $memlist = $LDGHASH->{ $groupid }->{ 'gmemlist' } ;
    $gname = $LDGHASH->{ $groupid }->{ 'gname' } ;
    logDebug("Primary Group users of $groupid is $primaryGroupUsers{$groupid}");
    if (exists $primaryGroupUsers{$groupid})
    {
      if($memlist eq "")
      {
        $allusers=$primaryGroupUsers{$groupid};
      }
      else
      {
        $allusers="$primaryGroupUsers{$groupid},$memlist";
      }
    }
    else
    {
      $allusers=$memlist;
    }
    
    $FOUNDPG=is_priv_group($gname, $groupid);
    
    logDebug("All users $gname: $allusers");
    logDebug("FOUNDPG:$FOUNDPG");

    foreach $username (split(/,/,$allusers))
    {
      if (exists $user_allgroups{$username})
      {
        my $is_founded_dublicate = 0;
        foreach my $usergroup (split(/,/,$user_allgroups{$username})){
        if ($usergroup eq $gname){
          $is_founded_dublicate = 1;
        }
      }

      if (!$is_founded_dublicate){
        $user_allgroups{$username} = $user_allgroups{$username} . "," . $gname;
      }
    }
    else
    {
      $user_allgroups{$username} = $gname;
    } # end if

    if ($FOUNDPG)
    # only save priv groups
    {
      logDebug("ADDING priv group $gname");
      if (exists $user_privgroups{$username})
      {
        $user_privgroups{$username} = $user_privgroups{$username} . "," . $gname;
      }
      else
      {
        $user_privgroups{$username} = $gname;
      } # end if
    } # end if

  } # end foreach

}#end for

}

sub get_ldgrp
{
  my %LDGRPS = ( );
  if($LDAPFILE eq "")
  {
    `$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT objectClass=posixGroup  cn gidNumber memberUid > $tmpfile `;
  }
  else
  {
    `$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL objectClass=$LDAPGROUPOBJCLASS cn gidNumber memberUid > $tmpfile `;
  }
  
  if ( $? != 0 )
  {
    logAbort("accessing LDAP server ($?)");
  }
  
  $gName=$gidNum=$memlist="";
  
  open(LDAP_FILE, " $tmpfile " ) || logAbort("Error on ldap");
  open(LDAP_GROUP_FILE, "> $LDAPGROUP") || logAbort("Can't open $LDAPGROUP for writing : $!");
  while (<LDAP_FILE>)
  {
    if ( /^\s/ )
    {
      logDebug("LDAP Group:$gName:$gidNum:$memlist");
      print LDAP_GROUP_FILE "$gName: :$gidNum:$memlist\n";
      $gName=$gidNum=$memlist="";
      next;
    }

    if ( /^cn:\s(\S+)/ )
    {
      $gName =  $1;
      $memlist = "";
      next;
    }

    if (/^gidNumber:\s(\d+)/)
    {
      $gidNum = $1;
      next;
    }
    
    if ( /^memberUid:\s(\w+)/ )
    {
      if ( $memlist eq "" )
      {
         $memlist = "$1";
      }
      else
      {
         $memlist = $memlist . ",$1";
      }
      next;
    }
  }
  close LDAP_FILE;
  close LDAP_GROUP_FILE;
  `rm -f $tmpfile` ;
  return \%LDGRPS;
}

sub is_adminent_accessible()
{
  if($IS_ADMIN_ENT_ACC == 0)
  {
    if ( $OSNAME =~ /aix/i && $LDAP == 1 )
    {
      `lsuser -R LDAP ALL  2>&1`;
      if ($?)
      {
        logInfo("Server $HOST ($OSNAME) is not LDAP connected");
      }
      else
      {
        $IS_ADMIN_ENT_ACC = 1;
      }
    }
    
    if ( ($OSNAME =~ /linux/i || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i) && ($NOAUTOLDAP == 0 || $LDAP == 1) )
    {
      `getent passwd`;
      if ($?)
      {
        logInfo("Checking on the admin ent tools . Operating system: $OSNAME is not supported");
      }
      else
      {
        $IS_ADMIN_ENT_ACC = 1;
      }
    }
  }
  logDebug("is_adminent_accessible = $IS_ADMIN_ENT_ACC");
}

sub check_pam()
{
  my $line="";
  my $ret=0;
  
  if($DEV == 1)
  {
    $LDAPCONF="./ldap.conf";
  }
  
  if ( -e $LDAPCONF && $OSNAME !~ /aix/i) 
  {
    open(LDAPCONF_FILE, $LDAPCONF) || logMsg(WARN,"Can't open $LDAPCONF : $!");
    while ($line = <LDAPCONF_FILE>)
    {
      if ($line =~ /^#/)  
      {
        next;
      }
      
      if ($line =~ /\s*pam_check_host_attr\s*yes/)
      {
        $ret=1;
        logDebug("pam_check_host_attr yes");
        last;
      }
    }
    close LDAPCONF_FILE;
  }
  else
  {
    logDebug("check_pam: Found AIX or $LDAPCONF is not accessible");
  }
  return $ret;
}

sub process_LDAP_users()
{
  my $isPAM=check_pam();
  logDebug("process_LDAP_users: check_pam=$isPAM");
  if($LDAPFILE eq "")
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT uid=* uid userpassword uidNumber gidNumber loginShell gecos host description`;
  }
  else
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT $LDAPADDITIONAL $LDAPUSERFILTER uid userpassword uidNumber gidNumber loginShell gecos host description`;
  }

  if ( $? != 0 )
  {
    logAbort("accessing LDAP server ($?)");
  }
  my $firstTime = 0;
  $username = $passwd = $uid = $gid = $shell = $gecos = "";
  my $isAIX=$OSNAME =~ /aix/i;
  my $checkHost=0;
   
  open(LDAP_PASSWD, "> $LDAPPASSWD") || logAbort("Can't open $LDAPPASSWD for writing : $!");
  
  foreach $line (split(/\n/,$attr))
  {
    logDebug("process_LDAP_users: line=$line");
    
    if ( $line =~ /^userPassword::\s(\S+)/ ) {
      $passwd = $1;
      next;
    }
    if ( $line =~ /^uidNumber:\s(\d+)/ ) {
      $uid = $1;
      next;
    }
    if ( $line =~ /^gidNumber:\s(\d+)/ ) {
      $gid  = $1;
      next;
    }
    if ( $line =~ /^loginShell:\s(\S+)/ ) {
      $shell  = $1;
      next;
    }
    if ( $line =~ /^gecos:\s(.*)$/ && $gecos eq "") {
      $gecos = $1;
      next;
    }
    if ( $line =~ /^description:\s(.*)$/ && $gecos eq "") {
      $gecos = $1;
      next;
    }
    if ( $line =~ /^uid:\s(.*)$/ ) {
      $username = $1;
      next;
    }
    
    if ( $line =~ /^host:\s(\S+)/ )
     {
      my $_host=lc $1;
      if($isPAM == 1 && (($_host eq $HOST) || ($_host eq $LONG_HOST_NAME)))
      {
        $checkHost=1;
        logDebug("process_LDAP_users: host $_host");
      }
      next;
    }

    if ( $line =~ /^dn:\s/ )
    {
      logDebug("process_LDAP_users: LDAP user=$username");
      if($firstTime == 0 )
      {
        $firstTime = 1;
        next;
      }
      
      if($uid eq "" && $gid eq "")
      {
        $passwd = $uid = $gid = $shell = $gecos = "";
        $checkHost=0;
        next;
      }
      
      if($isAIX)
      {
        if($LDAP_users{$username} == 1)
        {
          print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
        }
        else
        {
          logDebug("process_LDAP_users: skip user $username");
        }
      }
      else
      {
       if($isPAM)
        {
          if($checkHost == 1)
          {
            print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
          }
          else
          {
            logDebug("process_LDAP_users: skip user $username");
          }
        }
        else
        {
          print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
        }
      }
      $passwd = $uid = $gid = $shell = $gecos = "";
      $checkHost=0;
    }
  }

  if($uid ne "")
  {
    if($isAIX)
    {
      if($LDAP_users{$username} == 1)
      {
        print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
      }
      else
      {
       logDebug("process_LDAP_users: skip user $username");
      }
    }
    else
    {
     if($isPAM)
      {
        if($checkHost == 1)
        {
          print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
        }
        else
        {
          logDebug("process_LDAP_users: skip user $username");
        }
      }
      else
      {
        print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
      }
    }
  }
  close LDAP_PASSWD;
}

sub check_nisplus
{
   #my $proc = `ps -ef | grep nis_cachemgr`;
   my $ret = 0;
   #if ( -e "/var/nis/NIS_COLD_START" and $ret=~ /nis_cachemgr/)
   if ( -e "/var/nis/NIS_COLD_START" )
   {
      $ret = 1;
   }
   return $ret;
}

sub preparsesudoers()
{
  my $sudo_file=shift;
  my $tmp_sudo_file=shift;
    
  logDebug("Preprocess sudo file $sudo_file");
  `cat $sudo_file >> $tmp_sudo_file`;
  my $sudohandler = IO::File->new($sudo_file)  || logMsg(WARN, "Can't open SUDOERS: $sudo_file");
  my $include_file;
  while ($nextline = <$sudohandler>)
  {
    chomp $nextline;
    if ( $nextline =~ /^#include\s(.*)$/i )
    {
      $include_file = $1;
     
      if ( $include_file =~ /(.*)%h$/i )
      {
        $include_file = $1.$HOST;
        logDebug("SUDOERS: Add host name to sudo file $include_file");
      }
      
      if( ! -e $include_file)
      {
        logDebug("SUDOERS:$include_file is not a file");
        next;
      }
      
      logDebug("SUDOERS: Found #include directive. Included file name is $include_file");
      &preparsesudoers($include_file, $tmp_sudo_file);
    }
   if ( $nextline =~ /^#includedir\s(.*)$/i )
    {
      $include_dir = $1;
      $include_dir=trim($include_dir); 
      if($include_dir !~ /\/$/)
      {
        $include_dir.="/";
      }
      
      if(!opendir(SUDO_DIR, $include_dir))
      {
        logMsg(WARN, "SUDOERS: Can't open directory $include_dir");
        next;
      }
      
      while ($include_file = readdir(SUDO_DIR))
      {
        if( $include_file =~ /^\.\.?$/)
        {
          logDebug("SUDOERS: 1 Skip file $include_file");
          next;
        }
         
        if( $include_file =~ /~$/i || $include_file =~ /\./i)
        {
          logDebug("SUDOERS: 2 Skip file $include_file");
          next;
        }
          
        $include_file=$include_dir.$include_file;
          
        if( -d $include_file)
        {
          logDebug("SUDOERS:Skip directory $include_file");
          next;
        }

        &preparsesudoers($include_file, $tmp_sudo_file);
      }
      closedir(SUDO_DIR);
      logDebug("SUDOERS:Found #includedir directive. Included directory name is $include_dir");
    }
  }
}

sub trim($)
{
    my $str = shift;
    $str =~ s/^\s+//;
    $str =~ s/\s+$//;
    return $str;
}


sub mef_users_post_process
{
    my $OUTPUTFILE = shift;
    my $ibmOnly = shift;
    my $customerOnly = shift;

    if($ibmOnly == $customerOnly)
    {
        return 1;
    }
    
    my $isIbmUser = 0;
    my $base_mef_name = `basename $OUTPUTFILE`;
    $base_mef_name=trim($base_mef_name);
    my $TMP_OUT = "/tmp/${base_mef_name}_tmp";
    
    `cat $OUTPUTFILE > $TMP_OUT`;
    if(!open(TMP_OUT_FILE, $TMP_OUT))
    {
      unlink $TMP_OUT;
      logAbort("Can't open TMP_OUT_FILE '$TMP_OUT'");
      #$EXIT_CODE=EXEC_WARN;
      #$ErrCnt++;
      return 0;
    }
    # open file for writing
    if(!open(OUT_MEF_FILE, ">$OUTPUTFILE"))
    {
      unlink $TMP_OUT;
      logAbort("Can't open OUTPUTFILE '$OUTPUTFILE'");
      #$EXIT_CODE=EXEC_WARN;
      #$ErrCnt++;
      return 0;
    }
    while (<TMP_OUT_FILE>)
    {
        my $line = $_; 
        $line=trim($line);
        if (!($line =~ /([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)$/))
        {
            print (OUT_MEF_FILE "$line\n");
            next;
        }
        my $user  = $5;
        my $GECOS = $7;
        if($user =~ /^NOTaRealID.*/i) # NOTaRealID
        {
            print (OUT_MEF_FILE "$line\n");
            next;
        }
        if($user=~/^[^@]*@[^\.]*\.ibm\.com$/i && $ibmOnly == 1)
        {
                print (OUT_MEF_FILE "$line\n");
            next;
        }
        # if gecos is not an AG format get it
        #print "   --- GECOS = '$GECOS'";
        if( ($GECOS=~/\w{2,3}\/[^\/]*\/[^\/]*\/[^\/]*\/.*/i) == 0 )
        {
            #print "   --->  NOT AG FORMAT --- \n";
            $GECOS = get_urt_format($GECOS);
            #print "         ... GOT AG FORMAT --- ($GECOS)\n";
        }
        if( ($GECOS=~/\w{2,3}\/[^\/]*\/[^\/]*\/[^\/]*\/.*/i) == 0 )
        {
            logMsg(WARN,"Can't found URT Format $user:'$GECOS'");
            return 0;
        }
        $isIbmUser = ( $GECOS=~/\w{2,3}\/([ISFTEN])\/[^\/]*\/[^\/]*\/.*/i);
        #print "   --- FOUND IBM SYMBOL [$1] --- \n";
        if( ($isIbmUser==1 && $ibmOnly == 1) || ($isIbmUser==0 && $customerOnly))
        {
            print (OUT_MEF_FILE "$line\n");
            next;
        }
        if($isIbmUser==0 && $customerOnly)
        {
            print (OUT_MEF_FILE "$line\n");
            next;
        }
    }
    close(TMP_OUT_FILE);
    close(OUT_MEF_FILE);
    unlink $TMP_OUT;
    return 1;
}

sub Filter_mef3
{
  logDebug("filter: OutputFile:$OUTFILE");
  logDebug("filter: ibmOnly:$ibmonly"); 
  logDebug("filter: customerOnly:$customeronly");
  if( $ibmonly != 0 || $customeronly != 0 )
  {
    mef_users_post_process( $OUTFILE,$ibmonly,$customeronly );
  }
}

sub collect_LDAP_users_aix
{
  my $tmp_user_file="/tmp/ldapuser_tmp";
  
  my $nextline;
  my $username="";
  
  if($OSNAME =~ /aix/i)
  { 
    $attr=`lsuser -R LDAP ALL > $tmp_user_file`;
    if ( $? != 0 )
    {
      return;
    }
    
    open(TMP_USER_FILE, $tmp_user_file) || logMsg(WARN,"Can't open $tmp_user_file");
    while ($nextline = <TMP_USER_FILE>)
    {
      chomp($nextline);
    
      my $cmt_ix = index( $nextline, " ");
      if ( $cmt_ix >= 0 )
      {
        if($nextline =~ /registry=LDAP.*SYSTEM=.*LDAP.*\s/)
        {
          $username = substr( $nextline, 0, $cmt_ix);
          logDebug("collect_LDAP_users_aix : Add LDAP user $username");
          $LDAP_users{$username}=1;
        }
      }
    } # end while
    
    close TMP_USER_FILE;
    `rm -f $tmp_user_file`;
  }
}

sub getfqdn($)
{
  my $hostname = shift;
  my $conffile="/etc/resolv.conf";
  my $line="";
  my $fqdn="";

  if($DEV == 1)
  {
    $conffile="./resolv.conf";
  }
  
  open(RESOLV_FILE, $conffile) || logMsg(WARN,"Can't open $conffile : $!");
  while ($line = <RESOLV_FILE>)
  {
    logDebug("getfqdn: read $line");
    if ($line =~ /^domain\s*(.*)$/i)
    {
      $fqdn="$hostname.$1";
      last;
    }
  }
  close RESOLV_FILE;
    
  if($fqdn eq "")
  {
    $fqdn = `nslookup $hostname | awk '/^Name:/{print \$2}'`;
    logDebug("getfqdn: nslookup $fqdn");
  }
    
  if($fqdn eq "")
  {
    $fqdn=$hostname;
  }
    
  return lc trim($fqdn);
}
##############################################################
#GSA
##############################################################
#args filename, findwhat
#1- found
#0- not found
sub isThere
{
  my $FILENAME = shift;
  my $FINDWHAT = shift;
  
  logDebug("isThere : FILENAME=$FILENAME, FINDWHAT=$FINDWHAT");
  open(FILE_FILE, $FILENAME) || return 0;
  while ($line = <FILE_FILE>)
  {
    if ($line =~ /$FINDWHAT/i)
    {
      #logDebug("isThere : found=$line");
      logDebug("isThere : found");
      close FILE_FILE;
      return 1;
      
    }
  }
  close FILE_FILE;
  logDebug("isThere : not found");
  return 0;
}

sub getFromThere
{
  my $FILENAME = shift;
  my $FINDWHAT = shift;
  my $ret="";
  
  logDebug("getFromThere : FILENAME=$FILENAME, FINDWHAT=$FINDWHAT");
  open(FILE_FILE, $FILENAME) || return $ret;
  while ($line = <FILE_FILE>)
  {
    if ($line =~ /$FINDWHAT/i)
    {
      $ret=$1;
      last;
    }
  }
  close FILE_FILE;
  logDebug("getFromThere : return value=$ret");
  return $ret;
}

sub isThereDir
{
  my $DIR_NAME = shift;
  my $FILENAME_MASK = shift;
  my $FINDWHAT = shift;
  my $filename="";
  
  logDebug("isThereDir:$DIR_NAME $FILENAME_MASK $FINDWHAT");
  opendir(DIR_HANDLE, $DIR_NAME) || logMsg(WARN, "isThereDir: Can't open directory $DIR_NAME");
  while (defined ($filename = readdir(DIR_HANDLE)) )
  {
    if($filename =~ /$FILENAME_MASK/i)
    {
      if(isThere("$DIR_NAME$filename", $FINDWHAT) == 1)
      {
        closedir(DIR_HANDLE);
        return 1;
      }
    }
  }
  closedir(DIR_HANDLE);
  
  return 0; 
}

sub checkGSAconfig
{
  my $flag=0;
  my $METHODCFG="/usr/lib/security/methods.cfg";
  if($DEV == 1)
  {
    $METHODCFG="cfg/methods.cfg";
  }
  
  logDebug("checkGSAconfig: check configuration");
  
  if($OSNAME =~ /aix/i)
  {
    $flag = isThere($SUSER, "^[^\\*]\\s*SYSTEM.+gsa") && isThere($METHODCFG, "GSA");
  }  
  
  if($OSNAME =~ /linux/i)
  {
    my @checkFileList=("system-auth", "common-auth", "local-auth", "ftp", "login", "rexec", "rlogin", "samba", "sshd", "su", "sudo", "xscreensaver", "xdm", "gnome-screensaver");
    foreach $checkFile (@checkFileList)
    {
      if(isThere("/etc/pam.d/$checkFile", ".+gsa") == 1)
      {
        $flag = isThere("/etc/nsswitch.conf", "ldap");
        last;
      }
    }
    if($flag == 0)
    {                                            
      $flag=isThereDir("/etc/security/", "^pam", ".+gsa");
    }
  }
  logDebug("checkGSAconfig: return value is $flag");
  return $flag;
} 

sub GSALDAP
{
  my $LDAPServer="";
  
  logDebug("GSALDAP: get LDAP server address");
  
  if($OSNAME =~ /aix/i)
  {
    $LDAPServer=getFromThere($GSACONF,"^cellname\\s*(.*)\$");
    if($LDAPServer eq "")
    {
      $LDAPServer=getFromThere($GSACONF,"^ldaphost\\s*\\S*,\\s*(.*)\$");
    }
  }  
  
  if($OSNAME =~ /linux/i)
  {
    $LDAPServer=getFromThere($LDAPCONF, "^host\\s*(.*)\$");
    if($LDAPServer eq "")
    {
      $LDAPServer=getFromThere($GSACONF, "^host\\s*(.*)\$");
    }
  }  
  logDebug("GSALDAP: LDAP server address is $LDAPServer");
  return $LDAPServer;
}

sub getLDAPBASE
{
  my $gsabase="";
  logDebug("getLDAPBASE: start");
  $gsabase=getFromThere($GSACONF, "^ldapbase\\s*(.*)\$");
  if($gsabase ne "")
  {
    $PEOPLEBASE="ou=People,$gsabase";
    $GROUPBASE="ou=Group,$gsabase";
  }
  if($OSNAME =~ /linux/i && $gsabase eq "")
  {
    $PEOPLEBASE=getFromThere($LDAPCONF, "^nss_base_passwd\\s*(.*)\\?");
    $GROUPBASE=getFromThere($LDAPCONF, "^nss_base_group\\s*(.*)\\?");
  }
  logDebug("getLDAPBASE:$PEOPLEBASE,$GROUPBASE");
}

sub extractSudoUsersGroups
{
  my $tmp_sudo_file="/tmp/sudoersfile.tmp";
  `rm -f $tmp_sudo_file`;
  
  %BLOCKED = ();
  my %sudousers=();
  &preparsesudoers($SUDOERS, $tmp_sudo_file);

  open(SUDOERS_FILE, $tmp_sudo_file) || logMsg(WARN, "Can't open SUDOERS:$tmp_sudo_file : $!\nAccount SUDO privileges will be missing from extract");
  while ($nextline = <SUDOERS_FILE>)
  {
    chomp($nextline);
    logDebug("extractSudoUsersGroups:read $nextline");
    chomp $nextline;
    ## concatenate line with next line if line ends with \
    if ( $nextline =~ /\\\s*$/ )
    {
      # process continuation line
      ($nline)=$nextline=~/(.*)\\\s*$/;
      chomp($nline);
      chop($nextline);
      $InputLine .= $nline;
      next;
    }
    $InputLine .= $nextline;

    ## trim out comment lines
    $cmt_ix = index( $InputLine, "#" );
    if ( $cmt_ix >= 0 )
    {
      $InputLine = substr( $InputLine, 0, $cmt_ix);
    }

    # split line into tokens (names and keywords)
    @Line = split /[,=\s]/, $InputLine;
    $ix = 0;

    # classify pieces of the input
    TOKEN: while ( $ix <= $#Line ) {
      if ( $Line[$ix] eq "" ) {  # ignore seperators
        $ix++;
        next TOKEN;
      }
      if ( $Line[$ix] eq "Cmnd_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Runas_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Defaults" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Host_Alias" ){
        ($hostalias,$hostlist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $hostlist =~ s/\s//g;
      
        foreach $nextHost (split ',', $hostlist) {
          $nextHost=glob2pat($nextHost);
          if ( $HOST =~ /$nextHost/i || $LONG_HOST_NAME =~ /$nextHost/i || "ALL" =~ /$nextHost/i)
          {
            $validHostAlias{$hostalias}=$hostalias;
          }
        }
        last TOKEN;
      }
      if ( $Line[$ix] eq "User_Alias" )
      {
        ($useralias,$aliaslist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $aliaslist =~ s/\s//g;

        logDebug("extractSudoUsersGroups: $InputLine");
        logDebug("extractSudoUsersGroups: Found user_alias $useralias");
        logDebug("extractSudoUsersGroups: Found aliaslist $aliaslist");
        
        $AliasList{$useralias} = $aliaslist;
                    
        foreach $usr (split ',', $aliaslist)
        {
            logDebug("Added user $usr");
            $sudousers{$usr}=1;
        }  
        last TOKEN;
      }
      ($userlist,$hostlist)=$InputLine=~/\s*([\w\,\%\+\@\/\s]+\w)\s+([\,\!\w\s]+)\s*\=/;
      $userlist =~ s/\s//g;
      $hostlist =~ s/\s//g;
      $PROCESSLINE=0;
      if($priv =~ /!ALL/ )
      {
        logDebug("extractSudoUsersGroups: found !ALL");
        foreach $nextHost (split ',', $hostlist)
        {
          $nextHost1=glob2pat($nextHost);
          if ( $HOST =~ /$nextHost1/i || $LONG_HOST_NAME =~ /$nextHost1/i)
          {
            $PROCESSLINE=1;
          }
          elsif ("ALL" =~ /$nextHost1/i)
          {
            $PROCESSLINE=1;
          }
          elsif ($validHostAlias{$nextHost})
          {
            $PROCESSLINE=1;
          }
        }
        if($PROCESSLINE == 1)
        {
          if(exists($AliasList{$userlist}))
          {
            logDebug("extractSudoUsersGroups: $userlist is Alias");
            $userlist = $AliasList{$userlist};
            logDebug("extractSudoUsersGroups: corrected $userlist");
          }
      
          foreach my $usr (split ',', $userlist)
          {
            logDebug("extractSudoUsersGroups: added blocked user $usr");
            $BLOCKED{$usr}=1;
          }
          last TOKEN;
        }
      }
      foreach my $usr (split ',', $userlist)
      {
        $sudousers{$usr}=1;
        logDebug("extractSudoUsersGroups: added sudo user $usr");
      }
      last TOKEN;
    }
    $InputLine= "";
  } 

  close SUDOERS_FILE;
  `rm -f $tmp_sudo_file`;
  
  for my $gsauid (keys %sudousers)
  {
    if(exists($BLOCKED{$gsauid}))
    {
      logDebug("extractSudoUsersGroups: $gsauid is blocked, skipped");
      delete($MEMBERS{$gsauid});  
      next;
    }
    
    if(exists($AliasList{$gsauid}))
    {
      logDebug("extractSudoUsersGroups: $gsauid is Alias, skipped");
      next;
    }
    
    if($gsauid =~ /^%/ )
    {
      $gsauid =~ s/^%:*//;
      if($gsagrouplist ne "")
      {
        $gsagrouplist.=",$gsauid";
      }
      else
      {
       $gsagrouplist="$gsauid";
      }
      next;
    }
    logDebug("extractSudoUsersGroups:$gsauid is added to memberlist ");
    $MEMBERS{$gsauid}=1;
  }
  
  while(($key, $value) = each %AliasList){
    delete($AliasList{$key});
  };
  
  while(($key, $value) = each %BLOCKED){
    delete($BLOCKED{$key});
  };
  
  while(($key, $value) = each %sudousers){
    delete($sudousers{$key});
  };
}

sub getGSAgroup
{
  my @grouplist = split(',',shift);
  
  logDebug("getGSAgroup: starting");
      
  open(LDAP_GROUP_FILE, "> $LDAPGROUP") || logAbort("Can't open $LDAPGROUP for writing : $!");
  foreach my $gsagroup (@grouplist)
  {
    logDebug("getGSAgroup: get gsagroup $gsagroup information");
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $GROUPBASE cn=$gsagroup cn gidNumber memberUid`;
    if ( $? != 0 )
    {
      close LDAP_GROUP_FILE;
      logAbort("accessing LDAP server ($?)");
    }
    
    my $gidNumber="";
    my $memberUid="";
    
    foreach $line (split(/\n/,$attr))
    {
      logDebug("getGSAgroup: line=$line");
      if( $line =~ /^gidNumber:\s(\S+)/ )
      {
        $gidNumber = $1;
        logDebug("getGSAgroup: gidNumber=$gidNumber");
        next;
      }
      if( $line =~ /^memberUid:\s(\S+)/ )
      {
        $MEMBERS{$1}=1;
        if($memberUid ne "")
        {
          $memberUid.=",$1";
        }
        else
        {
          $memberUid="$1";
        }
        logDebug("getGSAgroup: memberUid=$1");
        next;
      }
    }
    print LDAP_GROUP_FILE "$gsagroup:!:$gidNumber:$memberUid\n";
    logDebug("getGSAgroup:groupfile->$gsagroup:!:$gidNumber:$memberUid");
  }   
  close LDAP_GROUP_FILE;
}

sub getGroupGID
{
  my $group = shift;
  
  logDebug("getGroupGID: group is $group");  
  
  my $temp=`$LDAPCMD -LLL -h $LDAPSVR -b $GROUPBASE cn="$group" gidNumber`;
  if ( $? != 0 )
  {
    logAbort("accessing LDAP server ($?)");
  }
  foreach my $str (split(/\n/,$temp))
  {
    logDebug("getGroupGID:$str");
    if( $str =~ /^gidNumber:\s(\S+)/)
    {
      return $1;
    }
  }
  return "";
}

sub getAdditionalGroup
{
  open(LDAP_GROUP_FILE, ">> $LDAPGROUP") || logAbort("Can't open $LDAPGROUP for append : $!");
  for my $gsauid (keys %MEMBERS)
  {
    logDebug("getAdditionalGroup: uid=$gsauid");
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $GROUPBASE memberUid=$gsauid cn`;
    if ( $? != 0 )
    {
      logAbort("accessing LDAP server ($?)");
    }
    foreach $line (split(/\n/,$attr))
    {
      logDebug("getAdditionalGroup:$line");
      if( $line =~ /^cn:\s(\S+)/)
      {
        my $gsagroup = $1;
        my $gidNumber=getGroupGID($gsagroup);
        print LDAP_GROUP_FILE "$gsagroup:!:$gidNumber:$gsauid\n";
        next;
      }
    }
  }
  close LDAP_GROUP_FILE;
}

sub getGSAuser
{
  logDebug("getGSAuser: starting");  
  
  open(LDAP_PASSWD_FILE, "> $LDAPPASSWD") || logAbort("Can't open $LDAPPASSWD for writing : $!");
  for my $gsauid (keys %MEMBERS)
  {
    logDebug("getGSAuser: gsauid=$gsauid");
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $PEOPLEBASE uid=$gsauid uniqueIdentifier cn`;
    if ( $? != 0 )
    {
      close LDAP_PASSWD_FILE;
      logAbort("accessing LDAP server ($?)");
    }
    
    my $uniqueIdentifier="";
    my $cn="";
    
    foreach $line (split(/\n/,$attr))
    {
      logDebug("getGSAuser: line=$line");
      if( $line =~ /^uniqueIdentifier:\s(\S+)/ )
      {
        $uniqueIdentifier=$1;
        logDebug("getGSAuser: uniqueIdentifier=$uniqueIdentifier");
        next;
      }
      if( $line =~ /^cn:\s(.+)/ )
      {
        $cn=$1;
        logDebug("getGSAuser: cn=$cn");
        next;
      }
    }
    
    if($uniqueIdentifier eq "" )
    {
      next;
    }
    
    my $CC=substr($uniqueIdentifier,6,3);
    my $SN=substr($uniqueIdentifier,0,6);
    
    my $IDs="";
    if($DEV == 1)
    {
      $IDs=`./id -u $gsauid`;
      $IDs=trim($IDs);
    }
    else
    {
      $IDs=`id -u $gsauid`;
      $IDs=trim($IDs);
    }
    
    my $GROUPID="";
    if($DEV == 1)
    {
      $GROUPID=`./id -g $gsauid`;
      $GROUPID=trim($GROUPID);
    }
    else
    {
      $GROUPID=`id -g $gsauid`;
      $GROUPID=trim($GROUPID);
    }
    
    print LDAP_PASSWD_FILE "$gsauid:!:$IDs:$GROUPID:$CC/I/$SN/IBM/$cn-GSA::\n";
    logDebug("getGSAuser:passwd->$gsauid:!:$IDs:$GROUPID:$CC/I/$SN/IBM/$cn-GSA::");
  }
  close LDAP_PASSWD_FILE;
}

sub collectGSAusers
{
  %MEMBERS = ();
  $gsagrouplist="";
  $GROUPBASE="";
  $PEOPLEBASE="";
    
  logDebug("collectGSAusers: started");
   
  $LDAPSVR = GSALDAP();
  
  if($LDAPSVR eq "")
  {
    logAbort("LDAP server address not found");
  }
  
  getLDAPBASE();
  
  $gsagrouplist=getFromThere($GSACONF, "^gsagroupallow\\s*(.*)\$");
  if($OSNAME =~ /linux/i && $gsagrouplist eq "")
  {
    $gsagrouplist=getFromThere($LDAPCONF, "^gsagroupallow\\s*(.*)\$");
  }
  
  if($gsagrouplist eq "")
  {
    extractSudoUsersGroups();
  }
  
  if($gsagrouplist eq "")
  {
    logAbort("Can't get GSA group list");  
  }
  
  getGSAgroup($gsagrouplist);
  getGSAuser();
  
  if($gsagrouplist ne "")
  {
    getAdditionalGroup; 
  }
  
  logDebug("collectGSAusers: finished");
  while(($key, $value) = each %MEMBERS){
    delete($MEMBERS{$key});
  };
}
