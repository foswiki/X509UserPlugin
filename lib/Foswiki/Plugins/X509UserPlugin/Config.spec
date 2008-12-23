# This could be in Plugins, but it seems large enough that I put it into a section of its own
#
# ---+ X509 Configuration
#
# The X509UserPlugin provides X.509 username mapping. 
# In conjunction with X509PasswdUser, X509UserMapping and X509Login, it allows users to be identified by X.509 certificate.
#
# **STRING 0**
# This isn't an option, but tells you about other configuration parameters that must be set for X509 to work properly.
$Foswiki::cfg{Plugins}{X509UserPlugin}{System} = ";
#
# **BOOLEAN EXPERT**
# Debugging mode
$Foswiki::cfg{Plugins}{X509UserPlugin}{Debug} = 0;

# ** BOOLEAN **
# Because X.509 Certificates are automatically presented by the browser (assuming your webserver is properly setup), it is convenient to automagically login every user.  Enable this option to cause authentication requests for all views except your registration page.  To force authentication for other scripts, add them to the {AuthScripts} configuration variable.

$Foswiki::cfg{Plugins}{X509UserPlugin}{ForceAuthentication} = 1;

# **BOOLEAN**
# Select this option to force a user's WikiName to be derived from his/her X.509 distingushed name.  
$Foswiki::cfg{Plugins}{X509UserPlugin}{RequireWikinameFromCertificate} = 1;

# **BOOLEAN**
# Select this option if you want users registered in the $Foswiki::cfg{UsersWebName}.$Foswiki::cfg{UsersTopicName} topic.  This is handy, but not required.
$Foswiki::cfg{Plugins}{X509UserPlugin}{RegisterInUsersTopic} = 1;

# **STRING 40**
# X.509 certificate autorities are notoriously creative when deciding how to format the user's Distinguished Name field.  This string specifies how the DN field is mapped to a wikiname at registration.  
#
# See %SYSTEMWEB%.X509UserPlugin for details of how this works.
$Foswiki::cfg{Plugins}{X509UserPlugin}{Cert2Wiki} = "^CN";

# **STRING 40 EXPERT**
# The topic name (Don't include the webname, which is either the Main or the System web) of the registration topic - UserRegistration.  Only this topic can use the X509 variable and bypass {ForceAuthentication}.  Changing and renaming this topic should be restricted to the AdminGroup.
$Foswiki::cfg{Plugins}{X509UserPlugin}{RegistrationTopic} = "UserRegistration";

# **BOOLEAN EXPERT**
# X.509 certificate names not only look like line noise, they often contain characters that will confuse Foswiki if they are placed on the Users Topic.  By default, they are omitted.  If you really want to deal with the problems, set this option.
$Foswiki::cfg{Plugins}{X509UserPlugin}{RegisterUsersWithLoginName} = 0;
