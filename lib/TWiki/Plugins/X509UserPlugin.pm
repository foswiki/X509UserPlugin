# Plugin for TWiki Collaboration Platform, http://TWiki.org/
#
# Copyright (C) 2000-2003 Andrea Sterbini, a.sterbini@flashnet.it
# Copyright (C) 2001-2004 Peter Thoeny, peter@thoeny.com
# Copyright (C) 2005-2008 Timothe Litt, litt@acm.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details, published at 
# http://www.gnu.org/copyleft/gpl.html
#
# =========================
#
# This plugin supports certificate-based authentication & identification
#
# The actual user mapping and password management functions are handled by
# X509UserMapping:: and X509PasswdUser:: respectively.
#
# This plugin simply makes the fields of the DN available as TWiki variables.
#
# Each element of the DN is accessible using its element name using
# the element method of X509UserMapping::Cert::.
#
# Early prototypes were based on FakeBasicAuthRegPlugin.
#
# =========================
package TWiki::Plugins::X509UserPlugin;

# Always use strict to enforce variable scoping
use strict;

require TWiki::Func;    # The plugins API
require TWiki::Plugins; # For the API version

# =========================
# $VERSION is referred to by TWiki, and is the only global variable that
# *must* exist in this package.
use vars qw( $VERSION $RELEASE $SHORTDESCRIPTION $debug $pluginName $NO_PREFS_IN_TOPIC );

# This should always be $Rev: 15942 (11 Aug 2008) $ so that TWiki can determine the checked-in
# status of the plugin. It is used by the build automation tools, so
# you should leave it alone.
$VERSION = '$Rev: 15942 (11 Aug 2008) $';

# This is a free-form string you can use to "name" your own plugin version.
# It is *not* used by the build automation tools, but is reported as part
# of the version number in PLUGINDESCRIPTIONS.
$RELEASE = 'V1.0-3';

# Short description of this plugin
# One line description, is shown in the %TWIKIWEB%.TextFormattingRules topic:
$SHORTDESCRIPTION = 'X509 Authentication support, used by TWiki Administrators';

# Do not parse plugin topic for preferences

$NO_PREFS_IN_TOPIC = 1;

$pluginName = 'X509UserPlugin';

use TWiki::Users::X509UserMapping::Cert;

=pod

---++ initPlugin($topic, $web, $user, $installWeb) -> $boolean
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
   * =$user= - the login name of the user
   * =$installWeb= - the name of the web the plugin is installed in

REQUIRED

Called to initialise the plugin. If everything is OK, should return
a non-zero value. On non-fatal failure, should write a message
using TWiki::Func::writeWarning and return 0. In this case
%FAILEDPLUGINS% will indicate which plugins failed.

In the case of a catastrophic failure that will prevent the whole
installation from working safely, this handler may use 'die', which
will be trapped and reported in the browser.


=cut

sub initPlugin
{
    my( $topic, $web, $user, $installWeb ) = @_;

    # check for Plugins.pm versions
    if( $TWiki::Plugins::VERSION < 1.2 ) {
        TWiki::Func::writeWarning( "Version mismatch between $pluginName and Plugins.pm" );
        return 0;
    }
    # Get plugin debug flag
    $debug = $TWiki::cfg{Plugins}{X509UserPlugin}{Debug} || 0;

    die "X509 User Mapping Manager is required by X509UerPlugin, but is not loaded." if( $TWiki::cfg{UserMappingManager} !~ /X509/ );

    TWiki::Func::registerTagHandler( 'X509', \&_X509TAG );

    # Plugin correctly initialized
    TWiki::Func::writeDebug( "- TWiki::Plugins::${pluginName}::initPlugin( $web.$topic ) is OK" ) if $debug;
    return 1;
}


=pod

---++ earlyInitPlugin()

This handler is called before any other handler, and before it has been
determined if the plugin is enabled or not. Use it with great care!

If it returns a non-null error string, the plugin will be disabled.

=cut

sub DISABLED_earlyInitPlugin
{

    return undef;
}

=pod

---++ initializeUserHandler( $loginName, $url, $pathInfo )
   * =$loginName= - login name recovered from $ENV{REMOTE_USER}
   * =$url= - request url
   * =$pathInfo= - pathinfo from the CGI query
Allows a plugin to set the username. Normally TWiki gets the username
from the login manager. This handler gives you a chance to override the
login manager.

Return the *login* name.

This handler is called very early, immediately after =earlyInitPlugin=.

*Since:* TWiki::Plugins::VERSION = '1.010'

=cut

sub initializeUserHandler
{
### my ( $loginName, $url, $pathInfo ) = @_;   # do not uncomment, use $_[0], $_[1]... instead

#    TWiki::Func::writeDebug( "- ${pluginName}::initializeUserHandler( $_[0], $_[1] )" ) if $debug;

    # Make sure that we have an HTTPs connection and a certificate.
    # This requires SSL
    # SSLOptions +StdEnvVars
    #
    # You probably also want
    # SSLOptions +FakeBasicAuth 
    # SSLVerifyClient require
    #
    # Determine the username from the client certificate
    #

    return "" if( !$_[0] );

    return $_[0] if( $_[0] !~ m|^/[\w]+=| );  # Check for and X.509 name: /XX=

    # Require a verified certificate - unless a command
    return TWiki::Func::getDefaultUserName() unless( TWiki::Func::getContext()->{command_line} || defined $ENV{'SSL_CLIENT_VERIFY'} && $ENV{'SSL_CLIENT_VERIFY'} eq 'SUCCESS' );


    return $_[0];
}

=pod

---++ registrationHandler($web, $wikiName, $loginName )
   * =$web= - the name of the web in the current CGI query
   * =$wikiName= - users wiki name
   * =$loginName= - users login name

Called when a new user registers with this TWiki.

*Since:* TWiki::Plugins::VERSION = '1.010'

=cut

sub DISABLED_registrationHandler
{
#    my ( $web, $wikiName, $loginName ) = @_;   # do not uncomment, use $_[0], $_[1]... instead

#    TWiki::Func::writeDebug( "- ${pluginName}::registrationHandler( $_[0], $_[1] )" ) if $debug;


}

=pod 

---++ _X509TAG
    * $session  - a reference to the TWiki session object 
    * =$params=  - a reference to a TWiki::Attrs object containing parameters.
                 This is a simple hash that maps parameter names
                 to values, with _DEFAULT being the name for the default
                 parameter.
    * =$theTopic= - name of the topic in the query
    * =$theWeb=   - name of the web in the query
     Return: the result of processing the variable

=cut

sub _X509TAG {
    my($session, $params, $theTopic, $theWeb) = @_;

    my $regtopic = $TWiki::cfg{Plugins}{X509UserPlugin}{RegistrationTopic} || 'TWikiRegistration';
    my $regweb = TWiki::Func::getMainWebname();
    unless( TWiki::Func::topicExists($regweb, $regtopic ) ){
	$regweb = TWiki::Func::getTwikiWebname();
    }

    unless( $debug || ( $theTopic eq $regtopic && $theWeb eq $regweb )
	           || TWiki::Func::checkAccessPermission( 'CHANGE', TWiki::Func::getWikiUserName(undef), undef, $regtopic, $regweb, undef ) ) {
	return "%<NOP>X509% not permitted on this topic"
    }

    my $element = $params->{element} || $params->{_DEFAULT};
    my $remove = $params->{remove};
    my $replace = $params->{replace} || "";

    TWiki::Func::writeDebug( "- TWiki::Plugins::${pluginName}::_X509TAG( $theWeb.$theTopic ) %X509{" . join( ", ", map { "$_=$params->{$_}" } (keys %$params) ) . "}%" ) if $debug;

    my $from = 'SSL_CLIENT_S';

    if( $params->{from} ) {
	if( $params->{from} eq 'issuer' ) {
	    $from = 'SSL_CLIENT_I';
	} elsif( $params->{from} eq 'user' ) {
	    $from = 'SSL_CLIENT_S';
	}
    }
    
    my $value;
    if( $element ) {
	# %X509{ DNfield login="" remove="" replace="" }%
	my $cert = $params->{login} ||  $ENV{"${from}_DN"} || "";

	$cert = TWiki::Users::X509UserMapping::Cert->parseDN( $cert );

	$value = $cert->element( $element );
    } elsif( $params->{getloginname} ) {
	# %X509{ getloginname="1" login="" remove="" replace="" }%

	$value = $params->{login} ||  $ENV{"${from}_DN"} || "";
    } elsif( $params->{getcert} ) {
	# %X509{ getcert="component" remove="" replace="" }% (e.g. C => country code)
	$value = $ENV{"${from}_DN_".$params->{getcert}} || "";
    } elsif( $params->{getwikiname} ) {
	# %X509{ getwikiname="1" login="" remove="" replace="" }%

	$value = $params->{login} ||  $ENV{"${from}_DN"} || "";

	$value = $session->{users}->{mapping}->wikinameFromDN( $value );
    } else {
	$value = "%X509: Unrecognized request{" . join( ", ", map { "$_=$params->{$_}" } (keys %$params) ) . "}%" 
    }
    
    if( defined $remove ) {
	TWiki::Func::writeDebug( "- TWiki::Plugins::${pluginName}::_X509TAG( $theWeb.$theTopic ) |$element|$value|$remove|$replace|" ) if $debug;
	  eval ( "\$value =~ s/$remove/$replace/g;" );
	  $value = "X509: eval failed: $@.  Check \$remove= and \$replace= parameters" if( $@ );
      }
    TWiki::Func::writeDebug( "- TWiki::Plugins::${pluginName}::_X509TAG( $theWeb.$theTopic ) value is \"$value\"" ) if $debug;

    return $value;
}
=pod

---++ commonTagsHandler($text, $topic, $web, $included, $meta )
   * =$text= - text to be processed
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
   * =$included= - Boolean flag indicating whether the handler is invoked on an included topic
   * =$meta= - meta-data object for the topic MAY BE =undef=
This handler is called by the code that expands %<nop>TAGS% syntax in
the topic body and in form fields. It may be called many times while
a topic is being rendered.

For variables with trivial syntax it is far more efficient to use
=TWiki::Func::registerTagHandler= (see =initPlugin=).

Plugins that have to parse the entire topic content should implement
this function. Internal TWiki
variables (and any variables declared using =TWiki::Func::registerTagHandler=)
are expanded _before_, and then again _after_, this function is called
to ensure all %<nop>TAGS% are expanded.

__NOTE:__ when this handler is called, &lt;verbatim> blocks have been
removed from the text (though all other blocks such as &lt;pre> and
&lt;noautolink> are still present).

__NOTE:__ meta-data is _not_ embedded in the text passed to this
handler. Use the =$meta= object.

*Since:* $TWiki::Plugins::VERSION 1.000

=cut

sub DISABLED_commonTagsHandler
{
### my ( $text, $topic, $web, $included, $meta ) = @_;   # do not uncomment, use $_[0], $_[1]... instead

#    TWiki::Func::writeDebug( "- ${pluginName}::commonTagsHandler( $_[2].$_[1] )" ) if $debug;

    return undef;
}

1;
