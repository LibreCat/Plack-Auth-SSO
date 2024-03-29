package Plack::Auth::SSO;

use strict;
use utf8;
use Data::Util qw(:check);
use Moo::Role;
use Data::UUID;
use Log::Any qw();

our $VERSION = "0.0137";

has session_key => (
    is       => "ro",
    isa      => sub { is_string($_[0]) or die("session_key should be string"); },
    lazy     => 1,
    default  => sub { "auth_sso" },
    required => 1
);
has authorization_path => (
    is       => "ro",
    isa      => sub { is_string($_[0]) or die("authorization_path should be string"); },
    lazy     => 1,
    default  => sub { "/"; },
    required => 1
);
has error_path => (
    is => "lazy"
);
has id => (
    is => "ro",
    lazy => 1,
    builder => "_build_id"
);
has uri_base => (
    is       => "ro",
    isa      => sub { is_string($_[0]) or die("uri_base should be string"); },
    required => 1,
    default  => sub { "http://localhost:5000"; }
);
has uuid => (
    is => "lazy",
    init_arg => undef
);
has log => (
    is => "lazy",
    init_arg => undef
);

requires "to_app";

sub _build_log {

    Log::Any->get_logger(
        category => ref($_[0])
    );

}

sub _build_uuid {

    Data::UUID->new();

}

sub _build_error_path {

    $_[0]->authorization_path;

}

sub redirect_to_authorization {

    my $self = $_[0];

    my $url  = $self->uri_for( $self->authorization_path );

    $self->log()->info( "redirecting to authorization url $url" );

    [ 302, [ Location => $url ], [] ];

}

sub redirect_to_error {

    my $self = $_[0];

    my $url  = $self->uri_for( $self->error_path );

    $self->log()->error( "redirecting to error url $url" );

    [ 302, [ Location => $url ], [] ];
}

sub uri_for {
    my ($self, $path) = @_;
    $self->uri_base() . $path;
}

sub _build_id {
    ref($_[0]);
}

#check if $env->{psgix.session} is stored Plack::Session->session
sub _check_plack_session {
    defined($_[0]->session) or die("Plack::Auth::SSO requires a Plack::Session");
}

sub get_auth_sso {
    my ($self, $session) = @_;
    _check_plack_session($session);

    my $value = $session->get($self->session_key);

    $self->log()->debugf( "extracted auth_sso from session['" . $self->session_key() . "']: %s", $value )
        if $self->log()->is_debug();

    $value;
}

sub set_auth_sso {
    my ($self, $session, $value) = @_;
    _check_plack_session($session);

    $self->log()->debugf( "session['".$self->session_key."'] set to: %s", $value )
        if $self->log()->is_debug();

    $session->set($self->session_key, $value);
}

sub get_auth_sso_error {
    my ($self, $session) = @_;
    _check_plack_session($session);

    my $value = $session->get($self->session_key()."_error");

    $self->log()->debugf( "extracted auth_sso_error from session['" . $self->session_key() . "_error']: %s", $value )
        if $self->log()->is_debug();

    $value;
}

sub set_auth_sso_error {
    my ($self, $session, $value) = @_;
    _check_plack_session($session);

    $self->log()->errorf( "session['".$self->session_key."_error'] set to: %s", $value )
        if $self->log()->is_error();

    $session->set($self->session_key . "_error", $value);
}

sub generate_csrf_token {
    $_[0]->uuid()->create_b64();
}

sub set_csrf_token {
    my ($self, $session, $value) = @_;
    _check_plack_session($session);

    $self->log()->debugf( "session['".$self->session_key."_csrf'] set to: %s", $value )
        if $self->log()->is_debug();

    $session->set($self->session_key . "_csrf" , $value);
}

sub get_csrf_token {
    my ($self, $session) = @_;
    _check_plack_session($session);

    my $value = $session->get($self->session_key . "_csrf");

    $self->log()->debugf( "extracted csrf token from session['" . $self->session_key() . "_csrf']: %s", $value )
        if $self->log()->is_debug();

    $value;
}

sub csrf_token_valid {
    my ($self, $session,$value) = @_;
    my $stored_token = $self->get_csrf_token($session);
    my $valid = defined($value) && defined($stored_token) && $value eq $stored_token;

    $self->log()->debug( "csrf validation " . ($valid ? "ok" : "failed") );

    $valid;
}

sub cleanup {

    my ( $self, $session ) = @_;

    $self->log()->debug( "removed session['" . $self->session_key() . "_error']"  );
    $self->log()->debug( "removed session['" . $self->session_key() . "_csrf']"  );

    $session->remove( $self->session_key() . "_error" );
    $session->remove( $self->session_key() . "_csrf" );

}

1;

=pod

=head1 NAME

Plack::Auth::SSO - role for Single Sign On (SSO) authentication

=begin markdown

# STATUS

[![Build Status](https://travis-ci.org/LibreCat/Plack-Auth-SSO.svg?branch=master)](https://travis-ci.org/LibreCat/Plack-Auth-SSO)
[![Coverage](https://coveralls.io/repos/LibreCat/Plack-Auth-SSO/badge.png?branch=master)](https://coveralls.io/r/LibreCat/Plack-Auth-SSO)
[![CPANTS kwalitee](http://cpants.cpanauthors.org/dist/Plack-Auth-SSO.png)](http://cpants.cpanauthors.org/dist/Plack-Auth-SSO)

=end markdown

=head1 IMPLEMENTATIONS

=over 4

=item SSO for Central Authentication System (CAS): L<Plack::Auth::SSO::CAS>

=item SSO for ORCID: L<Plack::Auth::SSO::ORCID>

=item SSO for Shibboleth: L<Plack::Auth::SSO::Shibboleth>

=back

=head1 SYNOPSIS

    package MySSOAuth;

    use Moo;
    use Data::Util qw(:check);

    with "Plack::Auth::SSO";

    sub to_app {

        my $self = shift;

        sub {

            my $env = shift;
            my $request = Plack::Request->new($env);
            my $session = Plack::Session->new($env);

            #did this app already authenticate you?
            #implementation of Plack::Auth::SSO should write hash to session key,
            #configured by "session_key"
            my $auth_sso = $self->get_auth_sso($session);

            #already authenticated: what are you doing here?
            if( is_hash_ref($auth_sso) ){

                return [ 302, [ Location => $self->uri_for($self->authorization_path) ], [] ];

            }

            #not authenticated: do your internal work
            #..

            #authentication done in external application code, but here something went wrong..
            unless ( $ok ) {

                #error is set in auth_sso_error..
                $self->set_auth_sso_error(
                    $session,
                    {
                        package => __PACKAGE__,
                        package_id => $self->id,
                        type => "connection_failed",
                        content => ""
                    }
                );

                #user is redirected to error_path
                return [ 302, [ Location => $self->uri_for($self->error_path) ], [] ];

            }

            #everything ok: set auth_sso
            $self->set_auth_sso(
                $session,
                {
                    package => __PACKAGE__,
                    package_id => $self->id,
                    response => {
                        content => "Long response from external SSO application",
                        content_type => "text/xml"
                    },
                    uid => "<uid>",
                    info => {
                        attr1 => "attr1",
                        attr2 => "attr2"
                    },
                    extra => {
                        field1 => "field1"
                    }
                }
            );

            #redirect to other application for authorization:
            return [ 302, [ Location => $self->uri_for($self->authorization_path) ], [] ];

        };
    }

    1;


    #in your app.psgi

    builder {

        mount "/auth/myssoauth" => MySSOAuth->new(

            session_key => "auth_sso",
            authorization_path => "/auth/myssoauth/callback",
            uri_base => "http://localhost:5001",
            error_path => "/auth/error"

        )->to_app;

        mount "/auth/myssoauth/callback" => sub {

            my $env = shift;
            my $session = Plack::Session->new($env);
            my $auth_sso = $session->get("auth_sso");

            #not authenticated yet
            unless($auth_sso){

                return [ 403, ["Content-Type" => "text/html"], ["forbidden"] ];

            }

            #process auth_sso (white list, roles ..)

            [ 200, ["Content-Type" => "text/html"], ["logged in!"] ];

        };

        mount "/auth/error" => sub {

            my $env = shift;
            my $session = Plack::Session->new($env);
            my $auth_sso_error = $session->get("auth_sso_error");

            unless ( $auth_sso_error ) {

                return [ 302, [ Location => $self->uri_for( "/" ) ], [] ];

            }

            [ 200, [ "Content-Type" => "text/plain" ], [
                $auth_sso_error->{content}
            ]];

        };

    };

=head1 DESCRIPTION

This is a Moo::Role for all Single Sign On Authentication packages. It requires
C<to_app> method, that returns a valid Plack application

An implementation is expected is to do all communication with the external
SSO application (e.g. CAS). When it succeeds, it should save the response
from the external service in the session, and redirect to the authorization
url (see below).

The authorization route must pick up the response from the session,
and log the user in.

This package requires you to use Plack Sessions.

=head1 CONSTRUCTOR ARGUMENTS

=over 4

=item C<< session_key >>

When authentication succeeds, the implementation saves the response
from the SSO application in this session key, together with extra information.

The response should look like this:

    {
        package => "<package-name>",
        package_id => "<package-id>",
        response => {
            content => "Long response from external SSO application like CAS",
            content_type => "<mime-type>"
        },
        uid => "<uid-in-external-app>",
        info => {
            attr1 => "attr1",
            attr2 => "attr2"
        },
        extra => {
            field1 => "field1"
        }
    }

This is usefull for several reasons:

=over 6

=item the authorization application can distinguish between authenticated and not authenticated users

=item it can pick up the saved response from the session

=item it can lookup a user in an internal database, matching on the provided "uid" from the external service.

=item the key "package" tells which package authenticated the user; so the application can do an appropriate lookup based on this information.

=item the key "package_id" defaults to the package name, but is configurable. This is usefull when you have several external services of the same type, and your application wants to distinguish between them.

=item the original response is stored as text, along with the content type.

=item other attributes stored in the hash reference "info". It is up to the implementing package whether it should only used attributes as pushed during the authentication step (like in CAS), or do an extra lookup.

=item "extra" should be used to store request information. e.g. "ORCID" gives a "token". e.g. "Shibboleth" supplies the "Shib-Identity-Provider".

=back

=item C<< authorization_path >>

(internal) path of the authorization route. This path will be prepended by "uri_base" to
create the full url.

When authentication succeeds, this application should redirect you here

=item C<< error_path >>

(internal) path of the error route. This path will be prepended by "uri_base" to
create the full url.

When authentication fails, this application should redirect you here

If not set, it has the same value as the authorizaton_path. In that case make sure that you also

check for auth_sso_error in your authorization route.

The implementor should expect this in the session key "auth_sso_error" ( "_error" is appended to the configured session_key ):

    {
        package => "Plack::Auth::SSO::TYPE",
        package_id => "Plack::Auth::SSO::TYPE",
        type => "my-error-type",
        content => "Something went terribly wrong!"
    }

Error types should be documented by the implementor.


=item C<< id >>

identifier of the authentication module. Defaults to the package name.
This is handy when using multiple SSO instances, and you need to known
exactly which package authenticated the user.

This is stored in "auth_sso" as "package_id".

=item C<< uri_base >>

base url of the Plack application

Required

=back

=head1 METHODS

=over 4

=item C<< uri_for( path ) >>

method that prepends your path with "uri_base".

=item C<< log >>

logger instance. Object instance of class L<Log::Any::Proxy> that logs messages
to a category that equals your current class name.

E.g. configure your logging in log4perl.conf:

    log4perl.category.Plack::Auth::SSO::CAS=INFO,STDERR
    log4perl.appender.STDERR=Log::Log4perl::Appender::Screen
    log4perl.appender.STDERR.stderr=1
    log4perl.appender.STDERR.utf8=1
    log4perl.appender.STDERR.layout=PatternLayout
    log4perl.appender.STDERR.layout.ConversionPattern=%d %p [%P] - %c[%L] : %m%n

See L<Log::Any> for more information

=item C<< to_app >>

returns a Plack application

This must be implemented by subclasses

=item C<< get_auth_sso($plack_session) : $hash >>

get saved SSO response from your session

=item C<< set_auth_sso($plack_session, $hash) >>

save SSO response to your session

$hash should be a hash ref, and look like this:

    {
        package => __PACKAGE__,
        package_id => __PACKAGE__ ,
        response => {
            content => "Long response from external SSO application like CAS",
            content_type => "<mime-type>",
        },
        uid => "<uid>",
        info => {},
        extra => {}
    }

=item C<< get_auth_sso_error($plack_session) : $hash >>

get saved SSO error response from your session

=item C<< set_auth_sso_error($plack_session, $hash) >>

save SSO error response to your session

$hash should be a hash ref, and look like this:

    {
        package => __PACKAGE__,
        package_id => __PACKAGE__ ,
        type => "my-type",
        content => "my-content"
    }

=item C<< generate_csrf_token() >>

Generate unique CSRF token. Store this token in your session, and supply it as parameter
to the redirect uri.

=item C<< set_csrf_token($session, $token) >>

Save csrf token to the session

The token is saved in key session_key + "_csrf"

=item C<< get_csrf_token($session): $string >>

Retrieve csrf token from the session

=item C<< csrf_token_valid($session,$token) : $boolean >>

Compare supplied token with stored token

=item C<< cleanup($session) >>

removes additional session keys like C<< auth_sso_error >> and C<< auth_sso_csrf >>
before redirecting to the authorization path.

implementations should supply an override when they
want to remove additional keys:

    around cleanup => sub {

        my ($orig, $self, $session) = @_;
        $self->$orig($session);
        $session->remove("auth_sso_my_implementation_temporary_attr");

    };

=back

=head1 EXAMPLES

See examples/app1:

    #copy example config to required location
    $ cp examples/catmandu.yml.example examples/catmandu.yml

    #edit config
    $ vim examples/catmandu.yml

    #start plack application
    plackup examples/app1.pl

=head1 AUTHOR

Nicolas Franck, C<< <nicolas.franck at ugent.be> >>

=head1 LICENSE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.

=head1 SEE ALSO

L<Plack::Auth::SSO::CAS>
L<Plack::Auth::SSO::ORCID>
L<Plack::Auth::SSO::Shibboleth>
L<Log::Any>

=cut
