# NAME

Plack::Auth::SSO - role for Single Sign On (SSO) authentication

# STATUS

[![Build Status](https://travis-ci.org/LibreCat/Plack-Auth-SSO.svg?branch=master)](https://travis-ci.org/LibreCat/Plack-Auth-SSO)
[![Coverage](https://coveralls.io/repos/LibreCat/Plack-Auth-SSO/badge.png?branch=master)](https://coveralls.io/r/LibreCat/Plack-Auth-SSO)
[![CPANTS kwalitee](http://cpants.cpanauthors.org/dist/Plack-Auth-SSO.png)](http://cpants.cpanauthors.org/dist/Plack-Auth-SSO)

# IMPLEMENTATIONS

- SSO for Central Authentication System (CAS): [Plack::Auth::SSO::CAS](https://metacpan.org/pod/Plack::Auth::SSO::CAS)
- SSO for ORCID: [Plack::Auth::SSO::ORCID](https://metacpan.org/pod/Plack::Auth::SSO::ORCID)
- SSO for Shibboleth: [Plack::Auth::SSO::Shibboleth](https://metacpan.org/pod/Plack::Auth::SSO::Shibboleth)

# SYNOPSIS

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

# DESCRIPTION

This is a Moo::Role for all Single Sign On Authentication packages. It requires
`to_app` method, that returns a valid Plack application

An implementation is expected is to do all communication with the external
SSO application (e.g. CAS). When it succeeds, it should save the response
from the external service in the session, and redirect to the authorization
url (see below).

The authorization route must pick up the response from the session,
and log the user in.

This package requires you to use Plack Sessions.

# CONSTRUCTOR ARGUMENTS

- `session_key`

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

    - the authorization application can distinguish between authenticated and not authenticated users
    - it can pick up the saved response from the session
    - it can lookup a user in an internal database, matching on the provided "uid" from the external service.
    - the key "package" tells which package authenticated the user; so the application can do an appropriate lookup based on this information.
    - the key "package\_id" defaults to the package name, but is configurable. This is usefull when you have several external services of the same type, and your application wants to distinguish between them.
    - the original response is stored as text, along with the content type.
    - other attributes stored in the hash reference "info". It is up to the implementing package whether it should only used attributes as pushed during the authentication step (like in CAS), or do an extra lookup.
    - "extra" should be used to store request information. e.g. "ORCID" gives a "token". e.g. "Shibboleth" supplies the "Shib-Identity-Provider".

- `authorization_path`

    (internal) path of the authorization route. This path will be prepended by "uri\_base" to
    create the full url.

    When authentication succeeds, this application should redirect you here

- `error_path`

    (internal) path of the error route. This path will be prepended by "uri\_base" to
    create the full url.

    When authentication fails, this application should redirect you here

    If not set, it has the same value as the authorizaton\_path. In that case make sure that you also

    check for auth\_sso\_error in your authorization route.

    The implementor should expect this in the session key "auth\_sso\_error" ( "\_error" is appended to the configured session\_key ):

        {
            package => "Plack::Auth::SSO::TYPE",
            package_id => "Plack::Auth::SSO::TYPE",
            type => "my-error-type",
            content => "Something went terribly wrong!"
        }

    Error types should be documented by the implementor.

- `id`

    identifier of the authentication module. Defaults to the package name.
    This is handy when using multiple SSO instances, and you need to known
    exactly which package authenticated the user.

    This is stored in "auth\_sso" as "package\_id".

- `uri_base`

    base url of the Plack application

    Required

# METHODS

- `uri_for( path )`

    method that prepends your path with "uri\_base".

- `log`

    logger instance. Object instance of class [Log::Any::Proxy](https://metacpan.org/pod/Log::Any::Proxy) that logs messages
    to a category that equals your current class name.

    E.g. configure your logging in log4perl.conf:

        log4perl.category.Plack::Auth::SSO::CAS=INFO,STDERR
        log4perl.appender.STDERR=Log::Log4perl::Appender::Screen
        log4perl.appender.STDERR.stderr=1
        log4perl.appender.STDERR.utf8=1
        log4perl.appender.STDERR.layout=PatternLayout
        log4perl.appender.STDERR.layout.ConversionPattern=%d %p [%P] - %c[%L] : %m%n

    See [Log::Any](https://metacpan.org/pod/Log::Any) for more information

- `to_app`

    returns a Plack application

    This must be implemented by subclasses

- `get_auth_sso($plack_session) : $hash`

    get saved SSO response from your session

- `set_auth_sso($plack_session, $hash)`

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

- `get_auth_sso_error($plack_session) : $hash`

    get saved SSO error response from your session

- `set_auth_sso_error($plack_session, $hash)`

    save SSO error response to your session

    $hash should be a hash ref, and look like this:

        {
            package => __PACKAGE__,
            package_id => __PACKAGE__ ,
            type => "my-type",
            content => "my-content"
        }

- `generate_csrf_token()`

    Generate unique CSRF token. Store this token in your session, and supply it as parameter
    to the redirect uri.

- `set_csrf_token($session, $token)`

    Save csrf token to the session

    The token is saved in key session\_key + "\_csrf"

- `get_csrf_token($session): $string`

    Retrieve csrf token from the session

- `csrf_token_valid($session,$token) : $boolean`

    Compare supplied token with stored token

- `cleanup($session)`

    removes additional session keys like `auth_sso_error` and `auth_sso_csrf`
    before redirecting to the authorization path.

    implementations should supply an override when they
    want to remove additional keys:

        around cleanup => sub {

            my ($orig, $self, $session) = @_;
            $self->$orig($session);
            $session->remove("auth_sso_my_implementation_temporary_attr");

        };

# EXAMPLES

See examples/app1:

    #copy example config to required location
    $ cp examples/catmandu.yml.example examples/catmandu.yml

    #edit config
    $ vim examples/catmandu.yml

    #start plack application
    plackup examples/app1.pl

# AUTHOR

Nicolas Franck, `<nicolas.franck at ugent.be>`

# LICENSE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See [http://dev.perl.org/licenses/](http://dev.perl.org/licenses/) for more information.

# SEE ALSO

[Plack::Auth::SSO::CAS](https://metacpan.org/pod/Plack::Auth::SSO::CAS)
[Plack::Auth::SSO::ORCID](https://metacpan.org/pod/Plack::Auth::SSO::ORCID)
[Plack::Auth::SSO::Shibboleth](https://metacpan.org/pod/Plack::Auth::SSO::Shibboleth)
[Log::Any](https://metacpan.org/pod/Log::Any)
