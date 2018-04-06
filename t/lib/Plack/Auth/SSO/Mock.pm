package Plack::Auth::SSO::Mock;

use strict;
use utf8;
use Moo;
use Data::Util qw(:check);

with "Plack::Auth::SSO";

sub to_app {

    my $self = shift;

    sub {

        my $env = shift;

        my $session = Plack::Session->new($env);

        my $auth_sso = $self->get_auth_sso($session);

        if( is_hash_ref($auth_sso) ){

            return [ 302, [ Location => $self->uri_for($self->authorization_path) ], [] ];

        }

        $self->set_auth_sso(
            $session,
            {
                package => __PACKAGE__,
                package_id => $self->id,
                response => {
                    content => "Long response from external SSO application",
                    content_type => "text/plain"
                },
                uid => "username",
                info => {
                    attr1 => "attr1",
                    attr2 => "attr2"
                },
                extra => {
                    field1 => "field1"
                }
            }
        );

        [ 302, [ Location => $self->uri_for($self->authorization_path) ], [] ];

    };
}

1;
