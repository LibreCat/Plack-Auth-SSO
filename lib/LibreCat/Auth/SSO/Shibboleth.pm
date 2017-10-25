package LibreCat::Auth::SSO::Shibboleth;

use Catmandu::Sane;
use Catmandu::Util qw(:check :is array_includes);
use Moo;
use Plack::Request;
use Plack::Session;
use JSON;
use namespace::clean;

our $VERSION = "0.01";

with "LibreCat::Auth::SSO";

#cf. https://github.com/toyokazu/omniauth-shibboleth/blob/master/lib/omniauth/strategies/shibboleth.rb

has request_type => (
    is => "ro",
    isa => sub {
        array_includes([qw(env header)],$_[0]) or die("request_type must be either 'env' or 'header'");
    },
    lazy => 1,
    default => sub { "env"; }
);
has shib_session_id_field => (
    is => "ro",
    isa => sub { check_string($_[0]); },
    lazy => 1,
    default => sub { "Shib-Session-ID"; }
);
has shib_application_id_field => (
    is => "ro",
    isa => sub { check_string($_[0]); },
    lazy => 1,
    default => sub { "Shib-Application-ID"; }
);
has uid_field => (
    is => "ro",
    isa => sub { check_string($_[0]); },
    lazy => 1,
    default => sub { "eppn"; }
);
has info_fields => (
    is => "ro",
    isa => sub { check_array_ref($_[0]); },
    lazy => 1,
    default => sub { []; }
);

#cf. https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess
my @other_shib_fields = qw(
    Shib-Identity-Provider
    Shib-Authentication-Instant
    Shib-Authentication-Method
    Shib-AuthnContext-Class
    Shib-AuthnContext-Decl
    Shib-Handler
);

sub request_param {
    my ( $self, $env, $key ) = @_;

    if ( $self->request_type eq "env" ) {

        return $env->{$key};

    }

    $key = uc($key);
    $key =~ tr/-/_/;
    $env->{"HTTP_${key}"};

}

sub to_app {
    my $self = $_[0];
    sub {

        state $json = JSON->new()->utf8(1);

        my $env = $_[0];

        my $request = Plack::Request->new($env);
        my $session = Plack::Session->new($env);

        my $auth_sso = $self->get_auth_sso($session);

        #already got here before
        if (is_hash_ref($auth_sso)) {

            return [
                302, [Location => $self->uri_for($self->authorization_path)],
                []
            ];

        }

        #Shibboleth Session active?
        my $shib_session_id = $self->request_param( $env, $self->shib_session_id_field );
        my $shib_application_id = $self->request_param( $env, $self->shib_application_id_field );
        my $uid = $self->request_param( $env, $self->uid_field );

        unless ( is_string( $shib_session_id ) && is_string( $shib_application_id ) && is_string($uid) ) {

            return [
                401, [ "Content-Type" => "text/plain" ], [ "Unauthorized" ]
            ];

        }

        my $info = +{};
        for my $info_field ( @{ $self->info_fields() } ) {
            $info->{$info_field} = $self->request_param( $env, $info_field );
        }

        my $extra = +{
            "Shib-Session-ID" => $shib_session_id,
            "Shib-Application-ID" => $shib_application_id
        };
        for my $shib_field ( @other_shib_fields ) {
            $extra->{$shib_field} = $self->request_param( $env, $shib_field );
        }

        my $content = +{};
        for my $header ( keys %$env ) {
            next if index( $header, "psgi." ) == 0;
            $content->{$header} = $env->{$header};
        }

        $self->set_auth_sso(
            $session,
            {
                uid => $uid,
                info => $info,
                extra => $extra,
                package    => __PACKAGE__,
                package_id => $self->id,
                response   => {
                    content => $json->encode($content),
                    content_type => "application/json"
                }
            }
        );

        return [
            302,
            [Location => $self->uri_for($self->authorization_path)],
            []
        ];



    };
}

1;

=pod

=head1 NAME

LibreCat::Auth::SSO::Shibboleth - implementation of LibreCat::Auth::SSO for Shibboleth

=head1 SYNOPSIS

=head1 DESCRIPTION

This is an implementation of L<LibreCat::Auth::SSO> to authenticate behind a Shibboleth Service Provider (SP)

It inherits all configuration options from its parent.

=head1 CONFIG

=head1 AUTHOR

Nicolas Franck, C<< <nicolas.franck at ugent.be> >>

=head1 SEE ALSO

L<LibreCat::Auth::SSO>

=cut
