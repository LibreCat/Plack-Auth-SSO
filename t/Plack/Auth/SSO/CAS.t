use strict;
use warnings FATAL => "all";
use Test::More;
use Test::Exception;
use Plack::Test;
use Plack::Builder
use Plack::Session;
use HTTP::Request::Common;
use HTTP::Cookies;
use URI::Escape qw(uri_escape);
use Dancer::Middleware:Rebase;

my $pkg;

BEGIN {
    $pkg = "Plack::Auth::SSO::CAS";
    use_ok $pkg;
}
require_ok $pkg;

dies_ok(
    sub {
        $pkg->new();
    },
    "cas_url required"
);
lives_ok(
    sub {
        $pkg->new( cas_url => "https://localhost:8443/cas" );
    },
    "lives ok"
);

$Plack::Test::Impl = "MockHTTP";
my $uri_base = "http://localhost.localhost";

my $auth;

lives_ok(sub {
    $auth = $pkg->new(
        uri_base => $uri_base,
        cas_url => "$uri_base/cas",
        authorization_path => "/login"
    );
});

my $app;

lives_ok(sub {

    my $cas_xml = <<EOF;
<?xml version="1.0"?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
    <cas:authenticationSuccess>
        <cas:user>username</cas:user>
        <cas:attributes>
            <cas:firstname>John</cas:firstname>
            <cas:lastname>Doe</cas:lastname>
            <cas:title>Mr.</cas:title>
            <cas:email>jdoe\@example.org</cas:email>
            <cas:affiliation>staff</cas:affiliation>
            <cas:affiliation>faculty</cas:affiliation>
        </cas:attributes>
        <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...</cas:proxyGrantingTicket>
    </cas:authenticationSuccess>
</cas:serviceResponse>
EOF

    $app = builder {

        enable "Session";
        enable "+Dancer::Middleware::Rebase", base => $uri_base, strip => 0;
        mount "/auth/cas" => $auth->to_app;
        mount "/cas/login" => sub{
            [ 302, [
                Location => "$uri_base/auth/cas?ticket=ticket"
            ], []];      
        };
        mount "/cas/serviceValidate" => sub {
            [200, [ "Content-Type" => "text/xml" ], [ $cas_xml ]];
        };
        mount "/login" => sub {
            my $env = shift;
            my $session = Plack::Session->new($env);

            my $auth = $session->get("auth_sso");
            if ( ref($auth) ne "HASH" ) {
                return [
                    401, [ "Content-Type" => "text/plain" ],
                    [ "not_authenticated" ]
                ];
            }
            my $uid = $auth->{uid};
            if ( $uid ne "username" ) {
                return [
                    403,
                    [ "Content-Type" => "text/plain" ],
                    [ "unauthorized" ]
                ];
            }
            $session->set( "user_id", $uid );
            [
                302,
                [ "Location" => "$uri_base/mypage" ],
                []
            ];
        };
        mount "/mypage" => sub {
            my $env = shift;

            my $session = Plack::Session->new( $env );

            my $user_id = $session->get("user_id");

            unless ( defined($user_id) && $user_id eq "username" ) {
                return [
                    403,
                    [ "Content-Type" => "text/plain" ],
                    [ "forbidden" ]
                ];
            }
        };
    };

});


done_testing;
