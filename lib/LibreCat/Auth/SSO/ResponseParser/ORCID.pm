package LibreCat::Auth::SSO::ResponseParser::ORCID;

use Catmandu::Sane;
use Catmandu::Util qw(is_string);
use JSON;
use Moo;
use namespace::clean;

our $VERSION = "0.01";

with "LibreCat::Auth::SSO::ResponseParser";

has json => (
    is => "ro",
    lazy => 1,
    builder => "_build_json",
    init_arg => undef
);

sub _build_json {
    JSON->new();
}

sub parse {

    my ( $self, $obj ) = @_;

    $obj = $self->json()->decode( $obj ) if is_string($obj);

    +{
        uid => $obj->{orcid},
        info => {
            name => $obj->{name}
        }
    };

}

1;
