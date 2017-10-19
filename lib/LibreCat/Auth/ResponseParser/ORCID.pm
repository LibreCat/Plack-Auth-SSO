package LibreCat::Auth::ResponseParser::ORCID;

use Catmandu::Sane;
use Moo;
use namespace::clean;

our $VERSION = "0.01";

with "LibreCat::Auth::ResponseParser";

sub parse {

    my ( $self, $obj ) = @_;

    +{
        uid => $obj->{orcid},
        info => {
            name => $obj->{name}
        }
    };

}

1;
