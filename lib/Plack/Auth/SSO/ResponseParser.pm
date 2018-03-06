package Plack::Auth::SSO::ResponseParser;

use Catmandu::Sane;
use Moo::Role;

our $VERSION = "0.012";

with "Catmandu::Logger";

requires "parse";

1;
