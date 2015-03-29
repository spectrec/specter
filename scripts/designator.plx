use strict;
use warnings;

use EV;
use Socket;
use AnyEvent;
use Data::Dumper;
use AnyEvent::Log;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Crypt::OpenSSL::RSA;

use autodie qw(:all);
use Scalar::Util qw(refaddr);

sub CMD_PUT() { 1 }
sub CMD_GET() { 2 }

sub RSA_BLOCK_SIZE {}

sub PING_EACH() { 5 } # seconds

my $__port = 5432;
my $public_key = read_file('public.pem');
my $private_key = read_file('private.pem');
my $rsa_private_key = Crypt::OpenSSL::RSA->new_private_key($private_key);
$rsa_private_key->use_pkcs1_padding();

my %AE_HANDLES;
my %SERVERS_INFO;

my %HANDLERS = (
	CMD_PUT() => sub {
		my $size = 10;
		my $format = 'NnN';

		shift->push_read(chunk => $size, sub {
			my ($self, $data) = @_;

			my ($host_p, $port_p, $pub_key_size) = unpack $format, $data;

			my $host = pack 'N', $host_p;
			my $port = pack 'n', $port_p;

			my $text_ip = inet_ntoa $host;
			AE::log debug => "got CMD_PUT()";
			if (not $text_ip) {
				AE::log error => 'got invlid ip address';
				return safe_destroy($self);
			}

			$self->push_read(chunk => $pub_key_size, sub {
				my ($self, $data) = @_;
				$SERVERS_INFO{ $host . $port }->{public_key} = $data;

				$self->push_write(pack 'N', length $public_key);
				$self->push_write($public_key);
			});

			my $t = AnyEvent->timer(
				after		=> PING_EACH(),
				interval	=> PING_EACH(),
				cb => sub {
					my $text_ip = format_address $host;

					AE::log debug => "timer called $text_ip:$port_p";
					tcp_connect $text_ip, $port_p, sub {
						my $fh = shift;

						if (not $fh) {
							delete $SERVERS_INFO{ $host . $port };
							AE::log debug => 'server has gone';

							return;
						}

						AE::log debug => 'server is alive';

						close $fh;
					};
				}
			);

			$SERVERS_INFO{ $host . $port } = {
				host		=> $host,
				port		=> $port,
				timer		=> $t,
			};
		});
	},

	CMD_GET() => sub {
		shift->push_read(chunk => ($rsa_private_key->size()), sub {
			my ($self, $data) = @_;

			my $payload = $rsa_private_key->decrypt($data);
			my ($count, @key) = unpack 'nC*', $payload;

			my @keys = keys %SERVERS_INFO;
			return safe_destroy($self)
				unless @keys;

			my $session_key = {
				key => \@key,
				pos => 0,
			};

			my @indexes = map { int(rand(@keys)) } 1 .. $count;
			foreach my $idx (@indexes) {
				my $key = $keys[$idx];
				my $info = $SERVERS_INFO{ $key };

				$self->push_write(encrypt_with_session_key($session_key, $info->{host}));
				$self->push_write(encrypt_with_session_key($session_key, $info->{port}));
				$self->push_write(encrypt_with_session_key($session_key, $info->{public_key}));
			}

			$self->on_drain(\&safe_destroy);
			AE::log info => 'hosts sent';
		});
	}
);

sub encrypt_with_session_key
{
	my ($key_ref, $data) = @_;

	my @res;
	foreach my $ch (unpack 'C*', $data) {
		if ($key_ref->{pos} == scalar @{ $key_ref->{key} }) {
			$key_ref->{pos} = 0;
		}

		push @res, $ch ^ $key_ref->{key}->[ $key_ref->{pos}++ ];
	}

	return pack 'C*', @res;
}

sub safe_destroy
{
	my $self = shift;

	AE::log info => 'Conn closed';
	delete $AE_HANDLES{ refaddr $self };
	$self->destroy();

	return;
}

sub read_file
{
	open my $fh, '<', shift;
	local $/;
	return <$fh>;
}

##################################################
my $cv = AnyEvent->condvar();
$AnyEvent::Log::FILTER->level('debug');
AnyEvent->signal(signal => 'TERM', cb => \&terminate_server);
AnyEvent->signal(signal => 'QUIT', cb => \&terminate_server);
AnyEvent->signal(signal => 'INT',  cb => \&terminate_server);

sub terminate_server { $cv->send() }
tcp_server(undef, $__port, sub {
	my ($fh, $host, $port) = @_;

	AE::log info => 'accept new connection';
	my $handle = AnyEvent::Handle->new(
		fh		=> $fh,
		on_error	=> sub {
			my ($self, undef, $message) = @_;

			AE::log error => $message;
			safe_destroy($self);
		},
		on_eof		=> sub { safe_destroy(shift) },
		on_read		=> sub {
			my $self = shift;

			$self->push_read(chunk => 1, sub {
				my ($self, $data) = @_;

				my $req = unpack 'C', $data;
				if (not exists $HANDLERS{$req}) {
					AE::log error => "unknown request: `$req'";
					return safe_destroy($self);
				}

				$HANDLERS{$req}->($self, $data);
			});
		}
	);

	$AE_HANDLES{ refaddr $handle } = $handle;
});

$cv->recv();
