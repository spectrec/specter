use strict;
use warnings;

use EV;
use Socket;
use AnyEvent;
use AnyEvent::Log;
use AnyEvent::Socket;
use AnyEvent::Handle;

use Data::Dumper;
use Scalar::Util qw(refaddr);

my $__port = 5432;
my $cv = AnyEvent->condvar();

sub CMD_PUT() { 1 }
sub CMD_GET() { 2 }

sub PING_EACH() { 5 } # seconds

my %AE_HANDLES;
my %SERVERS_INFO;

my %HANDLERS = (
	CMD_PUT() => sub {
		my $size = 6;
		my $format = 'Nn';

		shift->push_read(chunk => $size, sub {
			my ($self, $data) = @_;

			my ($host_p, $port_p) = unpack $format, $data;

			my $host = pack 'N', $host_p;
			my $port = pack 'n', $port_p;

			my $text_ip = inet_ntoa $host;
			AE::log debug => "got CMD_PUT()";
			if (not $text_ip) {
				AE::log error => 'got invlid ip address';
				return safe_destroy($self);
			}

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
		shift->push_read(chunk => 1, sub {
			my ($self, $data) = @_;

			my @keys = keys %SERVERS_INFO;
			my $count = unpack 'C', $data;
			my @indexes = map { int(rand(@keys)) } 1 .. $count;

			return safe_destroy($self)
				unless @keys;

			foreach my $idx (@indexes) {
				my $key = $keys[$idx];
				my $info = $SERVERS_INFO{ $key };

				$self->push_write($info->{host});
				$self->push_write($info->{port});
			}

			$self->on_drain(\&safe_destroy);
			AE::log info => 'hosts sent';
		});
	}
);

sub terminate_server { $cv->send() }

$AnyEvent::Log::FILTER->level('debug');
AnyEvent->signal(signal => 'TERM', cb => \&terminate_server);
AnyEvent->signal(signal => 'QUIT', cb => \&terminate_server);
AnyEvent->signal(signal => 'INT',  cb => \&terminate_server);

sub safe_destroy
{
	my $self = shift;

	AE::log info => 'Conn closed';
	delete $AE_HANDLES{ refaddr $self };
	$self->destroy();

	return;
}

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
