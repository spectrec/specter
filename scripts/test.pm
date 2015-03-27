use strict;
use warnings;

use EV;
use Socket;
use AnyEvent;
use AnyEvent::Log;
use AnyEvent::Handle;
use AnyEvent::Socket;

my $cv = AnyEvent->condvar();
$AnyEvent::Log::FILTER->level('debug');

my $handle;
tcp_connect('127.0.0.1', 7777, sub {
	my $fh = shift;

	if (not $fh) {
		AE::log warn => "connect failed: $!";
		return $cv->send();
	}

	$handle = AnyEvent::Handle->new(
		fh => $fh,
		on_error => sub {
			my ($self, undef, $msg) = @_;

			AE::log error => $msg;
			$self->destroy();
			$cv->send();
		},
		on_eof => sub {
			AE::log warn => 'conn closed';
			shift->destroy();
			$cv->send();
		},
		on_read => sub {
			shift->push_read(chunk => 6, sub {
				my ($self, $data) = @_;

				my ($host_p, $port_p) = unpack 'Nn', $data;
				my $host = inet_ntoa(pack 'N', $host_p);

				AE::log debug => "received $host:$port_p";
			});

			AE::log info => 'got response';
		},
	);

	$handle->push_write(pack 'C5n', 1, 127,0,0,1, 1665);
	$handle->push_write(pack 'C5n', 1, 213,180,204,3, 80); # ya.ru
	$handle->push_write(pack 'Cn',  2, 2);
});

$cv->recv();
