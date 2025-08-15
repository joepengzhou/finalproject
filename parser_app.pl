use Mojolicious::Lite -signatures;

# --- CORS Preflight Handling ---
# This route specifically handles the browser's preflight OPTIONS request.
options '/parse' => sub ($c) {

    # Set the required headers to grant permission for the actual POST request
    $c->res->headers->header( 'Access-Control-Allow-Origin' => '*' );
    $c->res->headers->header(
        'Access-Control-Allow-Methods' => 'POST, OPTIONS' );
    $c->res->headers->header(
        'Access-Control-Allow-Headers' => 'Content-Type' );

# Respond with "204 No Content" to tell the browser the preflight was successful
    $c->render( status => 204, text => '' );
};

# Preflight for /report as well
options '/report' => sub ($c) {
    $c->res->headers->header( 'Access-Control-Allow-Origin' => '*' );
    $c->res->headers->header( 'Access-Control-Allow-Methods' => 'POST, OPTIONS' );
    $c->res->headers->header( 'Access-Control-Allow-Headers' => 'Content-Type' );
    $c->render( status => 204, text => '' );
};

# --- Main API Logic ---
# This route handles the actual data parsing.
post '/parse' => sub ($c) {

    # The actual response must also include the Allow-Origin header
    $c->res->headers->header( 'Access-Control-Allow-Origin' => '*' );

    # Get the JSON data sent from the JavaScript
    my $data = $c->req->json;

    my @results;

    # Loop through the array of domain names
    foreach my $line ( @{ $data->{captured_data} } ) {

        # Use a regex to find valid-looking domain names
        if ( $line =~ /([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,61}\.[a-zA-Z]{2,})/ ) {
            push @results, $1;
        }
    }

    # Send the final parsed data back as JSON
    $c->render( json => { parsed_results => \@results } );
};

# --- Report Generation for Vulnerability Scanner ---
use Mojo::JSON qw(decode_json encode_json);
use File::Basename qw(dirname);
use File::Spec;
use Time::Piece;

helper _severity_rank => sub ($c, $sev) {
  my %rank = (
    info => 0, low => 1, medium => 2, high => 3, critical => 4
  );
  return exists $rank{$sev} ? $rank{$sev} : 0;
};

sub _load_latest_log {
  my $base_dir = dirname(__FILE__);
  my $log_dir = File::Spec->catdir($base_dir, 'logs');
  opendir(my $dh, $log_dir) or return undef;
  my @files = grep { /^scan-.*\.json$/ && -f File::Spec->catfile($log_dir, $_) } readdir($dh);
  closedir $dh;
  return undef unless @files;
  @files = sort @files;
  my $latest = $files[-1];
  my $path = File::Spec->catfile($log_dir, $latest);
  open my $fh, '<:encoding(UTF-8)', $path or return undef;
  local $/ = undef;
  my $content = <$fh>;
  close $fh;
  return decode_json($content);
}

post '/report' => sub ($c) {
  $c->res->headers->header('Access-Control-Allow-Origin' => '*');

  my $data = $c->req->json || {};
  my $severity_filter = $c->param('severity') || $data->{severity} || 'info';
  my $min_rank = $c->_severity_rank(lc $severity_filter);

  my $scan = $data->{scan} || undef;

  if (!$scan && $data->{log_path}) {
    eval {
      open my $fh, '<:encoding(UTF-8)', $data->{log_path} or die $!;
      local $/ = undef;
      my $content = <$fh>;
      close $fh;
      $scan = decode_json($content);
    };
  }

  if (!$scan) {
    $scan = _load_latest_log();
  }

  return $c->render(status => 400, json => { error => 'No scan data available' })
    unless $scan && $scan->{results};

  my @open_ports = grep { ($_->{status} // '') eq 'open' } @{ $scan->{results} };

  my %vulns_by_sev = ( info => [], low => [], medium => [], high => [], critical => [] );
  for my $item (@open_ports) {
    my $vulns = $item->{vulnerabilities} // [];
    for my $v (@$vulns) {
      my $sev = lc($v->{severity} // 'info');
      push @{ $vulns_by_sev{$sev} }, {
        port => $item->{port},
        service => $item->{service},
        banner => $item->{banner},
        %$v,
      };
    }
  }

  # Apply severity filter
  my %rank = ( info => 0, low => 1, medium => 2, high => 3, critical => 4 );
  my %filtered;
  for my $sev (keys %vulns_by_sev) {
    my @kept = grep { ($rank{lc($_->{severity})} // 0) >= $min_rank } @{ $vulns_by_sev{$sev} };
    $filtered{$sev} = [ @kept ];
  }

  my %counts = map { $_ => scalar @{ $filtered{$_} } } keys %filtered;

  my $report = {
    summary => {
      target => $scan->{target},
      started_at => $scan->{started_at},
      ended_at => $scan->{ended_at},
      open_ports => scalar(@open_ports),
      vulnerabilities => \%counts,
    },
    open_ports => [ map { { port => $_->{port}, service => $_->{service} // undef, banner => $_->{banner} // undef } } @open_ports ],
    vulnerabilities_by_severity => \%filtered,
  };

  return $c->render(json => { report => $report, scan_id => $scan->{scan_id} });
};

get '/report/latest' => sub ($c) {
  $c->res->headers->header('Access-Control-Allow-Origin' => '*');
  my $scan = _load_latest_log();
  return $c->render(status => 404, json => { error => 'No logs found' }) unless $scan;
  $c->render(json => $scan);
};

# Start the Mojolicious web server
app->start;
