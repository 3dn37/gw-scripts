#!/usr/bin/perl
### config #################################################################
use strict;
use warnings;
use DBI;
use Time::localtime;
use Sys::Syslog;

my$log_level = 5;
my$tc = '/usr/sbin/tc';
my$int_if = 'eth3'; my$ext_if = 'ifb0'; 

my@enabled_users; my$var; my@worked_users; my%worked_users;
my$dbhost='10.10.10.20'; my$dbpass='hg3k52u235i257252b525e25y2ysEhsujx'; my$dbuser='gwReader'; my$dbase='billing';
my$dbh = DBI->connect("DBI:mysql:$dbase;host=$dbhost",$dbuser,$dbpass) || die "Could not connect to database: $DBI::errstr";

LOG(5,"start checking\n") if ($log_level >= 5);

### subprograms #################################################################
sub sql_select {
    my @ans;
    my $query="$_[0]";
    my $data = $dbh->prepare($query);
    $data->execute;
    if (not $data) {print "nothing to show\n";}

    while (my@row=$data->fetchrow_array()) {
	push(@ans,\@row);
    }
    return @ans;
}

sub LOG {
    my($command,$text)=@_;
#    return 1 if ($command > $self->{'Config'}->{'DEBUG'});
    my%level=(
	'0'     =>'LOG_EMERG',          # system is unusable
	'1'     =>'LOG_ALERT',          # action must be taken immediately
	'2'     =>'LOG_CRIT',           # critical conditions
	'3'     =>'LOG_ERR',            # error conditions
	'4'     =>'LOG_WARNING',        # warning conditions
	'5'     =>'LOG_NOTICE',         # normal, but significant, condition
	'6'     =>'LOG_INFO',           # informational message
	'7'     =>'LOG_DEBUG',          # debug-level message
    );
#    if ($self->{'Config'}->{'consoleDEBUG'}) {
#	print "$text\n";
#    }
    syslog("$level{$command}","$text");
    return 0;
}

### main #################################################################
@enabled_users = sql_select('select INET_NTOA(s.segment) as ip, t.shape, v.shape as lim from vgroups v, staff s, tarifs t where v.vg_id=s.vg_id and t.tar_id=v.tar_id and v.blocked=0;');
@worked_users = `/usr/sbin/ipset list allowed_users | sed 1,7d`;

# удаляем перевод строки
foreach (@worked_users)
{
    chomp($_);
    $worked_users{"$_"} = "$_";
}

# проверяем получили что-то из базы или нет
if (scalar(@enabled_users) == 0)
{
    $dbh->disconnect();
    LOG(3,"Could not get anyfing from database") if ($log_level >= 3);
    exit(0);
}

# разбираем полученных пользователей и включаем их в iptables
foreach $var (@enabled_users){
    # 0:ip 1:shape 2:local_shape

    my@ip;
    my@iip = split(/\./, @$var['0']);
    foreach (@iip)
    {
	push(@ip, sprintf('%02x', $_));
    }

    if (exists($worked_users{@$var['0']}))
    {
	delete ($worked_users{@$var['0']});
	LOG(7,"-= enabled ".@$var['0']." =-\n") if ($log_level >= 7);
	if (my$speed = qx[/usr/sbin/tc class show dev eth3 classid 1:$ip[2]$ip[3] | /bin/awk '{ print \$8 }'])
	{
	    chomp($speed);
	    if (@$var['2'])
	    {
		if ("$speed" ne "@$var['2']Kbit")
		{
#		    print "error! have: $speed -===- must be: @$var[2]\n";
		    # unshape
#		    LOG(7,"-= unshape ".@$var['0']." =-\n") if ($log_level >= 7);
		    system "$tc class delete dev $int_if parent 1:0 classid 1:$ip[2]$ip[3]";
		    system "$tc class delete dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3]";
		    # shape
		    LOG(7,"-= update shape ".@$var['0']." with tarif speed ".@$var['2']." =-\n") if ($log_level >= 7);
		    system "$tc class replace dev $int_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[2]kbit ceil @$var[2]kbit";
		    system "$tc class replace dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[2]kbit ceil @$var[2]kbit";
		}
	    } elsif (@$var['1']) {
		if ("$speed" ne "@$var['1']Kbit")
		{
#		    print "error! have: $speed -===- must be: @$var[1]\n";
		    # unshape
#		    LOG(7,"-= unshape ".@$var['0']." =-\n") if ($log_level >= 7);
		    system "$tc class delete dev $int_if parent 1:0 classid 1:$ip[2]$ip[3]";
		    system "$tc class delete dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3]";
		    # shape
		    LOG(7,"-= update shape ".@$var['0']." with hand speed ".@$var['1']." =-\n") if ($log_level >= 7);
		    system "$tc class replace dev $int_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[1]kbit ceil @$var[1]kbit";
		    system "$tc class replace dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[1]kbit ceil @$var[1]kbit";
		}
	    } else {
		if ($speed)
		{
#		    print "error! have: $speed -===- must be: @$var[1]\n";
		    LOG(7,"-= update unshape ".@$var['0']." =-\n") if ($log_level >= 7);
		    system "$tc class delete dev $int_if parent 1:0 classid 1:$ip[2]$ip[3]";
		    system "$tc class delete dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3]";
		}
	    }
	} else {
#	    print "must here: $speed -===- new: @$var[1]\n";
	    if (@$var['2'])
	    {
		if ("$speed" ne "@$var['2']Kbit")
		{
#		    print "error! have: $speed -===- must be: @$var[2]\n";
		    # shape
		    LOG(7,"-= update shape ".@$var['0']." with tarif speed ".@$var['2']." =-\n") if ($log_level >= 7);
		    system "$tc class replace dev $int_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[2]kbit ceil @$var[2]kbit";
		    system "$tc class replace dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[2]kbit ceil @$var[2]kbit";
		}
	    } elsif (@$var['1']) {
		if ("$speed" ne "@$var['1']Kbit")
		{
#		    print "error! have: $speed -===- must be: @$var[1]\n";
		    # shape
		    LOG(7,"-= update shape ".@$var['0']." with hand speed ".@$var['1']." =-\n") if ($log_level >= 7);
		    system "$tc class replace dev $int_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[1]kbit ceil @$var[1]kbit";
		    system "$tc class replace dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[1]kbit ceil @$var[1]kbit";
		}
	    }
	}
    } else {
#	my@ip;
#	my@iip = split(/\./, @$var['0']);
#	foreach (@iip)
#	{
#	    push(@ip, sprintf('%02x', $_));
#	}

	LOG(5,"-= enable ".@$var['0']." =-\n") if ($log_level >= 5);
	system "/usr/sbin/ipset add allowed_users @$var[0]";

	if (@$var['2'])
	{
	    # unshape
	    LOG(7,"-= unshape ".@$var['0']." =-\n") if ($log_level >= 7);
	    system "$tc class delete dev $int_if parent 1:0 classid 1:$ip[2]$ip[3]";
	    system "$tc class delete dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3]";
	    # shape
	    LOG(7,"-= shape ".@$var['0']." with tarif speed ".@$var['2']." =-\n") if ($log_level >= 7);
	    system "$tc class replace dev $int_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[2]kbit ceil @$var[2]kbit";
	    system "$tc class replace dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[2]kbit ceil @$var[2]kbit";
	} else {
	    # unshape
	    LOG(7,"-= unshape ".@$var['0']." =-\n") if ($log_level >= 7);
	    system "$tc class delete dev $int_if parent 1:0 classid 1:$ip[2]$ip[3]";
	    system "$tc class delete dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3]";
	    if (@$var['1'])
	    {
		# shape
		LOG(7,"-= shape ".@$var['0']." with hand speed ".@$var['1']." =-\n") if ($log_level >= 7);
		system "$tc class replace dev $int_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[1]kbit ceil @$var[1]kbit";
		system "$tc class replace dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3] htb rate @$var[1]kbit ceil @$var[1]kbit";
	    } else {
		# unshape
		LOG(7,"-= unshape ".@$var['0']." =-\n") if ($log_level >= 7);
		system "$tc class delete dev $int_if parent 1:0 classid 1:$ip[2]$ip[3]";
		system "$tc class delete dev $ext_if parent 1:0 classid 1:$ip[2]$ip[3]";
	    }
	}
	undef(@ip); undef(@iip);
    }
}

foreach my$key (keys %worked_users)
{
    LOG(5,"-= delete ".$key." =-\n") if ($log_level >= 5);
    system "/usr/sbin/ipset del allowed_users $key";
}

$dbh->disconnect();


