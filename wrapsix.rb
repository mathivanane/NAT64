#!/usr/bin/env ruby
#####
## WrapSix
###
#> wrapsix.rb
#~ Main part of WrapSix that starts all other components
####
# Author:   Michal Zima, 2008-2009
# E-mail:   xhire@tuxportal.cz
# Homepage: http://wrapsix.tuxportal.cz/
#####
$version = '0.1.0'

$config = {}
$config['config_file'] = 'conf/wrapsix.conf'

### Include all necessary libraries
require 'yaml'
require 'socket'
require 'optparse'
# WrapSix libs
require 'lib/resolver'
require 'lib/wrapper'

### Parse command line arguments if any
OptionParser.new do |opts|
	opts.banner = "Usage: wrapsix.rb [options]"

	opts.on("--[no-]resolver", "Run the DNS resolver") do |resolver|
		$config['resolver'] = resolver
	end

	opts.on("--[no-]wrapper", "Run the wrapper") do |wrapper|
		$config['wrapper'] = wrapper
	end

	opts.on("--resolver-ip=IPv6_address", "Set the IPv6 address for the DNS resolver") do |rip|
		$config['resolver_ip'] = rip
	end

	opts.on("--dns-resolver=IP_address", "Set the address of DNS resolver to be used") do |sr|
		$config['secondary_resolver'] = sr
	end

	opts.on("--device=dev", "Set the network interface to override automatic detection") do |nic|
		$config['wrapper_device'] = nic
	end

	opts.on("--ipv6=prefix", "Set the IPv6 preffix (max. /96), e.g. fc00::") do |prefix|
		$config['wrapper_ipv6_prefix'] = prefix
	end

	opts.on("--ipv4=address", "Set the IPv4 address") do |addr|
		$config['wrapper_ipv4_address'] = addr
	end

	opts.on("-d", "--[no-]debug", "Run in the debug mode") do |d|
		$config['debug'] = d
	end

	opts.on_tail("-h", "--help", "Show this message") do
		puts opts
		exit
	end

	# Another typical switch to print the version.
	opts.on_tail("-v", "--version", "Show version") do
		puts "WrapSix #{$version}"
		puts "Copyright (c) 2008-2009 Michal Zima"
		exit
	end
end.parse!

### Load configuration from file and merge it with the original one
$config = YAML.load_file($config['config_file']).merge $config

### Handle some signals
def exit
	$resolver.exit	if $config['resolver']
	$wrapper.exit		if $config['wrapper']
	Process.exit
end

# TERM QUIT INT
trap "INT"  do; exit; end
trap "TERM" do; exit; end
trap "QUIT" do; exit; end

services = []
### Start DNS resolver function
$resolver = Resolver.new
if $config['resolver'] == true
	services << Thread.start do; $resolver.start;  end
end

### Start IPv6-to-IPv4 wrapper
$wrapper = Wrapper.new
if $config['wrapper'] == true
	services << Thread.start do; $wrapper.start; end
end

### Start WrapSix
# in best conditions it would *never* stop
services.each do |srvc| srvc.join end
