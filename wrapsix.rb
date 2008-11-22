#!/usr/bin/env ruby
#####
## WrapSix
###
#> wrapsix.rb
#~ Description...
####
# Author: Michal Zima, 2008
# E-mail: xhire@tuxportal.cz
#####

### Hardcoded configuration => configured by system administrator
$config = {}
$config['config_file'] = 'conf/wrapsix.conf'

#------------------------------------------------------------------------------#

### Include all necessary libraries
require 'yaml'
require 'socket'
# WrapSix libs
require 'lib/resolver'
require 'lib/wrapper'

### Parse command line arguments if any

### Load configuration
configuration = YAML.load_file $config['config_file']

## Merge both configs
$config.merge! configuration		# FIX: this overwrites those configs from command line!
#p $config

### Start logging facility (system wide one)

### Handle some signals
# todo: replace this with right variables
def exit
	$resolver.exit	if $config['resolver']
	$wrapper.exit		if $config['wrapper']
	Process.exit
end

# TERM -KILL- QUIT INT
trap "INT"  do; exit; end
trap "TERM" do; exit; end
trap "QUIT" do; exit; end

services = []
### Start DNS resolver function
if $config['resolver']
	$resolver = Resolver.new
	services << Thread.start do; $resolver.start;  end
end

### Start IPv6-to-IPv4 wrapper
if $config['wrapper']
	$wrapper = Wrapper.new
	services << Thread.start do; $wrapper.start; end
end

### Start WrapSix
# in best conditions it would *never* stop
services.each do |srvc| srvc.join end

