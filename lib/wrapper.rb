#####
## WrapSix
###
#> lib/wrapper.rb
#~ WrapSix Wrapper
####
# Author: Michal Zima, 2008-2009
# E-mail: xhire@tuxportal.cz
#####

class Wrapper
	def initializer
		@debug = $config['debug']
	end

	def start
		params  = "#{$config['wrapper_ipv4_address']} #{$config['wrapper_ipv6_prefix']}"
		params += " #{$config['wrapper_device']}" if $config['wrapper_device']
		unless @debug
			params += " > /dev/null"
		end
		system "wrapper/wrapper #{params}"
	end

	def exit
	end
end
