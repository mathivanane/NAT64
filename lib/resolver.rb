#####
## WrapSix
###
#> lib/resolver.rb
#~ WrapSix Resolver
####
# Author: Michal Zima, 2008
# E-mail: xhire@tuxportal.cz
#####

### Include all necessary libraries
require 'resolv'

class Resolver
	def initialize
		@debug = $config['debug']
	end

	def start
		@resolver = UDPSocket.open Socket::AF_INET6
		if @resolver.bind $config['resolver_ip'], 53
			p "Started DNS resolver on IPv6 address #{$config['resolver_ip']}" if @debug
		else
			p "DNS resolver not started!" if @debug
		end

		# just for now
		#@hosts = [
			#{:name => "example.com", :type => "A", :data => "192.168.0.1"}
		#]

		loop do
			# Receive and parse query
			data = @resolver.recvfrom 2048
			p "Client: #{data[1].join(' ')}" if @debug

			query = Resolv::DNS::Message::decode data[0]
			print "Whole query: " if @debug
			p query if @debug

			# Setup an answer
			answer = Resolv::DNS::Message::new query.id
			answer.qr = 1                 # 0 = Query, 1 = Response
			answer.opcode = query.opcode  # Type of Query; copy from query
			answer.aa = 0                 # Is this an authoritative response: 0 = No, 1 = Yes
			answer.rd = query.rd          # Is Recursion Desired, copied from query
			answer.ra = 1                 # Does name server support recursion: 0 = No, 1 = Yes
			answer.rcode = 0              # Response code: 0 = No errors

			query.each_question do |question, typeclass|    # There may be multiple questions per query
				name = question.to_s                          # The domain name looked for in the query.
				p "Looking for: #{name}" if @debug
				record_type = typeclass.name.split("::").last # For example "A", "MX"
				p "RR: #{typeclass}" if @debug
				p "RR: #{record_type}" if @debug

				# So let's look for it :c) (in secondary resolver)
				sr = Resolv::DNS::new :nameserver => $config['secondary_resolver']
				sr_data = sr.getresource name, typeclass
				sr_answer = sr_data.address		# this is acceptable only for A or so
				p sr_answer if @debug

				# temporary code
				#ttl = 16000
				#ttl = 86400		# 1 day
				#record = @hosts.find{|host| host[:name] == name && host[:type] == record_type }
				#unless record.nil?
					# Setup answer to this question
					#answer.add_answer(name + ".",ttl,typeclass.new(record[:data]))
					#answer.encode
				#end
			end
		end

		# Send the response
		#server.send answer.encode, 0, data[1][2], data[1][1]
	end

	def exit
		@resolver.close
	end
end
