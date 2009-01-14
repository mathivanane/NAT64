#####
## WrapSix
###
#> lib/resolver.rb
#~ WrapSix Resolver
####
# Author: Michal Zima, 2008-2009
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
		begin
			@resolver.bind $config['resolver_ip'], 53
		rescue Errno::EACCES
			$stderr.puts "You have to run #{$0} as root!"
			exit!
		end
		puts "Started DNS resolver on IPv6 address #{$config['resolver_ip']}" if @debug

		loop do
			# Receive and parse query
			data = @resolver.recvfrom 2048
			print "Client: " if @debug
			p data[1] if @debug

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
				begin
					name = question.to_s                          # The domain name looked for in the query.
					answer.add_question name, typeclass
					puts "Looking for: #{name}" if @debug
					#record_type = typeclass.name.split("::").last # For example "A", "MX"
					puts "RR: #{typeclass}" if @debug

					# So let's look for it :c) (in secondary resolver)
					sr = Resolv::DNS::new :nameserver => $config['secondary_resolver']
					sr_data = sr.getresource name, typeclass
					print "Raw answer: " if @debug
					p sr_data if @debug

					record = {}
					record[:name] = name
					record[:data] = sr_data

					print "Data: " if @debug
					p record if @debug

					# completing the answer
					ttl = 86400		# I think ttl doesn't matter ;c)
					answer.add_answer name + ".", ttl, record[:data]

					print "My answer: " if @debug
					p answer if @debug
				rescue Resolv::ResolvError
					# creating 'faked' AAAA entry
					begin
						if typeclass == Resolv::DNS::Resource::IN::AAAA
							sr = Resolv::DNS::new :nameserver => $config['secondary_resolver']
							sr_data = sr.getresource name, Resolv::DNS::Resource::IN::A
							print "Raw answer: " if @debug
							p sr_data if @debug

							# completing the answer
							aaaa_answer = Resolv::DNS::Resource::IN::AAAA.new(ipaddr_4to6(sr_data.address))
							print "IPv4 address: " if @debug
							p sr_data.address if @debug
							p ipaddr_4to6(sr_data.address) if @debug
							ttl = 86400		# I think ttl doesn't matter ;c)
							answer.add_answer name + ".", ttl, aaaa_answer

							print "My answer: " if @debug
							p answer if @debug
						end
					rescue Resolv::ResolvError
						puts "Error: DNS result has no information for #{name}"
					end
				end
			end

			# send the response
			@resolver.send answer.encode, 0, data[1][3], data[1][1]		# msg, flags, client, port
		end
	end

	def exit
		@resolver.close
	end

	private
	def ipaddr_4to6 ip4addr
		ip4parsed = ip4addr.to_s.match(Resolv::IPv4::Regex)
		return $config['wrapper_ipv6_prefix'] + ("%02x%02x:%02x%02x" % [ ip4parsed[1], ip4parsed[2], ip4parsed[3], ip4parsed[4] ])
	end
end
