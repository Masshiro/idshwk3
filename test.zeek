##
#   This program is to check HTTP sessions
#   if a source IP is related to three different usr-agent or more,
#   then output "XXX.XXX.XXX.XXX is a proxy."
#   where XXX.XXX.XXX.XXX is the src IP.
##

# A global variable to store relationship of sourceIP to user agent
global src_agent_table: table[addr] of set[string];

# Write a event which can return you the HTTP header info.
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	local src_ip: addr=c$id$orig_h;	# A local var to store the source IP addr.
	if (c$http?$user_agent)	# Use field value existence test(?$)
	{
		local agent: string;
		agent=to_upper(c$http$user_agent);	# Copy the value of user_agent
		if (src_ip in src_agent_table)	# If this src IP has already been there
		{
			# if this agent has been in table, then nothing will happen
			# otherwise, this agent will be added.
			add (src_agent_table[src_ip])[agent];
		}
		else # Otherwise
		{
			# Add this into the table.
			src_agent_table[src_ip]=set(agent);
		}
	}
}

# Print the result.
event zeek_done()
{
	# Traverse the table,
	for (src_ip in src_agent_table)
	{
		# if the number of the agents is larger or equal to 3
		if (|src_agent_table[src_ip]|>=3)
		{
			print fmt("%s is a proxy.", src_ip);
		}
	}
}