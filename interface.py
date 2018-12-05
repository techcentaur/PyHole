class PyHole():
	def __init__(self, ip_address):
		"""initialise ip address, api-baseurl, authenicate-data"""
		pass

	def get_pihole_token(self, password):
		"""get pi-hole token:: double sha256 hash of utf8 encoded password"""
		pass

	def authenticate(self, password):
		"""authenticate with pihole by generating pihole token"""
		pass

	def enable_pihole(self):
		"""enable pihole with token"""
		pass

	def disable_pihole(self, time_limit):
		"""disable pihole in time_limit(in seconds)"""
		pass

	def get_version(self):
		"""return version of pi-hole API: authentication not necessary!"""
		pass

	def do_refresh(self):
		"""Refresh all stats"""
		pass

	def add_to_list(self, domains_list, domain):
		"""adding domain to list"""
		pass

	def remove_from_list(self, domains_list, domain):
		"""remove domain from list"""
		pass

	def get_list(self, list_type):
		"""return list of blocked types: list_type"""
		pass

	def refresh_top_items(self, entries):
		"""
		return top items
		entries: no of items returned (default=10)
		"""
		pass

	def get_graph_data(self):
		"""return graph of domains/ads over time"""
		pass

	def get_all_DNS_queries_data(self):
		"""returns dict as DNS queries data"""
		pass

	def top_clients(self, entries):
		"""data needed for generating the top clients list"""
		pass
	
	def get_query_types(self):
		"""return number of queries that Pi-hole’s DNS server has processed"""			
		pass

	def get_forward_destinations(self):
		"""returns number of queries that have been forwarded and the target"""
		pass

	def get_recent_blocked(self):
		"""return most recently blocked domain"""
		pass
