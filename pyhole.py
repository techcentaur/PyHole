import time
import hashlib
import requests
import argparse

from logging import (getLogger, basicConfig)
from interface import implements

from pyhole_interface import PyHoleInterface


logger = getLogger()


class PyHole(implements(PyHoleInterface)):
	"""Python wrapper for Pihole"""

	def __init__(self, ip_address, loglevel):
		"""initialise ip address, api-baseurl, authenicate-data"""

		basicConfig(level=loglevel)

		self.ip_address = ip_address
		self.api_baseurl = "http://" + self.ip_address + "/admin/api.php"
		self._auth = None
		self.do_refresh()

	def do_refresh(self):
		"""Refresh all stats"""

		stats_json = requests.get(self.api_baseurl + "?summary")

		self.status = stats_json["status"]
		self.domain_count = stats_json["domains_being_blocked"]
		self.queries = stats_json["dns_queries_today"]
		self.blocked = stats_json["ads_blocked_today"]
		self.ads_percentage = stats_json["ads_percentage_today"]
		self.unique_domains = stats_json["unique_domains"]
		self.forwarded = stats_json["queries_forwarded"]
		self.cached = stats_json["queries_cached"]
		self.total_clients = stats_json["clients_ever_seen"]
		self.unique_clients = stats_json["unique_clients"]
		self.total_queries = stats_json["dns_queries_all_types"]
		self.gravity_last_updated = stats_json["gravity_last_updated"]
		

	def top_clients(self, entries=10):
		"""data needed for generating the top clients list"""
		
		if self._auth != None:
			top_clients_data = requests.get( self.api_baseurl + "?getQuerySources=" + str(entries) + "&auth=" + self.token).json()
			self.top_devices = topdevicedata["top_sources"]
			
			return self.top_devices
		return False

	
	def get_query_types(self):
		"""return number of queries that Pi-hole’s DNS server has processed"""			
		
		if self._auth != None:
			raw_data = requests.get(self.api_baseurl + "?getQueryTypes&auth=" + self.token).json()
			
			if self._version == "2":
				self.query_types = raw_data
			else:
				self.query_types = raw_data["querytypes"]
			return self.querytypes
		return False

	def get_forward_destinations(self):
		"""returns number of queries that have been forwarded and the target"""

		if self._auth != None:
			raw_data = requests.get(self.api_baseurl + "?getForwardDestinations&auth=" + self.token).json()
			
			if self._version == "2":
				self.forward_destinations = raw_data["forward_destinations"]
			else:
				self.forward_destinations = raw_data
			return self.forward_destinations
		return False


	def get_recent_blocked(self):
		"""return most recently blocked domain"""

		raw_data = requests.get(self.api_baseurl + "?recentBlocked")
		return raw_data.text


	def get_pihole_token(self, password):
		"""get pi-hole token:: double sha256 hash of utf8 encoded password"""

		self.token = hashlib.sha256(hashlib.sha256(str(password).encode()).hexdigest().encode()).hexdigest()
		self.auth_timestamp = time.time()
		# print('[*] Token: ', self.token)
		return True


	def authenticate(self, password):
		"""authenticate with pihole by generating pihole token"""

		self._auth = self.get_pihole_token(password)
		self.password = password

		return True


	def enable_pihole(self):
		"""enable pihole with token"""

		if self._auth == None:
			logger.DEBUG("[!] User found unauthenticated whilst enabling. Exit with false! ")
			return False

		# {"status":"enabled"}
		return requests.get(self.api_baseurl + "?enable&auth=" + self.token).json()

	
	def disable_pihole(self, time_limit):
		"""disable pihole in time_limit(in seconds)"""

		if self._auth == None:
			logger.DEBUG("[!] User found unauthenticated whilst disabling. Exit with false! ")			
			return False

		# {"status":"disabled"}
		return requests.get(self.api_baseurl + "?disable="+ str(time_limit) +"&auth=" + self.token).json()

	def add_to_list(self, domains_list, domain):
		"""adding domain to list"""

		if self._auth == None:
			logger.DEBUG("[!] User found unauthenticated whilst adding domain. Exit with false! ")
			return False

		with requests.session() as session:
			session.get("http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/add.php")
			data = {
				"list": domains_list,
				"domain": domain,
				"pw": self.password
			}
			requests.post("http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/add.php", data=data).text

		return True


	def remove_from_list(self, domains_list, domain):
		"""remove domain from list"""

		if self._auth == None:
			logger.DEBUG("[!] User found unauthenticated whilst removing domain. Exit with false!")
			return False

		with requests.session() as session:
			session.get("http://" + str(self.ip_address) + "/admin/scripts/pi-hole/php/sub.php")
			data = {
				"list": domains_list,
				"domain": domain,
				"pw": self.password
			}
			requests.post("http://" + str(self.ip_address) + "admin/scripts/pi-hole/php/sub.php", data=data).text

		return True

	def get_list(self, list_type):
		"""return list of blocked types: list_type"""

		get_api = "http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/get.php"
		domains_list = requests.get(get_api + "?list=" + str(list_type)).json()
		
		return domains_list

	def refresh_top_items(self, entries):
		"""
		return top items
		entries: no of items returned (default=10)
		"""

		if self._auth == None:
			logger.DEBUG("[!] User found aunthenticated whilst accessing top items. Exit with false!")
			return False

		stats_json = requests.get(self.api_baseurl + "?topItems="+ str(entries) +"&auth=" + self.token).json()
		self.top_queries = stats_json["top_queries"]
		self.top_ads = stats_json["top_ads"]

		top_items = {
			"top_queries": self.top_queries,
			"top_ads": self.top_ads
		}

		return top_items

	def get_graph_data(self):
		"""return graph of domains/ads over time"""

		stats_json = requests.get(self.api_baseurl + "?overTimeData10mins").json()	

		stats = {
		"domains_over_time": stats['domains_over_time'],
		"ads_over_time": stats['ads_over_time']
		}

		return stats

	def get_all_DNS_queries_data(self):
		"""returns dict as DNS queries data"""

		if self._auth == None:
			logger.DEBUG("[!] User found unauthenticated whilst getting DNS queries. Exit with false!")
			return False

		stats_json = requests.get(self.api_baseurl + "?getAllQueries&auth=" + self.token).json()
		# test the format
		stats_data = {}
		if self._version == "2":
			try:
				for i in range(len(stats_json["data"])):
					stats_data[i] = {
						"time_string": i[0],
						"query_type": i[1],
						"requested_domain_name": i[2],
						"requesting_client": i[3],
						"status": i[4],
						"last_column": i[5]
					}
			except IndexError:
				logger.ERROR("[!] DNS query returned less number of data")
		else:
			for i in range(len(stats_json["data"])):
				try:
					stats_data[i] = {
						"time_stamp": i[0],
						"query_type": i[1], #IPv6/IPv7
						"requested_domain_name": i[2],
						"requesting_client": i[3],
						"answer_type": i[4]
					}
				except IndexError:
					logger.ERROR("[!] DNS query returned less number of data")

		return stats_data



	def get_version(self):
		"""return version of pi-hole API: authentication not necessary!"""
		
		return requests.get(self.api_baseurl + "?versions").json()



if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Pihole wrapper')
    parser.add_argument('-ll', '--loglevel', help='Set the logging level', type=str, choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'])
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)
        
