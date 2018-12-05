import time
import hashlib
import requests
from logging import (getLogger, basicConfig)

from yaml import (load, YAMLError)

logger = getLogger()


class PyHole(object):
    """Python wrapper for Pi-hole"""

    def __init__(self):
        """initialise ip address, api-baseurl, authenicate-data"""

        basicConfig(level="INFO")

        with open("config.yml", 'r') as stream:
            try:
                yml_data = load(stream)
            except YAMLError as exc:
                logger.error(exc)

        self.ip_address = yml_data['IP_address']
        self.password = yml_data['password']

        self.api_baseurl = "http://" + self.ip_address + "/admin/api.php"
        self._auth = None

        self.get_version()
        self.do_refresh()

    def do_refresh(self):
        """Refresh all stats; return dict consisting stats"""

        stats_json = requests.get(self.api_baseurl + "?summary").json()
        logger.debug("[*] Stats refreshed!")

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
        
        return stats_json

    def top_clients(self, entries=10):
        """data needed for generating the top clients list"""
        
        if self._auth != None:
            top_clients_data = requests.get( self.api_baseurl + "?getQuerySources=" + str(entries) + "&auth=" + self.token).json()
            self.top_devices = top_clients_data["top_sources"]
            
            return self.top_devices
        return False

    def get_query_types(self):
        """return number of queries that Pi-hole’s DNS server has processed"""          
        
        if self._auth != None:
            raw_data = requests.get(self.api_baseurl + "?getQueryTypes&auth=" + self.token).json()

            if self._version == "3":
                self.query_types = raw_data["querytypes"]
            else:
                self.query_types = raw_data["querytypes"]
            return self.query_types
        return False

    def get_forward_destinations(self):
        """returns number of queries that have been forwarded and the target"""

        if self._auth != None:
            raw_data = requests.get(self.api_baseurl + "?getForwardDestinations&auth=" + self.token).json()
            
            if self._version == "3":
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
        return self.token

    def authenticate(self):
        """authenticate with pihole by generating pihole token"""

        self._auth = self.get_pihole_token(self.password)

        return True

    def enable_pihole(self):
        """enable pihole with token"""

        if self._auth == None:
            logger.debug("[!] User found unauthenticated whilst enabling. Exit with false! ")
            return False

        # {"status":"enabled"}  
        return requests.get(self.api_baseurl + "?enable&auth=" + self.token).json()

    def disable_pihole(self, time_limit=60):
        """disable pihole in time_limit(in seconds)"""

        if self._auth == None:
            logger.debug("[!] User found unauthenticated whilst disabling. Exit with false! ")          
            return False

        # {"status":"disabled"}
        return requests.get(self.api_baseurl + "?disable="+ str(time_limit) +"&auth=" + self.token).json()

    def add_to_list(self, domains_list, domain):
        """adding domain tocd list"""

        if self._auth == None:
            logger.debug("[!] User found unauthenticated whilst adding domain. Exit with false! ")
            return False

        with requests.session() as sess:
            sess.get("http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/add.php")
            data = {
                "list": domains_list,
                "domain": domain,
                "pw": self.password
            }
            resp = requests.post("http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/add.php", data=data).text

        return resp

    def remove_from_list(self, domains_list, domain):
        """remove domain from list"""

        if self._auth == None:
            logger.debug("[!] User found unauthenticated whilst removing domain. Exit with false!")
            return False

        with requests.session() as sess:
            sess.get("http://" + str(self.ip_address) + "/admin/scripts/pi-hole/php/sub.php")
            data = {
                "list": domains_list,
                "domain": domain,
                "pw": self.password
            }
            resp = requests.post("http://" + str(self.ip_address) + "admin/scripts/pi-hole/php/sub.php", data=data).text

        return resp

    def get_list(self, list_type):
        """return list of blocked types: list_type"""

        get_api = "http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/get.php"
        domains_list = requests.get(get_api + "?list=" + str(list_type)).json()
        
        return domains_list

    def refresh_top_items(self, entries=10):
        """
        return top items
        entries: no of items returned (default=10)
        """

        if self._auth == None:
            logger.debug("[!] User found aunthenticated whilst accessing top items. Exit with false!")
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
        # print(stats_json)
        stats = {
        "domains_over_time": stats_json['domains_over_time'],
        "ads_over_time": stats_json['ads_over_time']
        }

        return stats

    def get_all_DNS_queries_data(self):
        """returns dict as DNS queries data"""

        if self._auth == None:
            logger.debug("[!] User found unauthenticated whilst getting DNS queries. Exit with false!")
            return False

        stats_json = requests.get(self.api_baseurl + "?getAllQueries&auth=" + self.token).json()
        
        stats_data = {}
        if self._version == "3":
            try:
                for i in range(len(stats_json["data"])):
                    stats_data[i] = {
                        "time_string": stats_json["data"][i][0],
                        "query_type": stats_json["data"][i][1],
                        "requested_domain_name": stats_json["data"][i][2],
                        "requesting_client": stats_json["data"][i][3],
                        "status": stats_json["data"][i][4],
                        "last_column": stats_json["data"][i][5]
                    }
            except IndexError:
                logger.error("[!] DNS query returned less number of data")
        else:
            for i in range(len(stats_json["data"])):
                try:
                    stats_data[i] = {
                        "time_stamp": stats_json["data"][i][0],
                        "query_type": stats_json["data"][i][1], #IPv6/IPv7
                        "requested_domain_name": stats_json["data"][i][2],
                        "requesting_client": stats_json["data"][i][3],
                        "answer_type": stats_json["data"][i][4]
                    }
                except IndexError:
                    logger.error("[!] DNS query returned less number of data")

        return stats_data

    def get_version(self):
        """return version of pi-hole API: authentication not necessary!"""
        
        stats_json = requests.get(self.api_baseurl + "?version").json()
        self._version = stats_json["version"]
        
        return self._version

      
if __name__=="__main__":
    ph = PyHole()
    ph.authenticate()
    ph.enable_pihole()
    ph.get_list("black")