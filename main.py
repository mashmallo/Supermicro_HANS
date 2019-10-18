import requests
import argparse
import urllib3


class ServerData:
	def __init__(self, ip_addr_curr, new, mask, gateway, hostname):
		self.ip_addr_curr = ip_addr_curr
		self.new = new
		self.mask = mask
		self.gateway = gateway
		self.hostname = hostname

def set_snmp(myserver):
	try:
		#id = line.rstrip('\n')
		id = myserver.new
		url = 'https://'+id
		login_api = url + '/cgi/login.cgi'
		fillform = url + '/cgi/op.cgi'
		headers = {
			'Origin': url,
			'Accept-Encoding': 'gzip, deflate, br',
			'Accept-Language': 'en-US,en;q=0.9',
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
			'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
			'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
			'X-Prototype-Version': '1.5.0',
			'X-Requested-With': 'XMLHttpRequest',
			'Connection': 'keep-alive',		
		}
	
		login = {
			'name': 'YOUR ADMIN PAGE USERNAME',
			'pwd': 'YOUR PASSWORD',
		}
	
		#grab session ID
		s = requests.session()
		response = s.post(login_api, headers=headers, data=login, verify=False)
	except:
		print ('gagal login to ' + myserver.new)
		return False
		
	try:	
		setntp = {
			'op': 'config_date_time',
			'timezone': '25200', #UTC+07:00
			'dst_en': '0',
			'ntp': 'on', #enablentp
			'ntp_server_pri': 'YOUR NTP SERVER IP', #primary ntp server ip
			'ntp_server_2nd': 'YOUR NTP SERVER IP', #secondary ntp server ip
			'year': '2018',
			'month': '12',
			'day': '21',
			'hour': '17',
			'min': '05',
			'sec': '03',
			'_': ''
		}
	
		response = s.post(fillform, headers=headers, data=setntp, verify=False)
	except:
		print ('gagal setting NTP untuk ' + myserver.new)
		return False
	
	try:	
		setsnmp = {
			'op': 'config_snmp',
			'en_snmp': 'on',
			'en_snmpv2': 'on',
			'rocommunity': 'YOUR SNMP COMMUNITY',
			'rwcommunity': 'YOUR SNMP COMMUNITY',
			'en_snmpv3': 'off',
			'_': ''
		}
		
		response = s.post(fillform, headers=headers, data=setsnmp, verify=False)
		
	except:
		print ('gagal setting SNMP agent untuk ' + myserver.new)
		return False
	
	try:
		setalerts = {
			'op': 'config_alert',
			'ip': 'YOUR ALERTING SERVER IP',
			'severity': '2',
			'mail': 'NULL',
			'sub': 'NULL',
			'msg': 'NULL',
			'index': '0',
			'fun': 'm',
			'_': ''
		}
	
		response = s.post(fillform, headers=headers, data=setalerts, verify=False)
	except:
		print ('gagal setting SNMP trap untuk ' + myserver.new)
		return False
		
def ubah_ip_supermicro(myserver):
	"""
	Fungsi untuk merubah ip dan hostname super micro
	"""
	print ("==========================================")
	print ("current IP address : " + myserver.ip_addr_curr)
	print ("new ip : " + myserver.new)
	print ("netmask : " + myserver.mask)
	print ("gateway : " + myserver.gateway )
	print ("hostname : " + myserver.hostname)
	
	ip_addr_curr = myserver.ip_addr_curr
	ip_addr_new = myserver.new	
	ip_addr_mask = myserver.mask
	ip_addr_gw = myserver.gateway
	ip_hostname = myserver.hostname
	
	cookies = {
		'langSetFlag': '0',
		'language': 'English',
		'SID': 'nnfddxgiptxwexgw',
		'mainpage': 'system',
		'subpage': 'top',
	}
	
	headers = {
		'Connection': 'keep-alive',
		'Cache-Control': 'max-age=0',
		'Origin': 'https://'+ip_addr_curr,
		'Upgrade-Insecure-Requests': '1',
		'Content-Type': 'application/x-www-form-urlencoded',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
		'Referer': 'https://'+ip_addr_curr,
		'Accept-Encoding': 'gzip, deflate, br',
		'Accept-Language': 'en-US,en;q=0.9',
	}
	
	#ini user dan password
	data = {
	'name': 'YOUR ADMIN PAGE USERNAME',
	'pwd': 'YOUR PASSWORD'
	}
	
	s = requests.session()
	
	#tembak api nya IPMI untuk login
	r = s.post('https://'+ip_addr_curr+'/cgi/login.cgi', headers=headers,data=data, verify=False)
	
	ip_addr_new_edited = ''
	
	#ubah format ip addr new dengan prefix 0
	ip_parts = ip_addr_new.split('.')
	for i in range(0,len(ip_parts)):
		if len(ip_parts[i]) == 1:
			ip_parts[i] = '00'+ip_parts[i]
		if len(ip_parts[i]) == 2:
			ip_parts[i] = '0'+ip_parts[i]
		
	ip_addr_new_edited = '.'.join(ip_parts)
	
	#ubah format ip addr gateway dengan prefix 0
	ip_parts = ip_addr_gw.split('.')
	for i in range(0,len(ip_parts)):
		if len(ip_parts[i]) == 1:
			ip_parts[i] = '00'+ip_parts[i]
		if len(ip_parts[i]) == 2:
			ip_parts[i] = '0'+ip_parts[i]
	
	ip_addr_gw_edited = '.'.join(ip_parts)
			
	data = {
	'op': 'config_lan',
	'bmcip': ip_addr_new_edited,
	'bmcmask': ip_addr_mask,
	'gatewayip': ip_addr_gw_edited,
	'en_dhcp': 'off',
	'en_vlan': 'off',
	'vlanID': '0',
	'rmcpport': '623',
	'dns_server': '',
	'bmcipv6_dns_server': '',
	'bmcipv6_addr': '',
	'bmcipv6_opt': 'add',
	'bmcipv6_autoconf': 'on',
	'dhcpv6_mode': 'stateless',
	'lan_interface': '0',
	'link_conf': '0',
	'hostname': ip_hostname,
	'rt_src': '2',
	'srt_router1': '::',
	'srt_pval1': '::',
	'srt_plen1': '255',
	'srt_router2': '::',
	'srt_pval2': '::',
	'srt_plen2': '255',
	'_': ''
	}
	
	r = s.post('https://'+ip_addr_curr+'/cgi/op.cgi', headers=headers, data=data, verify=False)
	if (r.text=='ok'):
		return True
	else:
		return False

#ignore HTTPS warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
		
if __name__ == "__main__":
	
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--file", help="File dengan format csv. Format CSV : ip addr now, ip addr new, ip netmask, ip def gw, hostname", required=True)
	parser.add_argument("-l", "--log", help="File log")	
	args = parser.parse_args()
	fname = args.file
	with open(fname, 'r') as infile:
		for line in infile:
			tmp_str = line.split(',')
			ip_addr_curr = tmp_str[0]
			new = tmp_str[1]
			mask = tmp_str[2]
			gateway = tmp_str[3]
			hostname = tmp_str[4].rstrip('\n')
			
			myserver = ServerData(ip_addr_curr, new, mask, gateway, hostname)
			str_log = "ubah data ip {} -> ip {} dan hostname {}".format(ip_addr_curr, new, hostname)
			if ubah_ip_supermicro(myserver):
				print ('Sukses ' + str_log)
				print ("Setting NTP, SNMP agent and SNMP trap")
				set_snmp(myserver)
				if args.log:
					try:
						f=open(args.log,"a")
					except:
						f=open(args.log,"w")
					f.write('Sukses ' + str_log)
					f.close()
			else :
				print ('Gagal ' + str_log)
				if args.log:
					try:
						f=open(args.log,"a")
					except:
						f=open(args.log,"w")
					f.write('Gagal ' + str_log)
					f.close()
				