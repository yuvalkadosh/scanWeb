import time
from pprint import pprint
from zapv2 import ZAPv2
import nmap


class Scanner():
    def __init__(self, target) -> None:
        self.target = target

    def init_zap(self):
        # Local Zap ip and api key
        self.apiKey = 'hch6mjqukjhrp18u86v6fmgjpi'
        self.localProxy = {"http": "http://127.0.0.1:8080",
                           "https": "http://127.0.0.1:8080"}

        # Don't create new session, TODO: is it better for the other tests?
        self.isNewSession = False
        self.sessionName = 'ScanTool'

        self.useProxyChain = False
        self.useProxyScript = False
        self.useContextForScan = False

        # You can specify other URL in order to help ZAP discover more site locations
        # List can be empty
        # applicationURL = ['http://localhost:8081/WebGoat/start.mvc',
        #                   'http://localhost:8081/WebGoat/welcome.mvc',
        #                   'http://localhost:8081/WebGoat/attack']
        self.applicationURL = []

        # MANDATORY. Set value to True if you want to customize and use a scan policy
        self.useScanPolicy = True
        # MANDATORY only if useScanPolicy is True. Ignored otherwise. Set a policy name
        self.scanPolicyName = 'SQL Injection and XSS'
        # MANDATORY only if useScanPolicy is True. Ignored otherwise.
        # Set value to True to disable all scan types except the ones set in ascanIds,
        # False to enable all scan types except the ones set in ascanIds..
        self.isWhiteListPolicy = True
        # MANDATORY only if useScanPolicy is True. Ignored otherwise. Set the scan IDs
        # to use with the policy. Other scan types will be disabled if
        # isWhiteListPolicy is True, enabled if isWhiteListPolicy is False.
        # Use zap.ascan.scanners() to list all ascan IDs.
        # In the example bellow, the first line corresponds to SQL Injection scan IDs,
        # the second line corresponds to some XSS scan IDs
        self.ascanIds = [40018, 40019, 40020, 40021, 40022, 40024, 90018,
                         40012, 40014, 40016, 40017]
        # MANDATORY only if useScanPolicy is True. Ignored otherwise. Set the alert
        # Threshold and the attack strength of enabled active scans.
        # Currently, possible values are:
        # Low, Medium and High for alert Threshold
        # Low, Medium, High and Insane for attack strength
        self.alertThreshold = 'Medium'
        self.attackStrength = 'Low'

        # MANDATORY. Set True to use Ajax Spider, False otherwise.
        self.useAjaxSpider = True

        # MANDATORY. Set True to shutdown ZAP once finished, False otherwise
        self.shutdownOnceFinished = False

    def zap_scan(self):
        # Connect ZAP API client to the listening address of ZAP instance
        zap = ZAPv2(proxies=self.localProxy, apikey=self.apiKey)

        # Start the ZAP session
        core = zap.core
        if self.isNewSession:
            pprint('Create ZAP session: ' + self.sessionName + ' -> ' +
                   core.new_session(name=self.sessionName, overwrite=True))
        else:
            pprint('Load ZAP session: ' + self.sessionName + ' -> ' +
                   core.load_session(name=self.sessionName))

        # Enable all passive scanners (it's possible to do a more specific policy by
        # setting needed scan ID: Use zap.pscan.scanners() to list all passive scanner
        # IDs, then use zap.scan.enable_scanners(ids) to enable what you want
        pprint('Enable all passive scanners -> ' +
               zap.pscan.enable_all_scanners())

        ascan = zap.ascan
        # Define if a new scan policy is used
        if self.useScanPolicy:
            ascan.remove_scan_policy(scanpolicyname=self.scanPolicyName)
            pprint('Add scan policy ' + self.scanPolicyName + ' -> ' +
                   ascan.add_scan_policy(scanpolicyname=self.scanPolicyName))
            for policyId in range(0, 5):
                # Set alert Threshold for all scans
                ascan.set_policy_alert_threshold(id=policyId,
                                                 alertthreshold=self.alertThreshold,
                                                 scanpolicyname=self.scanPolicyName)
                # Set attack strength for all scans
                ascan.set_policy_attack_strength(id=policyId,
                                                 attackstrength=self.attackStrength,
                                                 scanpolicyname=self.scanPolicyName)
            if self.isWhiteListPolicy:
                # Disable all active scanners in order to enable only what you need
                pprint('Disable all scanners -> ' +
                       ascan.disable_all_scanners(scanpolicyname=self.scanPolicyName))
                # Enable some active scanners
                pprint('Enable given scan IDs -> ' +
                       ascan.enable_scanners(ids=self.ascanIds,
                                             scanpolicyname=self.scanPolicyName))
            else:
                # Enable all active scanners
                pprint('Enable all scanners -> ' +
                       ascan.enable_all_scanners(scanpolicyname=self.scanPolicyName))
                # Disable some active scanners
                pprint('Disable given scan IDs -> ' +
                       ascan.disable_scanners(ids=self.ascanIds,
                                              scanpolicyname=self.scanPolicyName))
        else:
            print('No custom policy used for scan')
            self.scanPolicyName = None

        # Open URL inside ZAP
        pprint('Access target URL ' + self.target)
        core.access_url(url=self.target, followredirects=True)
        for url in self.applicationURL:
            pprint('Access URL ' + url)
            core.access_url(url=url, followredirects=True)
        # Give the sites tree a chance to get updated
        time.sleep(2)

        # Launch Spider, Ajax Spider (if useAjaxSpider is set to true) and
        # Active scans, with a context and users or not
        forcedUser = zap.forcedUser
        spider = zap.spider
        ajax = zap.ajaxSpider
        scanId = 0
        print('Starting Scans on target: ' + self.target)

        # Spider the target and recursively scan every site node found
        scanId = spider.scan(url=self.target, maxchildren=None, recurse=True,
                             contextname=None, subtreeonly=None)
        print('Scan ID equals ' + scanId)
        # Give the Spider a chance to start
        time.sleep(2)
        while (int(spider.status(scanId)) < 100):
            print('Spider progress ' + spider.status(scanId) + '%')
            time.sleep(2)
        print('Spider scan completed')

        # if useAjaxSpider:

        # Give the passive scanner a chance to finish
        time.sleep(5)
        print(core.alerts_summary())
        print(core.alerts())
        print(ajax.full_results)
        print(spider.all_urls)  # spider.full_results(0)[0]['urlsInScope']
        # If you want to retrieve alerts:
        pprint(zap.core.alerts(baseurl=self.target, start=None, count=None))

        # To retrieve ZAP report in XML or HTML format
        # print('XML report')
        # core.xmlreport()
        print('HTML report:')
        pprint(core.htmlreport())

        with open('report.html', 'w') as f:
            f.write(core.htmlreport())

        if self.shutdownOnceFinished:
            # Shutdown ZAP once finished
            pprint('Shutdown ZAP -> ' + core.shutdown())

    def nmap_scan(self):
        nm = nmap.PortScanner()
        striped_target = self.target.strip().replace(
            'https://', '').replace('http://', '')
        nm.scan(hosts=striped_target, arguments='-sV -T4')
        nm_output = ""
        # hosts_list = [(x, nm[x]['status']['state']) for x in scanner.all_hosts()]
        for host in nm.all_hosts():
            nm_output += '----------------------------------------------------\n'
            nm_output += 'Host : %s (%s)\n' % (host, nm[host].hostname())
            nm_output += 'State : %s\n' % nm[host].state()
            for proto in nm[host].all_protocols():
                nm_output += '----------\n'
                nm_output += 'Protocol : %s\n' % proto
                lport = nm[host][proto].keys()
                for port in lport:
                    nm_output += 'port : %s\tstate : %s ' % (
                        port, nm[host][proto][port]['state'])
                    try:
                        nm_output += nm[host][proto][port]['product'] + ' '
                        nm_output += nm[host][proto][port]['version']
                    except KeyError:
                        pass
                    nm_output += '\n'
        with open('nmap_output.txt', 'w') as f:
            f.write(nm_output)


scanner = Scanner('https://yuvalkadosh.com')
scanner.nmap_scan()
# scanner.init_zap()
# scanner.zap_scan()
