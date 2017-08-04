import urllib2
import json
import sys

import StringIO
import xmltodict
from distutils.version import LooseVersion, StrictVersion
from gzip import GzipFile

VULNERS_LINKS = {'pkgChecker':'https://vulners.com/api/v3/audit/audit/',
                 'bulletin':'https://vulners.com/api/v3/search/id/?id=%s'}


class yumAudit():
    def __init__(self):
        pass

    # get full package names from a repo
    # Returns None if empty, or a list of strings 
    def getPackages(self, repoPath):
        installed = {}

        # get location of the 'primary' file from repomd.xml
        repomd = urllib2.urlopen(repoPath+"/repodata/repomd.xml")
        repomdDict = xmltodict.parse(repomd.read())
        primaryFilename = None
        for data in repomdDict.get('repomd').get('data'): 
            if data['@type'] == 'primary':
                primaryFilename = data['location']['@href'].strip('.rpm').split("/")[1] 
                break
        if not primaryFilename:
            return None

        # get and decompress the primary gz file
        primarygz = urllib2.urlopen(repoPath+"/repodata/"+primaryFilename)
        buf = StringIO.StringIO(primarygz.read())
        gz = GzipFile(fileobj=buf)
        primaryDict = xmltodict.parse(gz.read())


        # loop through all packages, compare versions, keep newest
        for package in primaryDict.get('metadata', {}).get('package'):
            
            name = package['name']
            epoch = package['version']['@epoch']
            ver = package['version']['@ver']
            rel = package['version']['@rel']
            fullName = package['location']['@href'].split("/")[1].strip('.rpm')
            fullVer = '.'.join([epoch,ver,rel])

            # if we've seen this pkg
            stored = installed.get(name)
            if stored:
                sepoch = stored['epoch']
                sver = stored['ver']
                srel = stored['rel']
                sFullVer = '.'.join([sepoch, sver, srel])
                # if version greater than stored
                if LooseVersion(fullVer) > LooseVersion(sFullVer):
                    installed[name]['ver'] = ver
                    installed[name]['rel'] = rel
                    installed[name]['epoch'] = epoch
                    installed[name]['fullname'] = fullName
            # brand new entry
            else:
                installed[name] = {
                    'ver': ver,
                    'rel': rel,
                    'epoch': epoch,
                    'fullname': fullName,
                }

        if len(installed.keys()) > 0:
            return [ value['fullname'] for value in installed.values() ]

        return None


    def audit(self, repoPath, os, version):

        installedPackages = self.getPackages(repoPath)
        if not installedPackages:
            print("Couldn't find packages")
            return

        print("Total provided packages: %s" % len(installedPackages))


        # Get vulnerability information from vulners
        payload = {'os':os,
                   'version':version,
                   'package':installedPackages}
        req = urllib2.Request(VULNERS_LINKS.get('pkgChecker'))
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'vulners-yum-scanner-v0.1')
        response = urllib2.urlopen(req, json.dumps(payload).encode('utf-8'))
        responseData = response.read()
        if isinstance(responseData, bytes):
            responseData = responseData.decode('utf8')
        responseData = json.loads(responseData)
        resultCode = responseData.get("result")
        if resultCode == "OK":
            #print(json.dumps(responseData, indent=4))
            print("\nVulnerabilities:\n%s\n" % "\n".join(responseData.get('data').get('vulnerabilities')))
            print("\nCVE List:\n%s" % "\n".join(responseData.get('data').get('cvelist')))
        else:
            print("Error - %s" % responseData.get('data').get('error'))
        return