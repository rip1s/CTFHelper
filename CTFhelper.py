# Author :unamer
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from java.lang import RuntimeException
from java.net import URL
import re
from os import path
from urlparse import urlparse

stderr = None
stdout = None
helpers = None
cbs = None


class backupScan(IScannerCheck):
    def __init__(self):
        self.hs = set()
        self.patterns = {
            re.compile(r'([^\/]*\.php\d{0,1})', re.IGNORECASE): [r'.\1.swp', r'.\1.swn', r'.\1.swo', r'\1.bak',
                                                                 r'\1.zip', r'.\1.txt', r'\1.~', r'\1~'],
            re.compile(r'([^\/]*\.)php\d{0,1}', re.IGNORECASE): [r'\1txt', r'\1bak', r'.\1swp', r'\1swn', r'\1swo',
                                                                 r'\1zip', r'\1~']}

    def doPassiveScan(self, baseRequestResponse):
        # Nope ...
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):

        reqinfo = helpers.analyzeRequest(baseRequestResponse)
        url = str(reqinfo.getUrl())
        url = urlparse(url)

        issues = []

        burl = url.scheme + '://' + url.netloc + '/' + url.path

        if burl in self.hs or url.path[-1] == '/':
            return None

        self.hs.add(burl)

        for regex in self.patterns.iterkeys():
            subs = self.patterns[regex]

            for sub in subs:
                baktest = helpers.buildHttpRequest(URL(url.scheme, url.hostname, url.port, regex.sub(sub, url.path)))

                attack = cbs.makeHttpRequest(baseRequestResponse.getHttpService(), baktest)
                reqinfo = helpers.analyzeResponse(attack.getResponse())

                if reqinfo.getStatusCode() == 200:
                    issues.append(CustomScanIssue(
                        attack.getHttpService(),
                        helpers.analyzeRequest(attack).getUrl(),
                        [attack],
                        "Backup file leaked",
                        "Suspecious backup file likely leaked",
                        "High"))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


class DirScan(IScannerCheck):
    def __init__(self):
        self.hs = set()
        self.patterns = ['.git', '.git/index', '.hg', '.svn', '.idea', '.git/config', '.idea/workspace.xml', '.bzr',
                         'wwwroot.zip', 'www.zip', 'backup.zip']

    def doPassiveScan(self, baseRequestResponse):
        # Nope ...
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):

        reqinfo = helpers.analyzeRequest(baseRequestResponse)
        url = str(reqinfo.getUrl())
        url = urlparse(url)

        issues = []

        rpath, file = path.split(url.path)
        burl = url.scheme + '://' + url.netloc + '/' + rpath

        if burl in self.hs:
            return None

        self.hs.add(burl)

        for dir in self.patterns:

            dirtest = helpers.buildHttpRequest(URL(url.scheme, url.hostname, url.port, rpath + '/' + dir))

            attack = cbs.makeHttpRequest(baseRequestResponse.getHttpService(), dirtest)
            reqinfo = helpers.analyzeResponse(attack.getResponse())

            if reqinfo.getStatusCode() == 200:
                issues.append(CustomScanIssue(
                    attack.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    [attack],
                    "Sensitive info leaked",
                    "Sensitive directory or file likely leaked",
                    "High"))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0


class BurpExtender(IBurpExtender, IScannerCheck):
    #
    # implement IBurpExtender
    #
    def __init__(self):
        self.hs = set()

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        global cbs, helpers, stdout, stderr
        cbs = callbacks

        helpers = callbacks.getHelpers()

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("CTF helper")

        stdout.println("Welcome to my CTF world...")
        stdout.println('CTF helper by unamer.')

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(backupScan())
        callbacks.registerScannerCheck(DirScan())


#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
