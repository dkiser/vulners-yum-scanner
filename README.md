# vulners-yum-scanner

> Note: quick and dirty 8-)

CLI utility for scanning a Yum repository against 
[Vulners](https://vulners.com) for advisories/CVE's.

This utility supports the following commands

* `audit` - Using a repo url (public or private), download the primary
            repo XML file, get the latest packages, and utilize the 
            [Vulners API](https://vulners.com/api/v3/audit/audit/) to
            search for advisories/CVE's based on package
            version info, OS version info, and OS family.

## Installation

If you don't use `pipsi`, you're missing out.
Here are [installation instructions](https://github.com/mitsuhiko/pipsi#readme).

Simply run:

    $ pipsi install .


You can also clone the directory and install via `pip`

    $ pip install .

## Usage

To use it:

    $ vulners-yum-scanner --help

    $ vulners-yum-scanner audit -r https://<yum repo> -o centos -v 7
    Starting Yum audit for: {'repo': u'https://<REDACTED>','version': u'7', 'os': u'centos'}
    Total provided packages: 718

    Vulnerabilities:
    CESA-2017:1789
    CESA-2017:1809
    CESA-2017:1681
    CESA-2017:1581
    CESA-2017:1680


    CVE List:
    CVE-2017-10193
    CVE-2017-10087
    CVE-2017-10198
    CVE-2017-10107
    CVE-2017-10243
    CVE-2017-10135
    CVE-2017-10101
    CVE-2017-10108
    CVE-2017-10090
    CVE-2017-10111
    CVE-2017-10096
    CVE-2017-10110
    CVE-2017-9148
    CVE-2017-5664
    CVE-2017-10115
    CVE-2017-3142
    CVE-2017-5648
    CVE-2017-10116
    CVE-2017-10067
    CVE-2017-10078
    CVE-2017-3143
    CVE-2017-10074
    CVE-2017-10053
    CVE-2017-10081
    CVE-2017-10089
    CVE-2017-10109
    CVE-2017-9524
    CVE-2017-10102
