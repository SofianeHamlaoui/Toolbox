#!/usr/bin/python27
# Demo version 1.0.0
# iran-cyber.Net
# this software was created just for penetration testing and information gathering!
# So we don't Accept any responsibility for any illegal usage.
# White Hat Coder
import sys
try:
    import hashlib
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install hashlib'
    print '   [-] you need to install hashlib Module'
    sys.exit()

try:
    import codecs
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install codecs'
    print '   [-] you need to install codecs Module'
    sys.exit()
try:
    import glob
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install glob'
    print '   [-] you need to install glob Module'
    sys.exit()
import time, re, urllib2, os
try:
    import color
except ImportError:
    print '---------------------------------------------------'
    print '[*] color.py File Missing!'
    print '   [-] you need to add color.py file'
    sys.exit()
from Queue import Queue
import socket
import threading
try:
    import rarfile
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install rarfile'
    print '   [-] you need to install rarfile Module'
    sys.exit()
try:
    import zipfile
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install zipfile'
    print '   [-] you need to install zipfile Module'
    sys.exit()
import cookielib, binascii, random, json
from urlparse import urlparse
from multiprocessing.dummy import Pool as ThreadPool
try:
    import uncompyle6
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install uncompyle6'
    print '   [-] you need to install uncompyle6 Module'
    sys.exit()

try:
    import requests
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install requests'
    print '   [-] you need to install requests Module'
    sys.exit()

try:
    import tqdm
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install tqdm'
    print '   [-] you need to install tqdm Module'
    sys.exit()



try:
    from passlib.hash import phpass
except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install passlib'
    print '   [-] you need to install passlib Module'
    sys.exit()

try:
    from colorama import Fore, Back, Style

    r = Fore.RED
    g = Fore.GREEN
    w = Fore.WHITE
    b = Fore.BLUE
    y = Fore.YELLOW
    m = Fore.MAGENTA
    c = Fore.CYAN
    res = Style.RESET_ALL

except ImportError:
    print '---------------------------------------------------'
    print '[*] pip install colorama'
    print '   [-] you need to install colorama Module'
    sys.exit()

__ScriptVersion__ = '1.0.0'
try:
    os.mkdir('logs')
except:
    pass

class Md5_Bruteforce(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        self.__hash = raw_input('     Enter md5 Hash: ')
        self.md5()

    def md5(self):
        if len(self.__hash) != 32:
            color.cls()
            color.print_logo()
            color.NotValidmd5Hash()
            sys.exit()
        else:
            try:
                check_Online_Md5 = requests.get('https://md5.gromweb.com/?md5=' + self.__hash, timeout=10)
                passwordhash = re.findall('<em class="long-content string">(.*)</em>', check_Online_Md5.text)
            except:
                color.Connection()
                sys.exit()
            if 'was succesfully reversed into the string' not in check_Online_Md5.text:
                color.HashNotfound_DB()
                Get_Ans = raw_input(
                    Fore.GREEN + '    [' + Fore.RED + '+' + Fore.GREEN + ']' + Fore.CYAN +
                    ' You Want Manual Brute force ? ' + Fore.RED + '[y]or[n]: ')
                if Get_Ans == 'y':
                    try:
                        lists = raw_input(
                            Fore.GREEN + '    [' + Fore.YELLOW + '+' + Fore.GREEN + ']'
                            + Fore.YELLOW + ' Password LIST: ')
                    except IOError:
                        color.NotFoundList()
                        sys.exit()
                    if lists:
                        try:
                            with open(lists, 'r') as f:
                                fox = f.read().splitlines()
                                Time1 = time.time()
                        except IOError:
                            color.NotFoundList(lists)
                            sys.exit()
                        color.stdoutz(' Please Wait')
                        count = 0
                        for i in fox:
                            Time2 = time.time()
                            count = count + 1
                            __Md5back = hashlib.md5(i).hexdigest()

                            if self.__hash == __Md5back:
                                color.HashOK(self.__hash, count, Time2, Time1, i)
                                sys.exit()
                        if self.__hash != __Md5back:
                            color.HashNo(self.__hash, count, Time2, Time1)
                            sys.exit()
                    else:
                        sys.exit()
            else:
                print Fore.GREEN + '    [' + Fore.YELLOW + '+' + Fore.GREEN + ']' \
                      + Fore.YELLOW + ' MD5: ' + Fore.GREEN + self.__hash
                print Fore.GREEN + '    [' + Fore.YELLOW + '+' + Fore.GREEN + ']' \
                      + Fore.YELLOW + ' Cracked Password: ' + Fore.RED + str(
                    passwordhash[0])
class Zone_h_Poster(object):
    def __init__(self):
        self.concurrent = 500
        color.cls()
        color.print_logo()
        try:
            self.Getlist = raw_input('  Enter Your list Website: ')
            self.NotifierName = raw_input('  Enter Your NickName In Zone-h: ')
        except:
            print 'something worng! we cant load list!'
            sys.exit()
        self.q = Queue(self.concurrent * 2)
        for i in range(self.concurrent):
            self.t = threading.Thread(target=self.doWork)
            self.t.daemon = True
            self.t.start()
        try:
            for url in open(self.Getlist):
                self.q.put(url.strip())
            self.q.join()
        except:
            pass
    def doWork(self):
        while True:
            url = self.q.get()
            self.Poster_Zh(url)
            self.q.task_done()

    def Poster_Zh(self, url):
        sess = requests.session()
        notifier = self.NotifierName
        Check = url
        if Check.startswith("http://"):
            Check = Check.replace("http://", "")
        elif Check.startswith("https://"):
            Check = Check.replace("https://", "")
        else:
            pass
        Postdata = dict(defacer=notifier, domain1='http://' + Check, hackmode=1, reason=1)
        Go = sess.post('http://www.zone-h.org/notify/single', data=Postdata,
                       headers={'Referer': 'http://www.zone-h.org/'})
        if 'color="red">OK</font>' in Go.text:
            color.Zone_h_OK(Check)
            with open('Result_okZone-h.txt', 'a') as x:
                x.write(Check + '\n')
        else:
            color.Zone_h_NO(Check)
            with open('Result_NoZone-h.txt', 'a') as x:
                x.write(Check + '\n')


class Zone_H_urlHunter(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        defacer = raw_input('   Defacer Name: ')
        zh = raw_input('   Enter ZH ID: ')
        phpsessid = raw_input('   Enter PHPSESSID: ')
        self.ZonE_H_Url_Hunter(defacer, zh , phpsessid)
    def ZonE_H_Url_Hunter(self, __Defacer, __ZH, __PHPSESSID):
        if len(__Defacer) & len(__ZH) & len(__PHPSESSID) <= 0:
            print 'SomeThingWorng ! try again with True Values!'
            sys.exit()
        page = 1
        print r + '    [' + w + '+' + r + '] ' + w + 'Notifier is : ' + r + __Defacer
        while True:
            url = 'http://zone-h.com/archive/notifier=' + __Defacer + '/page=' + str(page)
            page = page + 1
            sess = requests.session()

            my_cookie = {
                'ZH': __ZH,
                'PHPSESSID': __PHPSESSID
            }

            Open = sess.get(url, cookies=my_cookie, timeout=10)
            Hunt_urls = re.findall('<td>(.*)\n							</td>', Open.content)
            for xx in Hunt_urls:
                print r + '    [' + w + '*' + r + '] ' + y + xx.split('/')[0]
                with open('hunted_urls.txt', 'a') as rr:
                    rr.write(xx.split('/')[0] + '\n')

            if page > 50:
                sys.exit()
            else:
                continue

class Sqli_Finder(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        self.error = ["DB Error", "SQL syntax;", "mysql_fetch_assoc", "mysql_fetch_array", "mysql_num_rows",
                      "is_writable",
                      "mysql_result", "pg_exec", "mysql_result", "mysql_num_rows", "mysql_query", "pg_query",
                      "System Error",
                      "io_error", "privilege_not_granted", "getimagesize", "preg_match", "mysqli_result", 'mysqli']
        ipz = raw_input('    Enter Ip/Domain Address: ')
        self.ip_bing(ipz)
    def duplicate_remover(self, x):
        urls3 = glob.glob(x)
        domains = {}
        for line in urls3:
            with open(line, "r") as infile:
                for line1 in infile:
                    parse = urlparse(line1)
                    domains[parse[1]] = line1
            with open(line, "w") as outfile:
                for line1 in domains:
                    outfile.write(domains[line1])
            domains.clear()

    def ip_bing(self, __ip):
        try:
            if __ip.startswith("http://"):
                __ip = __ip.replace("http://", "")
            elif __ip.startswith("https://"):
                __ip = __ip.replace("https://", "")
            else:
                pass
            try:
                ip = socket.gethostbyname(__ip)
            except:
                color.domainnotvalid()
                sys.exit()
            color.GraBbingIpscan(ip)
            try:
                next = 0
                while next <= 500:
                    url = "http://www.bing.com/search?q=ip%3A" + ip + " php?id=&first=" + str(next) + "&FORM=PORE"
                    sess = requests.session()
                    cnn = sess.get(url, timeout=5)
                    next = next + 10
                    finder = re.findall(
                        '<h2><a href="(\S+)"',
                        cnn.text)
                    for url in finder:
                        if url.startswith('http://'):
                            url = url.replace('http://', '')
                        elif url.startswith('https://'):
                            url = url.replace('https://', '')
                        else:
                            pass
                        if 'php?id=' in url:
                            with open("logs/" + ip + "_sqli.txt", 'a') as f:
                                if 'go.microsoft.com' in url:
                                    pass
                                else:
                                    f.write(str(url + '\n'))
                        else:
                            pass
                lines = open("logs/" + ip + "_sqli.txt", 'r').read().splitlines()
                lines_set = set(lines)
                count = 0
                for line in lines_set:
                    try:
                        with open(ip + "_sqli.txt", 'a') as xx:
                            count = count + 1
                            xx.write(line + '\n')
                    except:
                        print 'Something Worng!'
                        sys.exit()
                os.unlink("logs/" + ip + "_sqli.txt")
                self.spritliST(ip + "_sqli.txt", ip)
            except:
                print ' Something Worng in Get Datas from bing.com! please Run VPN And Try Again.'
        except IOError:
            print 'IOError!'
            sys.exit()
        except IndexError:
            print 'IndexError!'
            sys.exit()

    def sqli(self, f, opener, ip):
        try:
            for s in self.error:
                URL = 'http://' + f + "'"
                sqli = urllib2.Request(URL)
                conn = opener.open(sqli).read()
                if s in conn:
                    SQLI = URL.replace("'", "")
                    break
            with open(ip + '_SQLI_OK.txt', 'a') as char:
                char.write(SQLI + '\n')
            self.duplicate_remover(ip + '_SQLI_OK.txt')
        except Exception, e:
            pass

    def spritliST(self, filetosprit, ip):
        threads = []
        files = open(filetosprit, 'r').read().splitlines()
        cj = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        print "-" * 50
        print "              VULN SQL-INJECTION SITES "
        print "-" * 50
        for f in files:
            t = threading.Thread(target=self.sqli, args=(f, opener, ip))
            t.start()
            threads.append(t)
            time.sleep(0.3)
        for j in threads:
            j.join()
        with open(ip + '_SQLI_OK.txt', 'r') as Reader:
            urlsqli = Reader.read().splitlines()
        for sqlurl in urlsqli:
            color.sqliDomain(sqlurl)
        os.unlink(filetosprit)

class WhoisTool(object):
    def __init__(self):
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:36.0) Gecko/20100101 Firefox/36.0',
                   'Accept': '*/*'}
        self.domain_Or_ipAddress = raw_input('     Enter IP/Domain Address: ')
        self.Whois()

    def Whois(self):
        Check = self.domain_Or_ipAddress
        if Check.startswith("http://"):
            Check = Check.replace("http://", "")
        elif Check.startswith("https://"):
            Check = Check.replace("https://", "")
        else:
            pass
        try:
            ip = socket.gethostbyname(Check)
        except:
            color.NotregistedYet(self.domain_Or_ipAddress)
            sys.exit()
        whoisrez = requests.get(binascii.a2b_base64('aHR0cDovL3d3dy52aWV3ZG5zLmluZm8vd2hvaXMvP2RvbWFpbj0=') + ip,
                                headers=self.headers, timeout=5)
        Revlist = re.findall('<font size="2" face="Courier">(.*)<br><br></td></tr><tr></tr>', whoisrez.text)
        result = Revlist[0].replace('<br>', '\n')
        if 'no entries found' in result:
            color.NotregistedYet(self.domain_Or_ipAddress)
        with open(Check + '_WhoIs_Result.txt', 'a') as ww:
            ww.write(result)
        color.whoisResults(str(Check + '_WhoIs_Result.txt'))



class BingDorker(object):
    def __init__(self):
        self.domains = ['ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'an', 'ao',
                   'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az', 'ba', 'bb',
                   'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm', 'bn', 'bo',
                   'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz', 'ca', 'cc', 'cd',
                   'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr',
                   'cu', 'cv', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do',
                   'dz', 'ec', 'ee', 'eg', 'eh', 'er', 'es', 'et', 'eu', 'fi',
                   'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge', 'gf',
                   'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'gs',
                   'gt', 'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu',
                   'id', 'ie', 'il', 'im', 'in', 'io', 'iq', 'is', 'it',
                   'je', 'jm', 'jo', 'jp', 'ke', 'kg', 'kh', 'ki', 'km', 'kn',
                   'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk',
                   'lr', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'mc', 'md', 'me',
                   'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr',
                   'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nc',
                   'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz',
                   'om', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn',
                   'pr', 'ps', 'pt', 'pw', 'py', 'qa', 're', 'ro', 'rs', 'ru',
                   'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sj',
                   'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'st', 'su', 'sv', 'sy',
                   'sz', 'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm',
                   'tn', 'to', 'tp', 'tr', 'tt', 'tv', 'tw', 'tz', 'ua', 'ug',
                   'uk', 'um', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg', 'vi',
                   'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'za', 'zm', 'zw', 'com',
                   'net', 'org', 'biz', 'gov', 'mil', 'edu', 'info', 'int', 'tel',
                   'name', 'aero', 'asia', 'cat', 'coop', 'jobs', 'mobi', 'museum',
                   'pro', 'travel']

    def ip_bing(self, __ip):
        try:
            if __ip.startswith("http://"):
                __ip = __ip.replace("http://", "")
            elif __ip.startswith("https://"):
                __ip = __ip.replace("https://", "")
            else:
                pass
            try:
                ip = socket.gethostbyname(__ip)
            except:
                color.domainnotvalid()
                sys.exit()
            color.GraBbingIp(ip)
            next = 0
            while next <= 500:
                url = "http://www.bing.com/search?q=ip%3A" + ip + "&first=" + str(next) + "&FORM=PORE"
                sess = requests.session()
                cnn = sess.get(url, timeout=5)
                next = next + 10
                finder = re.findall(
                    '<h2><a href="((?:https://|http://)[a-zA-Z0-9-_]+\.*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11})',
                    cnn.text)
                for url in finder:
                    if url.startswith('http://'):
                        url = url.replace('http://', '')
                    elif url.startswith('https://'):
                        url = url.replace('https://', '')
                    else:
                        pass
                    with open("logs/" + ip + ".txt", 'a') as f:
                        if 'go.microsoft.com' in url:
                            pass
                        else:
                            f.write(str(url + '\n'))
            lines = open("logs/" + ip + ".txt", 'r').read().splitlines()
            lines_set = set(lines)
            count = 0
            for line in lines_set:
                with open(ip + ".txt", 'a') as xx:
                    count = count + 1
                    color.Domain(line)
                    xx.write(line + '\n')
            os.unlink("logs/" + ip + ".txt")
        except IOError:
            sys.exit()
        except IndexError:
            sys.exit()


    def Dork_bing(self, __dork):
        for domain in self.domains:
            color.GraBbing(__dork, domain)
            next = 0
            while next <= 500:
                url = 'http://www.bing.com/search?q=' + __dork + 'site:' + domain + '&first=' + str(next) + '&FORM=PORE'
                sess = requests.session()
                cnn = sess.get(url, timeout=5)
                next = next + 10
                finder = re.findall(
                    '<h2><a href="((?:https://|http://)[a-zA-Z0-9-_]+\.*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11})',
                    cnn.text)
                for url in finder:
                    color.Domain(url)
                    if url.startswith('http://'):
                        url = url.replace('http://', '')
                    elif url.startswith('https://'):
                        url = url.replace('https://', '')
                    else:
                        pass
                    with open("logs/logs.txt", 'a') as f:
                        if 'go.microsoft.com' in url:
                            pass
                        else:
                            f.write(str(url + '\n'))
            lines = open("logs/logs.txt", 'r').read().splitlines()
            lines_set = set(lines)
            count = 0
            for line in lines_set:
                with open("list_domain.txt", 'a') as xx:
                    count = count + 1
                    xx.write(line + '\n')
            os.unlink("logs/logs.txt")


class reverse_ipz(object):
    def __init__(self):
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:36.0) Gecko/20100101 Firefox/36.0',
                   'Accept': '*/*'}
        color.cls()
        color.print_logo()
        Domorip = raw_input('     Enter Domain/IP Address: ')
        self.Reverse_ip(Domorip)
    def Reverse_ip(self, domain_Or_ipAddress):

        Check = domain_Or_ipAddress
        if Check.startswith("http://"):
            Check = Check.replace("http://", "")
        elif Check.startswith("https://"):
            Check = Check.replace("https://", "")
        else:
            pass
        try:
            ip = socket.gethostbyname(Check)
        except:
            color.domainnotvalid()
            sys.exit()
        Rev = requests.get(binascii.a2b_base64('aHR0cDovL3ZpZXdkbnMuaW5mby9yZXZlcnNlaXAvP2hvc3Q9') + ip + '&t=1',
                           headers=self.headers, timeout=5)
        Revlist = re.findall('<tr> <td>((([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}))</td>', Rev.text)
        if len(Revlist) == 1000:
            for url in Revlist:
                with open('logs/' + ip + '.txt', 'a') as xx:
                    xx.write(str(url[0]) + '\n')
            gotoBing = BingDorker()
            gotoBing.ip_bing(ip)
        else:
            color.ResultTotalDomain(str(len(Revlist)), ip)
            for url in Revlist:
                color.ResultDomain(str(url[0]))
                with open('logs/' + ip + '.txt', 'a') as xx:
                    xx.write(str(url[0]) + '\n')



class rar_Zip_Bruteforce(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        zipfiletoimport = raw_input('     Enter Zip/Rar File: ')
        wordlist = raw_input('     Enter password list: ')
        if '.rar' in zipfiletoimport:
            self.GoBruteforcerar(zipfiletoimport, wordlist)
        elif '.zip' in zipfiletoimport:
            self.GoBruteforceZip(zipfiletoimport, wordlist)

        else:
            print ' this File Not Zip/RAr File!'
    # zip File Brute Force
    def __Lets_Extract(self, __ZipFile_pwn, password):
        try:
            __ZipFile_pwn.extractall(pwd=password)
            print ''
            print Fore.RED + '    [*] ' + Fore.YELLOW + 'Key: ' + Fore.WHITE + password
            print(Style.RESET_ALL)
            exit()
        except:
            pass

    def GoBruteforceZip(self, __ZipFile, __ZipPass):
        try:
            __ZipFile_pwn = zipfile.ZipFile(__ZipFile)
        except IOError:
            color.NotFoundList(__ZipFile)
            sys.exit()
        try:
            __PassOpener = open(__ZipPass, 'r')
        except IOError:
            color.NotFoundList(__ZipFile)
            sys.exit()
        color.stdoutz('BruteForce Starting')

        for __Pass in __PassOpener.readlines():
            password = __Pass.strip('\n')
            t = threading.Thread(target=self.__Lets_Extract, args=(__ZipFile_pwn, password))
            t.start()
    # RAr File Brute Force
    def __Lets_Extractrar(self, __rarFile_pwn, password):
        try:
            __rarFile_pwn.extractall(pwd=str(password))
            print ''
            print Fore.RED + '    [*] ' + Fore.YELLOW + 'Key: ' + Fore.WHITE + password
            print(Style.RESET_ALL)
            exit()
        except:
            pass

    def GoBruteforcerar(self, __rarFile, __rarPass):
        color.cls()
        try:
            __rarFile_pwn = rarfile.RarFile(__rarFile)
        except IOError:
            color.NotFoundList(__rarFile)
            sys.exit()
        try:
            __PassOpener = open(__rarPass, 'r')
        except IOError:
            color.NotFoundList(__rarFile)
            sys.exit()
        color.stdoutz('BruteForce Starting')

        for __Pass in __PassOpener.readlines():
            password = __Pass.strip('\n')
            t = threading.Thread(target=self.__Lets_Extractrar, args=(__rarFile_pwn, password))
            t.start()

class Teleg_insta_checker(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        users = raw_input('    Enter List usernames: ')
        self.Checkti(users)
    def Checkti(self, listfile):
        try:
            with open(listfile, 'r') as x:
                usernames = x.read().splitlines()
        except:
            color.cls()
            color.print_logo()
            color.NotFoundList(listfile)
            sys.exit()

        for username in usernames:
            try:
                Check = requests.get('http://t.me/' + username, timeout=5)
                check2 = requests.get('http://instagram.com/' + username, timeout=5)

                if len(username) <= 4:
                    color.usernameNo(username, 'telegram')
                else:
                    if 'tgme_username_link' in Check.text:
                        color.UsernameOK(username, 'telegram')
                        with open('can_create_accounts_telegram.txt', 'a') as x:
                            x.write(username + '\n')
                    else:
                        color.usernameNo(username, 'telegram')
                        with open('cant_create_accounts_telegram.txt', 'a') as x:
                            x.write(username + '\n')
                if check2.status_code != 200:
                    color.UsernameOK(username, 'instagram')
                    with open('can_create_accounts_instagram.txt', 'a') as x:
                        x.write(username + '\n')
                else:
                    color.usernameNo(username, 'instagram')
                    with open('cant_create_accounts_instagram.txt', 'a') as x:
                        x.write(username + '\n')

            except:
                color.Connection()
                sys.exit()

class ICGwPScaN():
    def __init__(self):
        color.cls()
        color.print_logo()
        try:
            self.url = raw_input('    Enter Target: ')
        except IndexError:
            self.cls()
            self.print_logo()
            self.__option()
            sys.exit()
        if self.url.startswith('http://'):
            self.url = self.url.replace('http://', '')
        elif self.url.startswith("https://"):
            self.url = self.url.replace('https://', '')
        else:
            pass
        __kill_ip = self.url
        try:
            ip = socket.gethostbyname(__kill_ip)
            self.CheckWordpress = requests.get('http://' + self.url, timeout=5)
            if '/wp-content/' in self.CheckWordpress.text:
                self.cls()
                self.print_logo()
                print r + '    [' + y + '+' + r + ']' + w + ' URL      : ' + m + self.url
                print r + '    [' + y + '+' + r + ']' + w + ' IP Server: ' + m + ip
                print r + '    [' + y + '+' + r + ']' + w + ' Server   : ' + m + self.CheckWordpress.headers[
                    'server']
                self.UserName_Enumeration()
                self.CpaNel_UserName_Enumeration()
                self.Version_Wp()
                self.GeT_Theme_Name()
                self.GeT_PluGin_Name()
            else:
                self.cls()
                self.print_logo()
                self.Worng2()
                sys.exit()
        except socket.gaierror:
            self.cls()
            self.print_logo()
            print y + '---------------------------------------------------'
            print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                  ' Something worng! target.com without / in end ' + y + ']'
            sys.exit()
        except requests.exceptions.ReadTimeout:
            self.cls()
            self.print_logo()
            print y + '---------------------------------------------------'
            print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                  ' ConnectionError! Maybe server Down, Or your ip blocked! ' + y + ']'

    def __option(self):
        try:
            print y + '---------------------------------------------------'
            print r + '    [' + y + '+' + r + ']' + w + ' usage: ' + g + '    [ ' \
                  + w + ' Python ICgWpScaN.py Domain.com ' + g + ']'
        except:
            pass

    def Worng(self):
        try:
            print y + '---------------------------------------------------'
            print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                  ' Enter Valid Domain, We Cant Connect to Server ' + y + ']'
        except:
            pass

    def Worng2(self):
        try:
            print y + '---------------------------------------------------'
            print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                  ' This WebSite Not WordPress! ' + y + ']'
        except:
            pass

    def print_logo(self):
        clear = "\x1b[0m"
        colors = [36, 32, 34, 35, 31, 37, 30, 33, 38, 39]

        x = """
              _____ _____ _____          _____      _____      _   _ 
             |_   _/ ____/ ____|        |  __ \    / ____|    | \ | |
               | || |   | |  ____      _| |__) |__| |     __ _|  \| |
               | || |   | | |_ \ \ /\ / /  ___/ __| |    / _` | . ` |
              _| || |___| |__| |\ V  V /| |   \__ \ |___| (_| | |\  |
             |_____\_____\_____| \_/\_/ |_|   |___/\_____\__,_|_| \_|
                Coded By white Hat Hacker <3      IraN-cYber.Net



    """
        for N, line in enumerate(x.split("\n")):
            sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
            time.sleep(0.01)

    def cls(self):
        linux = 'clear'
        windows = 'cls'
        os.system([linux, windows][os.name == 'nt'])

    def UserName_Enumeration(self):
        _cun = 1
        Flag = True
        __Check2 = requests.get('http://' + self.url + '/?author=1', timeout=10)
        try:
            while Flag:
                GG = requests.get('http://' + self.url + '/wp-json/wp/v2/users/' + str(_cun), timeout=5)
                __InFo = json.loads(GG.text)
                if 'id' not in __InFo:
                    Flag = False
                else:
                    Usernamez = __InFo['name']
                    print r + '    [' + y + '+' + r + ']' + w + ' Wordpress Username: ' + m + Usernamez
                _cun = _cun + 1
        except:
            try:
                if '/author/' not in __Check2.text:
                    print r + '    [' + y + '+' + r + ']' + w + ' Wordpress Username: ' + r + 'Not FOund'
                else:
                    find = re.findall('/author/(.*)/"', __Check2.text)
                    username = find[0].strip()
                    if '/feed' in username:
                        find = re.findall('/author/(.*)/feed/"', __Check2.text)
                        username2 = find[0].strip()
                        print r + '    [' + y + '+' + r + ']' + w + ' Wordpress Username: ' + m + username2
                    else:
                        print r + '    [' + y + '+' + r + ']' + w + ' Wordpress Username: ' + m + username

            except requests.exceptions.ReadTimeout:
                self.cls()
                self.print_logo()
                print y + '---------------------------------------------------'
                print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                      ' ConnectionError! Maybe server Down, Or your ip blocked! ' + y + ']'

    def CpaNel_UserName_Enumeration(self):
        try:
            Get_page = requests.get('http://' + self.url, timeout=10)
            if '/wp-content/' in Get_page.text:
                Hunt_path = requests.get('http://' + self.url + '/wp-includes/ID3/module.audio.ac3.php', timeout=10)

                def Hunt_Path_User():
                    try:
                        find = re.findall('/home/(.*)/public_html/wp-includes/ID3/module.audio.ac3.php', Hunt_path.text)
                        x = find[0].strip()
                        return x
                    except:
                        pass

                def Hunt_Path_Host():
                    try:
                        find = re.findall("not found in <b>(.*)wp-includes/ID3/module.audio.ac3.php", Hunt_path.text)
                        x = find[0].strip()
                        return x
                    except:
                        pass

                Cpanel_username = Hunt_Path_User()
                Path_Host = Hunt_Path_Host()
                if Cpanel_username == None:
                    print r + '    [' + y + '+' + r + ']' + w + ' Cpanel Username: ' + r + 'Not FOund'

                else:
                    print r + '    [' + y + '+' + r + ']' + w + ' Cpanel Username: ' + m + Cpanel_username

                if Path_Host == None:
                    print r + '    [' + y + '+' + r + ']' + w + ' User Path Host : ' + r + 'Not FOund'
                else:
                    print r + '    [' + y + '+' + r + ']' + w + ' User Path Host : ' + m + Path_Host

        except requests.exceptions.ReadTimeout:
            self.cls()
            self.print_logo()
            print y + '---------------------------------------------------'
            print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                  ' ConnectionError! Maybe server Down, Or your ip blocked! ' + y + ']'

    def Plugin_NamE_Vuln_TeST(self, Plugin_NaME):
        num = 1
        cal = 0
        Flag = True
        while Flag:
            if Plugin_NaME == 'revslider':
                Plugin_NaME = 'Slider Revolution'
            url = 'https://wpvulndb.com/searches?page=' + str(num) + '&text=' + Plugin_NaME
            aa = requests.get(url, timeout=5)
            if 'No results found.' in aa.text:
                Flag = False
                break
            else:
                az = re.findall('<td><a href="/vulnerabilities/(.*)">', aa.text)
                bb = (len(az) / 2)
                for x in range(int(bb)):
                    uz = 'www.wpvulndb.com/vulnerabilities/' + str(az[cal])
                    Get_title = requests.get('http://' + uz, timeout=5)
                    Title = re.findall('<title>(.*)</title>', Get_title.text.encode('utf-8'))
                    print r + '        [' + y + 'MayBe Vuln' + r + '] ' + w + uz + ' --- ' + r + \
                          Title[0].encode('utf-8').split('-')[0]
                    cal = cal + 2
                cal = 0
                num = num + 1

    def Version_Wp(self):
        try:
            Check_oNe = requests.get('http://' + self.url + '/readme.html', timeout=10)
            find = re.findall('Version (.+)', Check_oNe.text)
            try:
                version = find[0].strip()
                if len(version) != None:
                    print r + '    [' + y + '+' + r + ']' + w + ' Wp Version: ' + m + version
                    self.Plugin_NamE_Vuln_TeST('Wordpress ' + version)
            except:
                print r + '    [' + y + '+' + r + ']' + w + ' Wp Version: ' + r + 'Not Found'

        except requests.exceptions.ReadTimeout:
            self.cls()
            self.print_logo()
            print y + '---------------------------------------------------'
            print g + '    [' + y + '+' + g + ']' + r + ' Error: ' + y + '    [ ' + w + \
                  ' ConnectionError! Maybe server Down, Or your ip blocked! ' + y + ']'

    def GeT_PluGin_Name(self):
        plugin_NamEz = {}
        Dup_Remove_Plug = 'iran-cyber.net'
        a = re.findall('/wp-content/plugins/(.*)', self.CheckWordpress.text)
        s = 0
        bb = len(a)
        for x in range(int(bb)):
            name = a[s].split('/')[0]
            if '?ver=' in a[s]:
                verz = a[s].split('?ver=')[1]
                version = re.findall('([0-9].[0-9].[0-9])', verz)
                if len(version) ==0:
                    if '-' in str(name):
                        g = name.replace('-', ' ')
                        plugin_NamEz[g] = s
                    elif '_' in str(name):
                        h = name.replace('_', ' ')
                        plugin_NamEz[h] = s
                    else:
                        plugin_NamEz[name] = s
                else:
                    OK_Ver = name + ' ' + version[0]
                    Dup_Remove_Plug = name
                    if '-' in OK_Ver:
                        ff = OK_Ver.replace('-', ' ')
                        plugin_NamEz[ff] = s
                    elif '_' in OK_Ver:
                        ff = OK_Ver.replace('_', ' ')
                        plugin_NamEz[ff] = s
                    else:
                        plugin_NamEz[OK_Ver] = s
            else:
                if Dup_Remove_Plug in name:
                    pass
                else:
                    if '-' in str(name):
                        g = name.replace('-', ' ')
                        plugin_NamEz[g] = s
                    elif '_' in str(name):
                        h = name.replace('_', ' ')
                        plugin_NamEz[h] = s
                    else:
                        plugin_NamEz[name] = s
            s = s + 1
        for name_plugins in plugin_NamEz:
            print r + '    [' + y + '+' + r + ']' + w + ' Plugin Name: ' + m + name_plugins
            self.Plugin_NamE_Vuln_TeST(name_plugins)

    def GeT_Theme_Name(self):
        a = re.findall('/wp-content/themes/(.*)', self.CheckWordpress.text)
        Name_Theme = a[0].split('/')[0]
        if '?ver=' in a[0]:
            verz = a[0].split('?ver=')[1]
            version = re.findall('([0-9].[0-9].[0-9])', verz)
            OK_Ver = Name_Theme + ' ' + version[0]
            if '-' in OK_Ver:
                x2 = OK_Ver.replace('-', ' ')
                print r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x2
                self.Plugin_NamE_Vuln_TeST(x2)
            elif '_' in OK_Ver:
                x = OK_Ver.replace('_', ' ')
                print r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x
                self.Plugin_NamE_Vuln_TeST(x)
            else:
                print r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + OK_Ver
                self.Plugin_NamE_Vuln_TeST(OK_Ver)
        else:
            if '-' in Name_Theme:
                x2 = Name_Theme.replace('-', ' ')
                print r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x2
                self.Plugin_NamE_Vuln_TeST(x2)
            elif '_' in Name_Theme:
                x = Name_Theme.replace('_', ' ')
                print r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x
                self.Plugin_NamE_Vuln_TeST(x)
            else:
                print r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + Name_Theme
                self.Plugin_NamE_Vuln_TeST(Name_Theme)



class crawlerEMail(object):
    def __init__(self):
        self.emailz = {}
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:36.0) Gecko/20100101 Firefox/36.0',
                   'Accept': '*/*'}
        color.cls()
        color.print_logo()
        urlz = raw_input('     Enter Website Address: ')
        self.Email_crawler(urlz)
    def Email_crawler(self, url):
        try:
            if url.startswith("http://"):
                url = url.replace("http://", "")
            elif url.startswith("https://"):
                url = url.replace("https://", "")
            else:
                pass
            try:
                requests.get('http://' + url, timeout=5)
            except requests.ConnectionError:
                color.domainnotvalid()
                sys.exit()
            sess = requests.session()
            a = sess.get(binascii.a2b_base64('aHR0cDovL3ZpZXdkbnMuaW5mby93aG9pcy8/ZG9tYWluPQ==') + url,
                         timeout=5, headers=self.headers)
            whoisemail = re.findall('Admin Email: (.*)<br>', a.text)
            try:
                rezwhois = whoisemail[0].split('<')[0]
                self.emailz[rezwhois] = 'Address'
            except:
                pass
            get_site = requests.get('http://' + url, timeout=5)
            Emails = re.findall('[\w\.-]+@[\w\.-]+', get_site.text)
            for Email in Emails:
                self.emailz[Email] = 'Address'
            results = set(self.emailz)
            for result in results:
                color.crawlerResult(result)
            if len(self.emailz) ==0:
                print '       [-] Email Not Found!'
        except requests.ConnectTimeout:
            color.crawlerTimeout()
            sys.exit()

class Base64(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        self.Chose()
        Chose2 = raw_input(' Enter Your Method : ')
        if Chose2 == '1':
            self.Single()
        elif Chose2 == '2':
            self.Multi()
        elif Chose2 == '3':
            self.Help_options()
        else:
            print 'Option Not found!'

    def Chose(self):
        print('\033[35m' + '   1) ' + '\033[32m' + 'Text To base64')
        print('\033[35m' + '   2) ' + '\033[32m' + 'File to base64')
        print('\033[35m' + '   3) ' + '\033[32m' + 'About, Help')
        print('\033[37m')

    def Select_pr(self):
        print('\033[35m' + '   1) ' + '\033[32m' + 'base64 Encode')
        print('\033[35m' + '   2) ' + '\033[32m' + 'base64 Decode')
        print('\033[37m')

    def Help_options(self):
        print('\033[31m' + ' ------------------------------------------------------------  ')
        print('\033[36m' + ' This is Simple project For decode and Encode base64  ')
        print('\033[32m' + ' option 1 for Text to base64 ')
        print('\033[35m' + ' option 2 for file.txt to base64 ')
        print('\033[31m' + ' ------------------------------------------------------------  ')
        print('\033[37m')

    def Multi(self):
        def base64_Decode():
            try:
                Encoded_File = raw_input("   Chose File : ")
                with open(Encoded_File, 'r') as x, open('decoded64.txt', 'w') as done:
                    for line in x:
                        decoded_line = binascii.a2b_base64(line.strip())
                        done.write(decoded_line + "\n")
                        print('\033[35m' + "\n\n Decoded ! \n\n")
                        print('\033[32m' + " Result : " + '\033[31m' + decoded_line)
                        print('\033[37m')
            except:
                pass
        def base64_EnCode():
            try:
                Decoded_File = raw_input("   Chose File : ")
                with open(Decoded_File, 'r') as x, open('encoded64.txt', 'w') as done:
                    for line in x:
                        encoded_line = binascii.b2a_base64(line.strip())
                        done.write(encoded_line + "\n")
                        print('\033[35m' + "\n\n Encoded ! \n\n")
                        print('\033[32m' + " Result : " + encoded_line)
                        print('\033[37m')
            except:
                pass
        self.Select_pr()
        Chose = raw_input(' Enter Your Method : ')
        if Chose == '1':
            base64_EnCode()
        elif Chose == '2':
            base64_Decode()
        else:
            print 'Option not found!'
    def Single(self):
        def base64_Decode():
            try:
                Encoded_File = raw_input("   Enter your Text : ")
                decoded_line = binascii.a2b_base64(Encoded_File.strip())
                print('\033[35m' + "\n\n base64 Decoded ! \n\n")
                print('\033[32m' + " Result : " + '\033[31m' + decoded_line)
                print('\033[37m')
            except:
                pass

        def base64_EnCode():
            try:
                Decoded_File = raw_input("   Enter your Text : ")
                decoded_line = binascii.b2a_base64(Decoded_File.strip())
                print('\033[35m' + "\n\n base64 Encoded ! \n\n")
                print('\033[32m' + " Result : " + '\033[31m' + decoded_line)
                print('\033[37m')
            except:
                pass
        self.Select_pr()
        Chose = raw_input(' Enter Your Method : ')
        if Chose == '1':
            base64_EnCode()
        elif Chose == '2':
            base64_Decode()
        else:
            print 'Option Not Found!'


class WpHashBruteForce(object):
    def __BruteForce(self, password):
        try:
            try:
                if len(self.Impurt_hash) != 34:
                    color.cls()
                    color.print_logo()
                    print r + '----------------------------'
                    sys.stdout.write(g + '    [' + r + '-' + g + ']' + y + ' Hash Not Valid : ' + r + str(self.Impurt_hash))
                    print ''
                    sys.exit()
            except:
                sys.exit()
            Checker = phpass.verify(password, self.Impurt_hash)
            CheckedHash = str(Checker) + ':' + str(password)
            if CheckedHash == 'True:' + password:
                print g + '        [' + g + '+' + g + ']' + y + ' Cracked Hash : ' + g + str(self.Impurt_hash)
                print g + '        [' + g + '+' + g + ']' + y + ' Password     : ' + g + str(password)
                print g + '        [' + g + '+' + g + ']' + y + ' Cracked Time : ' + g + str(self.Time2 - self.Time1)
                sys.exit(1)
        except:
            sys.exit(1)
    def __init__(self):
        try:
            color.cls()
            color.print_logo()
            Password_list = raw_input(' Enter Password List: ')
            self.Impurt_hash = raw_input(' Enter Your Hash: ')
            self.Time1 = time.time()
        except IndexError:
            color.cls()
            color.print_logo()
            sys.exit()
        try:
            __Readpass = open(Password_list).readlines()
        except:
            print y + '---------------------------------------------------'
            print r + '    [' + y + '-' + r + ']' + r + ' Error: ' + g + '    [ ' + w + ' oh Sorry i cant Read ' + \
                  Password_list + ' wordlist ' + g + ']'
            sys.exit()

        sys.stdout.write(g + '    [' + r + '~' + g + ']' + y + ' Please Wait')
        for n in range(3):
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(0.10)
        print ''
        sys.stdout.write(g + '    [' + r + '+' + g + ']' + y + ' Loaded Passwords : ' + m + str(len(__Readpass)))
        print ''
        count = 0

        for Wordlist in __Readpass:
            self.Time2 = time.time()
            count = count + 1
            Wordlist = Wordlist.rstrip()
            for i in xrange(1):
                t = threading.Thread(target=self.__BruteForce(Wordlist))
                t.start()


class Decompile_Pyc(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        try:
            self.file = raw_input(' file to decompile: ')
            self.box = raw_input(' Name file after Decompile: ')
            self.Main()
        except:
            print 'something Worng! try Again.'

    def Main(self):
        color.cls()
        color.print_logo()
        try:
            with open(self.box, "wb") as ff:
                uncompyle6.uncompyle_file(self.file, ff)
                print r + '        [' + y + '+' + r + ']' + g + ' file decompiled successfully.'

        except:
            print r + '        [' + y + '-' + r + ']' + r + ' Unsuccessful.'



class DeteCtor_CMS(object):
    def __init__(self):
        self.concurrent = 500
        color.cls()
        color.print_logo()
        try:
            self.Getlist = raw_input('  Enter Your list Website: ')
        except:
            print 'something worng! we cant load list!'
            sys.exit()
        self.q = Queue(self.concurrent * 2)
        for i in range(self.concurrent):
            self.t = threading.Thread(target=self.doWork)
            self.t.daemon = True
            self.t.start()
        try:
            for url in open(self.Getlist):
                self.q.put(url.strip())
            self.q.join()
        except:
            pass
    def doWork(self):
        while True:
            url = self.q.get()
            self.getStatus(url)
            self.q.task_done()

    def getStatus(self, url):
        if url.startswith('http://'):
            url = url.replace('http://', '')
        elif url.startswith("https://"):
            url = url.replace('https://', '')
        else:
            pass
        try:
            check = requests.get('http://' + url, timeout=5)
            checkJoomla = requests.get('http://' + url + '/language/en-GB/en-GB.ini', timeout=5)
            if '/wp-content/' in check.text:
                color.Print_Wordpres(url)
                with open('logs/wordpress.txt', 'a') as x:
                    x.write(url + '\n')
            elif '/sites/default/' in check.text:
                color.Print_Drupal(url)
                with open('logs/drupal.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'Joomla!' in checkJoomla.text:
                color.Print_Joomla(url)
                with open('logs/joomla.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'static.squarespace' in check.text:
                color.Print_cms(url, 'squarespace')
                with open('logs/squarespace.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'content="vBulletin' in check.text:
                color.Print_cms(url, 'vBulletin')
                with open('logs/vBulletin.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'blogger.com/static' in check.text:
                color.Print_cms(url, 'blogger')
                with open('logs/blogger.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'static.tumblr.com' in check.text:
                color.Print_cms(url, 'Tumblr')
                with open('logs/Tumblr.txt', 'a') as x:
                    x.write(url + '\n')
            elif "id='ipbwrapper'" in check.text:
                color.Print_cms(url, 'Invision Power Board')
                with open('logs/ipb.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'pull-right hidden-xs' in check.text:
                color.Print_cms(url, 'Vanilla Forums')
                with open('logs/Vanilla_Forums.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'The phpBB Group :' in check.text:
                color.Print_cms(url, 'phpBB')
                with open('logs/phpBB.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'smf_theme_url' in check.text:
                color.Print_cms(url, 'SMF')
                with open('logs/SMF.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'id="XenForo"' in check.text:
                color.Print_cms(url, 'XenForo')
                with open('logs/XenForo.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'class="DnnModule' in check.text:
                color.Print_cms(url, 'DotNetNuke')
                with open('logs/DNN.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'content="TYPO' in check.text:
                color.Print_cms(url, 'TYPO3')
                with open('logs/TYPO3.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'cdn7.bigcommerce.com' in check.text:
                color.Print_cms(url, 'BigCommerce')
                with open('logs/bigcommerce.txt', 'a') as x:
                    x.write(url + '\n')
            elif '/index.php?route=' in check.text:
                color.Print_cms(url, 'OpenCart')
                with open('logs/OpenCart.txt', 'a') as x:
                    x.write(url + '\n')
            elif '.shappify.com' in check.text:
                color.Print_cms(url, 'Shappify')
                with open('logs/Shappify.txt', 'a') as x:
                    x.write(url + '\n')
            elif '/skin/frontend' in check.text:
                color.Print_cms(url, 'Magento')
                with open('logs/Magento.txt', 'a') as x:
                    x.write(url + '\n')
            elif 'var prestashop' in check.text:
                color.Print_cms(url, 'Prestashop')
                with open('logs/Prestashop.txt', 'a') as x:
                    x.write(url + '\n')
            else:
                color.Print_Unknown(url)
                with open('logs/unknown.txt', 'a') as x:
                    x.write(url + '\n')
        except:
            color.Print_Unknown(url)


class Option(object):
    def __init__(self):
        color.cls()
        color.print_logo()
        color.print_options()
        Choose = raw_input('     $ ')
        if Choose == str(1):
            Md5_Bruteforce()
        elif Choose == str(2):
            Zone_h_Poster()
        elif Choose == str(3):
            Zone_H_urlHunter()
        elif Choose == str(4):
            Sqli_Finder()
        elif Choose == str(5):
            WhoisTool()
        elif Choose == str(6):
            color.cls()
            color.print_logo()
            dork = raw_input('     Enter Dork : ')
            BingDorker().Dork_bing(dork)
        elif Choose == str(7):
            reverse_ipz()
        elif Choose == str(8):
            rar_Zip_Bruteforce()
        elif Choose == str(9):
            Teleg_insta_checker()
        elif Choose == str(10):
            ICGwPScaN()
        elif Choose == str(11):
            crawlerEMail()
        elif Choose == str(12):
            Base64()
        elif Choose == str(13):
            WpHashBruteForce()
        elif Choose == str(14):
            Decompile_Pyc()
        elif Choose == str(15):
            DeteCtor_CMS()
Option()