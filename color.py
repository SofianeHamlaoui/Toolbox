import sys, os, time, random

def cls():
    linux = 'clear'
    windows = 'cls'
    os.system([linux, windows][os.name == 'nt'])
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

def Print_Wordpres(url):
    print r + '    [' + y + '*' + r + ']' + w + ' URL: ' + m + url + r + '   [ ' + w + 'Wordpress' + r + ' ]'

def Print_Joomla(url):
    print r + '    [' + y + '*' + r + ']' + w + ' URL: ' + m + url + r + '   [ ' + w + 'Joomla' + r + ' ]'

def Print_Drupal(url):
    print r + '    [' + y + '*' + r + ']' + w + ' URL: ' + m + url + r + '   [ ' + w + 'Drupal' + r + ' ]'

def Print_Unknown(url):
    print r + '    [' + y + '-' + r + ']' + w + ' URL: ' + c + url + r + '   [ ' + y + 'Unknown' + r + ' ]'


def Print_cms(url, cms):
    print r + '    [' + y + '*' + r + ']' + w + ' URL: ' + c + url + r + '   [ ' + g + cms + r + ' ]'


def Print_Color_Checking(url):
    print r + '    [' + y + '*' + r + ']' + w + ' URL: ' + m + url + y + '  [ Checking ]'

def Print_Color_OK(url, NameVuln):
    print r + '       [' + y + '+' + r + ']' + w + ' URL: ' + m + url + r + '   [ ' + g + NameVuln + r + ' ]'

def Print_Color_No(url, NameVuln):
    print r + '       [' + y + '-' + r + ']' + w + ' URL: ' + m + url + r + '   [ ' + r + NameVuln + r + ' ]'



def print_logo():
    clear = "\x1b[0m"
    colors = [31, 32, 37]
    x = """

           ____  Iran-cyber.NeT      ,
          /---.'.__             ____//
               '--.\           /.---'
          _______  |\         //   
        /.------.\  \|      .'/  ______
       //  ___  \ \ ||/|\  //  _/_----.\__
      |/  /.-.\  \ \:|< >|// _/.'..\   '--'
         //   |'. | |'.|.'/ /_/ /  ||
        //     \ \_\/" ' ~\-'.-'    ||
       //       '-._| :H: |'-.__     ||
      //           (/'==='\)'-._\     ||
      || What You want ? Hmm    |\    \|
      ||  Everything is here     |\    '
      |/                          ||
                                  ||
                                  ||
                                  ||
                                   '
    """

    for N, line in enumerate(x.split("\n")):
        sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
        time.sleep(0.01)



def Domain(url):
    print g + '       [' + y + '+' + g + '] ' + w + url


def GraBbing(Dork, Domain):
    print r + '    [' + y + '+' + r + ']' + w + ' Grabbing ' + r + '[' + y + Dork + ' site:' + Domain + r + ']'

def GraBbingIp(ip):
    print r + '    [' + y + '+' + r + ']' + w + ' Getting List From: ' + r + '[' + y + ip + r + ']'


def print_options():
    print y + '     ------[Options]-----------------------------------------'
    print r + '         [' + y + '1' + r + ']' + w + ' MD5 Hash Crack Tool '
    print r + '         [' + y + '2' + r + ']' + w + ' Zone-h Poster'
    print r + '         [' + y + '3' + r + ']' + w + ' Zone-h Url Grabber'
    print r + '         [' + y + '4' + r + ']' + w + ' Sqli Finder'
    print r + '         [' + y + '5' + r + ']' + w + ' WHOIS Tool'
    print r + '         [' + y + '6' + r + ']' + w + ' Dorker [Search Dork]'
    print r + '         [' + y + '7' + r + ']' + w + ' Reverse Ip [ grab List of Websites on Server ]'
    print r + '         [' + y + '8' + r + ']' + w + ' Zip/Rar File Password BruteForce Tool'
    print r + '         [' + y + '9' + r + ']' + w + ' Telegram/instagram Username Checker'
    print r + '         [' + y + '10' + r + ']' + w + ' ICG Wordpress Scanner'
    print r + '         [' + y + '11' + r + ']' + w + ' Email Crawler'
    print r + '         [' + y + '12' + r + ']' + w + ' Base64 Encode/Decode'
    print r + '         [' + y + '13' + r + ']' + w + ' Wordpress Hash BruteForce tool'
    print r + '         [' + y + '14' + r + ']' + w + ' Python Bytecode file decompiler [.pyc]'
    print r + '         [' + y + '15' + r + ']' + w + ' CMS Detector [Checker]'


def NotFoundList(NotFoundFilename):
    cls()
    print_logo()
    print y + '-----------------------------------------'
    print y + '    [' + r + '-' + y + '] ' + w + NotFoundFilename + r + ' Not Found in This Directory!'
    print(Style.RESET_ALL)

def stdoutz(text):
    sys.stdout.write(g + '    [' + r + '~' + g + ']' + y + text)
    for n in range(3):
        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(0.39)

def ZipandRarKey(key):
    print r + '    [' + y + '+' + r + ']' + w + ' Key: ' + m + '[ ' + g + key + m + ' ]'

def NotValidmd5Hash():
    print Fore.YELLOW + '-----------------------------------------'
    print r + '[*]' + y + ' Your ' + g + 'MD5' + y + ' Hash Not Valid !'
    print ''

def HashNotfound_DB():
    print g + '    [' + r + '-' + g + ']' + c + ' Status: ' + r + 'Hash Not Avaible On DB'

def HashOK(__hash,count,Time2,Time1,i):
    print ''
    print g + '        [' + y + '+' + g + ']' + y + ' MD5: ' + g + __hash
    print g + '        [' + y + '+' + g + ']' + y + ' Total Passwords: ' + g + str(count)
    print g + '        [' + y + '+' + g + ']' + y + ' Duration: ' + g + str(Time2 - Time1)
    print g + '        [' + y + '+' + g + ']' + y + ' Cracked Password: ' + r + str(i)
    print ''

def HashNo(__hash, count, Time2, Time1):
    print ''
    print g + '        [' + r + '-' + g + ']' + c + ' MD5: ' + r + __hash
    print g + '        [' + r + '-' + g + ']' + c + ' Total Passwords: ' + r + str(count)
    print g + '        [' + r + '-' + g + ']' + c + ' Duration: ' + r + str(Time2 - Time1)
    print g + '        [' + r + '-' + g + ']' + c + ' Status: ' + r + 'Password Not Avaible On Your List'
    print ''

def Connection():
    print y + '    [' + r + '-' + y + '] ' + w + 'ConnectionError:' + r + ' Check Your internet Connection! '

def UsernameOK(username, instaortelegram):
    if 'telegram' in instaortelegram:
        print y + '     ' + c + ' ' + instaortelegram + '  :' + y + ' ' + g + username
    else:
        print y + '     ' + c + ' ' + instaortelegram + ' :' + y + ' ' + g + username

def usernameNo(username, instaortelegram):
    if 'telegram' in instaortelegram:
        print y + '     ' + c + ' ' + instaortelegram + '  :' + y + ' ' + r + username
    else:
        print y + '     ' + c + ' ' + instaortelegram + ' :' + y + ' ' + r + username

def crawlerTimeout():
    print y + '    [' + r + '-' + y + '] ' + w + 'TimeOut:' + r + ' Maybe Your ip Blocked! '

def domainnotvalid():
    print y + '    [' + r + '-' + y + '] ' + w + 'Something is Worng:' + r + ' Maybe Domain Not Valid! '

def crawlerResult(email):
    print r + '    [' + y + '+' + r + ']' + w + ' Email: ' + r + '[ ' + y + email + r + ' ]'

def ResultTotalDomain(TotalDomain, ip):
    print r + '    [' + y + '+' + r + ']' + w + ' Ip Address  : ' + r + '[ ' + c + ip + r + ' ]'
    print r + '    [' + y + '+' + r + ']' + w + ' Total Domain: ' + r + '[ ' + c + TotalDomain + r + ' ]'


def ResultDomain(url):
    print g + '       [' + y + '+' + g + '] ' + r + y + url


def whoisResults(whoisResult):
    print r + '    [' + y + '+' + r + ']' + w + ' Whois Result Saved. Check This file:' \
                                                ' ' + r + '[ ' + y + whoisResult + r + ' ]'

def NotregistedYet(domain):
    print r + '    [' + y + '+' + r + ']' + w + ' Hmm, i think this Domain Not Registered Yet! I Not found' \
                                                ' ANy results for you! : ' + r + '[ ' + y + domain + r + ' ]'
def TotalDomain(TotalDomain):
    print r + '    [' + y + '+' + r + ']' + w + ' Total Domain: ' + r + '[ ' + c + TotalDomain + r + ' ]'

def sqliDomain(url):
    print r + '    [' + y + '+' + r + '] ' + w + url + r + ' [ ' + c + 'SQLi' + r + ' ]'

def GraBbingIpscan(ip):
    print r + '    [' + y + '+' + r + ']' + w + ' Scanning This IP Address: ' + r + '[' + y + ip + r + ']'

def Zone_h_OK(Check):
    print r + '    [' + y + '+' + r + '] ' + w + Check + c + '  [ ' + g + 'OK' + c + ' ]'

def Zone_h_NO(Check):
    print r + '    [' + y + '+' + r + '] ' + w + Check + c + '  [ ' + r + 'NO' + c + ' ]'