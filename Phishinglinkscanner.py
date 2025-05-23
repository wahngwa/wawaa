import re
import requests

#리디렉션되는지 보는 함수
def is_redirected(url):
    
    try:
        response = requests.get(url, allow_redirects=True, timeout=3)
        if response.history: # 리디렉션된 경우 history 속성에 이전 URL이 저장됨
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False # 예외 발생 시 리디렉션으로 판단하지 않음


#흔한 피싱 키워드
phishing_keywords = ["login", "verify", "account", "update", "secure", "bank", "password", "signin", "confirm","0"]

# 피싱키워드 유무 확인
def contains_phishing_keywords(url):
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True
    return False

# URL 의심 검사 (IP주소인지)
def contains_suspicious_patterns(url):
    # Check for presence of IP address in URL
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    if ip_pattern.search(url):
        return True

    # 서브도메인 확인 (e.g., http://secure-login.example.com)
    subdomain_pattern = re.compile(r'(\w+\.){3,}')
    if subdomain_pattern.search(url):
        return True

    return False

# 스캔 함수
def scan_for_phishing(urls):
    for url in urls:
        if contains_phishing_keywords(url):
            print(f"피싱사이트일 확률 매우높음: {url}")
        elif contains_suspicious_patterns(url):
            print(f"피싱사이트가 의심됨: {url}")
        else:
            print(f"안전한 사이트일 확률 매우 높음: {url}")

#예시:
#URL정의
urls_to_scan = [
    "http://example.com",
    "http://login-bank.com",
    "http://192.168.1.1",
    "http://secure-login.example.com",
    "http://update-password.com",
    
]
a = ["http://go0gle.com"]
#검사함수실행
scan_for_phishing(a)
URL_to_scan = ["www.naver.com"
,"https://www.youtube.com/shorts/x4GNxOSyQpw"]
scan_for_phishing(URL_to_scan)


#예시 사용
url = "https://www.naver.com/dsaw" # 리디렉션되는 URL 예시
is_redirected_url = is_redirected(url)

if is_redirected_url:
    print(f"{url}은 리디렉션 됩니다.")
else:
    print(f"{url}은 리디렉션되지 않습니다.")

url = "https://www.python.org/" # 리디렉션되지 않는 URL 예시
is_redirected_url = is_redirected(url)

if is_redirected_url:
    print(f"{url}은 리디렉션 됩니다.")
else:
    print(f"{url}은 리디렉션되지 않습니다.")