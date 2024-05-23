import requests
from bs4 import BeautifulSoup
import logging
import os
from urllib.parse import urljoin, urlparse
from threading import Thread, Lock

# Configurar logging
logging.basicConfig(filename='web_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Payloads para testes de vulnerabilidades
XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

# Diretório para salvar conteúdo estático
DOWNLOAD_DIR = "downloaded_content"
lock = Lock()

# Dicionário para armazenar vulnerabilidades encontradas
vulnerabilities = {
    'xss': [],
    'sqli': []
}

def fetch_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"URL acessada com sucesso: {url}")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao acessar a URL {url}: {e}")
        return None

def parse_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup

def find_links_and_forms(soup, base_url):
    links = []
    forms = []
    
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if not href.startswith('http'):
            href = urljoin(base_url, href)
        links.append(href)

    for form in soup.find_all('form'):
        forms.append(form)

    return links, forms

def find_static_resources(soup, base_url):
    resources = []
    tags_and_attributes = {
        'img': 'src',
        'script': 'src',
        'link': 'href',
        'video': 'src',
        'source': 'src',
        'a': 'href'
    }
    
    for tag, attribute in tags_and_attributes.items():
        for resource in soup.find_all(tag, {attribute: True}):
            resource_url = resource[attribute]
            if not resource_url.startswith('http'):
                resource_url = urljoin(base_url, resource_url)
            if any(resource_url.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.mp4', '.webm', '.pdf', '.doc', '.docx', '.xls', '.xlsx']):
                resources.append(resource_url)

    return resources

def test_xss(form, url):
    for input_tag in form.find_all('input'):
        if input_tag.get('type') == 'text':
            data = {input_tag.get('name'): XSS_PAYLOAD}
            response = submit_form(form, url, data)
            if XSS_PAYLOAD in response.text:
                logging.warning(f"Possível vulnerabilidade XSS encontrada em {url}")
                vulnerabilities['xss'].append(url)
                print(f"Possível vulnerabilidade XSS encontrada em {url}")

def test_sqli(form, url):
    for input_tag in form.find_all('input'):
        if input_tag.get('type') == 'text':
            data = {input_tag.get('name'): SQLI_PAYLOAD}
            response = submit_form(form, url, data)
            if "SQL" in response.text or "syntax" in response.text:
                logging.warning(f"Possível vulnerabilidade SQL Injection encontrada em {url}")
                vulnerabilities['sqli'].append(url)
                print(f"Possível vulnerabilidade SQL Injection encontrada em {url}")

def submit_form(form, url, data):
    action = form.get('action')
    if not action.startswith('http'):
        action = urljoin(url, action)
    method = form.get('method', 'get').lower()
    
    if method == 'post':
        return requests.post(action, data=data)
    else:
        return requests.get(action, params=data)

def download_resource(resource_url):
    try:
        response = requests.get(resource_url, stream=True)
        response.raise_for_status()
        parsed_url = urlparse(resource_url)
        resource_path = os.path.join(DOWNLOAD_DIR, os.path.basename(parsed_url.path))

        os.makedirs(os.path.dirname(resource_path), exist_ok=True)
        
        with open(resource_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        
        logging.info(f"Recurso baixado com sucesso: {resource_url}")
        print(f"Recurso baixado: {resource_url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao baixar recurso {resource_url}: {e}")

def analyze_seo(soup):
    seo_report = {
        'title': '',
        'meta_description': '',
        'meta_keywords': '',
        'headers': [],
        'images_with_alt': 0,
        'images_without_alt': 0
    }

    # Title
    title_tag = soup.find('title')
    if title_tag:
        seo_report['title'] = title_tag.string

    # Meta tags
    description_tag = soup.find('meta', attrs={'name': 'description'})
    if description_tag:
        seo_report['meta_description'] = description_tag.get('content', '')

    keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
    if keywords_tag:
        seo_report['meta_keywords'] = keywords_tag.get('content', '')

    # Headers
    for i in range(1, 7):
        headers = soup.find_all(f'h{i}')
        for header in headers:
            seo_report['headers'].append((f'h{i}', header.get_text(strip=True)))

    # Images
    images = soup.find_all('img')
    for img in images:
        if img.get('alt'):
            seo_report['images_with_alt'] += 1
        else:
            seo_report['images_without_alt'] += 1

    return seo_report

def print_seo_report(report):
    print("\nRelatório de SEO:")
    print(f"Título: {report['title']}")
    print(f"Meta Descrição: {report['meta_description']}")
    print(f"Meta Keywords: {report['meta_keywords']}")
    print("Cabeçalhos:")
    for header in report['headers']:
        print(f"  {header[0]}: {header[1]}")
    print(f"Imagens com atributo alt: {report['images_with_alt']}")
    print(f"Imagens sem atributo alt: {report['images_without_alt']}")

def print_vulnerability_report():
    print("\nRelatório de Vulnerabilidades:")
    if vulnerabilities['xss']:
        print("Vulnerabilidades XSS encontradas em:")
        for url in vulnerabilities['xss']:
            print(f"  - {url}")
    else:
        print("Nenhuma vulnerabilidade XSS encontrada.")

    if vulnerabilities['sqli']:
        print("Vulnerabilidades SQL Injection encontradas em:")
        for url in vulnerabilities['sqli']:
            print(f"  - {url}")
    else:
        print("Nenhuma vulnerabilidade SQL Injection encontrada.")

class ScannerThread(Thread):
    def __init__(self, url, functions):
        Thread.__init__(self)
        self.url = url
        self.functions = functions

    def run(self):
        html_content = fetch_url(self.url)
        if html_content:
            soup = parse_html(html_content)
            links, forms = find_links_and_forms(soup, self.url)
            static_resources = find_static_resources(soup, self.url)

            if 'links' in self.functions:
                lock.acquire()
                try:
                    print(f"\nLinks encontrados em {self.url}:")
                    for link in links:
                        print(link)
                        logging.info(f"Link encontrado: {link}")
                finally:
                    lock.release()

            if 'resources' in self.functions:
                for resource in static_resources:
                    download_resource(resource)

            if 'xss' in self.functions or 'sqli' in self.functions:
                for form in forms:
                    if 'xss' in self.functions:
                        test_xss(form, self.url)
                    if 'sqli' in self.functions:
                        test_sqli(form, self.url)

            if 'seo' in self.functions:
                seo_report = analyze_seo(soup)
                lock.acquire()
                try:
                    print_seo_report(seo_report)
                finally:
                    lock.release()

def main(url, functions):
    html_content = fetch_url(url)
    if html_content:
        soup = parse_html(html_content)
        links, forms = find_links_and_forms(soup, url)

        threads = []
        for link in links:
            thread = ScannerThread(link, functions)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        if 'xss' in functions or 'sqli' in functions:
            for form in forms:
                if 'xss' in functions:
                    test_xss(form, url)
                if 'sqli' in functions:
                    test_sqli(form, url)

        if 'seo' in functions:
            seo_report = analyze_seo(soup)
            print_seo_report(seo_report)

        if 'xss' in functions or 'sqli' in functions:
            print_vulnerability_report()

def get_function_choice():
    print("\nEscolha a função a ser executada:")
    print("1. links - Encontrar links na página")
    print("2. resources - Baixar conteúdo estático (imagens, vídeos, documentos)")
    print("3. xss - Testar vulnerabilidades XSS")
    print("4. sqli - Testar vulnerabilidades SQL Injection")
    print("5. seo - Analisar elementos SEO (meta tags, headers, etc.)")
    
    choice = input("Digite o número da função desejada: ")
    return choice

if __name__ == '__main__':
 print("""
██╗    ██╗████████ ███████   ███████╗██████╗ █████╗  ███╗   ██╗███╗   ██╗███████╗███████╗ ®
██║    ██║██╔════╝ ██╔══██   ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║█████╗   ██████    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔══╝   ██╚══██     ╚══██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗ ██║████╗  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝ ╚══════╝  ╚══════╝ ╚═════ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                             by Cr4wler
""")
url = input("Insira a URL: ")
while True:
    choice = get_function_choice()
    if choice == '1':
        main(url, ['links'])
    elif choice == '2':
        main(url, ['resources'])
    elif choice == '3':
        main(url, ['xss'])
    elif choice == '4':
        main(url, ['sqli'])
    elif choice == '5':
        main(url, ['seo'])
    else:
        print("Escolha inválida. Por favor, tente novamente.")
