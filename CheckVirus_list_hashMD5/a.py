# #for /r %i in (*.exe) do certutil -hashfile "%i" MD5 >> hashes.txt
import requests
import re
import time

api_key = '4e8eec375ab5e1c9ebe0622d9c10030bd6f2fa73cd993e3fc54e3fbc6117bb53'
url = 'https://www.virustotal.com/vtapi/v2/file/report'

cout_malware=0
count_nope=0
count_safe=0

with open("hash.txt", "r") as f:
    md5_list = [line.strip() for line in f if re.search(r'^[0-9a-fA-F]{32}$', line)]

for md5 in md5_list:
    params = {'apikey': api_key, 'resource': md5}
    response = requests.get(url, params=params)
    json_response = response.json()
    if json_response['response_code'] == 1:
        positives = json_response['positives']
        total = json_response['total']
        if positives > 0:
            print(f'{md5} phát hiện độc hại {positives}/{total}')
            cout_malware +=1
            print('Chi tiết cảnh báo: \n')
            for scanner, result in json_response['scans'].items():
                if result['detected']:
                    print(f"\t{scanner}: {result['result']}")
        else:
            count_safe+=1
            print(f'{md5} không phát hiện độc hại {positives}/{total}')
    else:
        count_nope+=1
        print(f'{md5} không có kết quả tìm kiếm trên VirusTotal trước đây')
    time.sleep(25) #Key pro thì bỏ cho nhanh
print('Số lượng file độc hại:',cout_malware)
print('Số lượng file an toàn:',count_safe)
print('Số lượng file chưa phát hiện bởi Virustotal:',count_nope)
print("DONE!!!!")
