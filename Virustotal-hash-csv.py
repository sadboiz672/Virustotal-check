import csv
import requests
import time

# Đọc file CSV và lấy dữ liệu từ cột chứa hash
hashes = []
with open('a.csv') as csv_file:
    csv_reader = csv.reader(csv_file)
    # Bỏ qua hàng tiêu đề (nếu có)
    next(csv_reader)
    for row in csv_reader:
        hashes.append(row[4])

# Khai báo API key của VirusTotal
api_key = 'API_key'

# Gửi yêu cầu đến VirusTotal để kiểm tra hash
for hash in hashes:
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': hash}
    response = requests.get(url, params=params)
    json_response = response.json()

    # Kiểm tra nếu VirusTotal phát hiện cảnh báo độc hại
    if json_response['response_code'] == 1:
        positives = json_response['positives']
        total = json_response['total']
        if positives > 0:
            print(f'{hash} has {positives}/{total} positive detections on VirusTotal')
            for scanner, result in json_response['scans'].items():
                if result['detected']:
                    print(f"\t{scanner}: {result['result']}")
        else:
            print(f'{hash} has no detections on VirusTotal {positives}/{total}')
    else:
        print(f'{hash} no results found for on VirusTotal')
    time.sleep(25)

    # chay den cuoi dang bi loi, nhung khong sao, do la viec danh sach hash da het
