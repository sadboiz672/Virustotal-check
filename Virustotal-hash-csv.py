import csv
import requests
import time

# Đọc file CSV và lấy dữ liệu từ cột chứa hash
hashes = []
cout_malware=0
count_nope=0
count_safe=0
with open('a.csv') as csv_file: #Thay tên file tùy biến
    csv_reader = csv.reader(csv_file)
    # Bỏ qua hàng đầu tiêu đề (nếu có)
    next(csv_reader)
    for row in csv_reader:
    	value = row[4].strip()
    	if value:
    		hashes.append(value)

# Khai báo API key của VirusTotal
api_key = '########'

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
            print(f'{hash} phát hiện độc hại {positives}/{total}')
            cout_malware +=1
            print('Chi tiết cảnh báo: \n')
            for scanner, result in json_response['scans'].items():
                if result['detected']:
                    print(f"\t{scanner}: {result['result']}")
        else:
        	count_safe+=1
        	print(f'{hash} không phát hiện độc hại {positives}/{total}')
    else:
    	count_nope+=1
    	print(f'{hash} không có kết quả tìm kiếm trên VirusTotal trước đây')
    time.sleep(25) #Key pro thì bỏ cho nhanh
print('Số lượng file độc hại:',cout_malware)
print('Số lượng file an toàn:',count_safe)
print('Số lượng file chưa phát hiện bởi Virustotal:',count_nope)
print("DONE!!!!")
