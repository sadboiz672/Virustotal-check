import os
import hashlib
import requests
import time
# Cài đặt thông tin kết nối đến VirusTotal API
api_key = '######################'
url = 'https://www.virustotal.com/vtapi/v2/file/report'

# Đường dẫn tới thư mục chứa các tệp tin 
dir_path = './'

# Hash các tệp tin và lưu vào dictionary
hash_dict = {}
for filename in os.listdir(dir_path):
    if filename.endswith('###########################'):  # thay đổi tùy biến theo mục đích
        filepath = os.path.join(dir_path, filename)
        with open(filepath, 'rb') as f:
            filehash = hashlib.md5(f.read()).hexdigest()
            hash_dict[filename] = filehash

# Kiểm tra kết quả trên VirusTotal
for filename, filehash in hash_dict.items():
    print('Đang kiểm tra tệp tin', filename, 'có mã hash MD5 là', filehash)
    params = {'apikey': api_key, 'resource': filehash}
    response = requests.get(url, params=params)

    # Xử lý kết quả từ VirusTotal
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            if result['positives'] > 0:
                print('Tệp tin', filename, 'đã được phát hiện là độc hại bởi', result['positives'], 'trong số', result['total'], 'dịch vụ quét')
            else:
                print('Tệp tin', filename, 'không bị phát hiện là độc hại')
        else:
            print('Không thể kiểm tra tệp tin', filename)
    else:
        print('Không thể kết nối tới VirusTotal API để kiểm tra tệp tin', filename)
    time.sleep(20)
