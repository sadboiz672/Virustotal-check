Check theo list MD5 có sẵn
Hiện tại để chạy trên môi trường windows, mình chưa thực sự có giải pháp nào cụ thể hơn việc chúng ta sẽ check từng folder với command sau:

for /r %i in (*.exe) do certutil -hashfile "%i" MD5 >> hashes.txt

Nhược điểm là chỉ áp dụng với MD5, các hash khác cần phải điều chỉnh lại việc nhận diện các dòng hash
