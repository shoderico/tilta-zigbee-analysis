@echo off

SET PATH=C:\Users\shoderico\AppData\Local\Programs\Python\Python313;%PATH%
SET PATH=%PATH%;C:\Program Files\Wireshark
cd /d %~dp0

for %%a in (%*) do (

echo Target file: %%a
python psd2pcap.py %%a

)
pause

@echo on