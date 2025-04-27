@echo off
echo Installing requirements...
pip install flask scapy

echo Creating virtual network adapter if needed...
REM (Optional) You might need a firewall rule creation script too.

echo Done. You can now run server.py and redirector.py
pause
