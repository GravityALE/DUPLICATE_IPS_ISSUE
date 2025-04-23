import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
import io

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 10
        self.command_timeout = 15
        self.max_workers = 20

    def connect_to_device(self, device_ip, device_type):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(device_ip, username=self.username, password=self.password,
                        timeout=self.ssh_timeout, banner_timeout=20)
            return ssh
        except:
            return None

    def execute_command(self, ssh, command):
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode().strip()
            return output
        except:
            return None

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return None, None

        try:
            if 'huawei' in device_type:
                command = f"dis ip routing-table {target_ip}"
            elif 'xe' in device_type:
                command = f"show ip route {target_ip}"
            elif 'xr' in device_type:
                command = f"show route {target_ip}"
            else:
                return device_ip, None

            output = self.execute_command(ssh, command)
            if output and target_ip in output:
                return device_ip, output
            return device_ip, None
        finally:
            ssh.close()

    def process_devices(self, excel_data, target_ip):
        df = pd.read_excel(excel_data)
        devices = [(str(row[0]), str(row[1]).lower()) for _, row in df.iterrows()]
        found_devices = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.check_duplicate_ip, ip, tipo, target_ip): ip
                for ip, tipo in devices
            }
            for future in as_completed(futures):
                device_ip = futures[future]
                try:
                    result_ip, output = future.result()
                    if output:
                        found_devices.append((result_ip, output))
                except:
                    continue
        return found_devices

# STREAMLIT UI
st.title("🔍 Verificador de IP Duplicada en Equipos de Red")
st.write("Sube un Excel con los dispositivos y escribe la IP que deseas verificar.")

uploaded_file = st.file_uploader("📄 Archivo Excel (.xlsx)", type=["xlsx"])
target_ip = st.text_input("🔢 IP a verificar")
username = st.text_input("👤 Usuario SSH", type="default")
password = st.text_input("🔐 Contraseña SSH", type="password")

if st.button("Iniciar búsqueda"):
    if uploaded_file and target_ip and username and password:
        scanner = NetworkDeviceScanner(username, password)
        with st.spinner("Buscando..."):
            results = scanner.process_devices(uploaded_file, target_ip)
        if results:
            st.success(f"✅ IP {target_ip} encontrada en {len(results)} dispositivo(s):")
            for ip, output in results:
                st.markdown(f"**{ip}**")
                st.code(output)
        else:
            st.warning("IP no encontrada en ningún dispositivo.")
    else:
        st.error("Completa todos los campos para continuar.")
