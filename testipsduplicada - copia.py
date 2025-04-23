import paramiko
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time

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
            ssh.connect(device_ip,
                        username=self.username,
                        password=self.password,
                        timeout=self.ssh_timeout,
                        banner_timeout=20)
            return ssh
        except Exception as e:
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
            return device_ip, None

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

    def process_devices(self, file, target_ip):
        try:
            df = pd.read_excel(file)
            devices = [(str(row[0]), str(row[1]).lower()) for _, row in df.iterrows()]
        except Exception as e:
            st.error(f"Error al leer el archivo Excel: {str(e)}")
            return []

        found_devices = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self.check_duplicate_ip,
                    device_ip,
                    device_type,
                    target_ip
                ): (device_ip, device_type)
                for device_ip, device_type in devices
            }

            for future in as_completed(futures):
                device_ip, device_type = futures[future]
                try:
                    result_ip, output = future.result()
                    if output:
                        found_devices.append((result_ip, device_type, output))
                except Exception as e:
                    st.warning(f"Error procesando {device_ip}: {str(e)}")

        return found_devices

# Streamlit interface
st.title("🔎 Buscador de IP Duplicadas en Equipos de Red")

username = st.text_input("Usuario SSH", value="juribeb")
password = st.text_input("Contraseña SSH", type="password")
target_ip = st.text_input("IP a buscar", value="172.20.142.101")
file = st.file_uploader("Sube el archivo Excel de equipos", type=["xlsx"])

if st.button("Buscar IP duplicada"):
    if not file or not username or not password or not target_ip:
        st.error("Por favor completa todos los campos.")
    else:
        with st.spinner("Procesando dispositivos..."):
            scanner = NetworkDeviceScanner(username, password)
            resultados = scanner.process_devices(file, target_ip)

        if resultados:
            st.success(f"¡IP duplicada encontrada en {len(resultados)} dispositivos!")
            for ip, tipo, salida in resultados:
                st.markdown(f"### {ip} ({tipo})")
                st.code(salida)
        else:
            st.info("No se encontró la IP en ningún dispositivo.")
