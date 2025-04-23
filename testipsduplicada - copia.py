import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 20
        self.command_timeout = 25
        self.max_workers = 10
        self.results = []
        self.failures = []

    def connect_to_device(self, device_ip, device_type):
        """Conexión SSH optimizada"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(device_ip,
                      username=self.username,
                      password=self.password,
                      timeout=self.ssh_timeout,
                      banner_timeout=30,
                      look_for_keys=False,
                      allow_agent=False)
            return ssh
        except Exception as e:
            self.failures.append(f"{device_ip} ({device_type}): {str(e)}")
            return None

    def execute_command(self, ssh, command):
        """Ejecución robusta de comandos"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            return stdout.read().decode('utf-8', errors='ignore').strip()
        except:
            return None

    def scan_device(self, device_ip, device_type, target_ip):
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return None
        
        try:
            if 'huawei' in device_type.lower():
                commands = [
                    f"display ip routing-table {target_ip}",
                    f"display current-configuration | include {target_ip}"
                ]
            elif 'xe' in device_type.lower():
                commands = [f"show ip route {target_ip}"]
            elif 'xr' in device_type.lower():
                commands = [f"show route {target_ip}"]
            else:
                return None
            
            for cmd in commands:
                output = self.execute_command(ssh, cmd)
                if output and target_ip in output:
                    self.results.append((device_ip, device_type, output))
                    return True
            return False
        finally:
            ssh.close()

def main():
    st.title("🔍 Escáner Local de Red")
    st.warning("""
    **Ejecutar localmente** (no en Streamlit Cloud):
    ```bash
    streamlit run scanner_local.py
    ```
    """)
    
    with st.sidebar:
        st.header("Configuración")
        username = st.text_input("Usuario SSH", "juribeb")
        password = st.text_input("Contraseña", type="password")
        target_ip = st.text_input("IP a buscar", "172.20.142.85")
        excel_file = st.file_uploader("Archivo Excel", type=['xlsx'])
    
    if excel_file and st.button("Iniciar Escaneo"):
        scanner = NetworkDeviceScanner(username, password)
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            df = pd.read_excel(excel_file)
            devices = [(row['IP'], row['Tipo']) for _, row in df.iterrows()]
            
            with ThreadPoolExecutor(max_workers=scanner.max_workers) as executor:
                futures = {executor.submit(scanner.scan_device, ip, tipo, target_ip): (ip, tipo) for ip, tipo in devices}
                
                for i, future in enumerate(as_completed(futures), 1):
                    progress = i / len(devices)
                    progress_bar.progress(progress)
                    status_text.text(f"Procesados: {i}/{len(devices)} | Fallos: {len(scanner.failures)}")
            
            if scanner.results:
                st.success("Resultados encontrados:")
                for ip, tipo, _ in scanner.results:
                    st.write(f"- {ip} ({tipo})")
            else:
                st.error("No se encontró la IP en los dispositivos accesibles")
                
            if scanner.failures:
                with st.expander("Errores de conexión", expanded=False):
                    for error in scanner.failures:
                        st.text(error)
                        
        except Exception as e:
            st.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
