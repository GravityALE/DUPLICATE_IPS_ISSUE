import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from io import BytesIO

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 15  # Aumentado desde 10
        self.command_timeout = 20  # Aumentado desde 15
        self.max_workers = 15  # Reducido desde 20 para mayor estabilidad
        self.found_devices = []
        self.failed_connections = []

    def connect_to_device(self, device_ip, device_type):
        """Versión idéntica a tu script local pero con logs para Streamlit"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(device_ip, 
                       username=self.username, 
                       password=self.password, 
                       timeout=self.ssh_timeout,
                       banner_timeout=25)  # Aumentado desde 20
            return ssh
        except socket.timeout:
            self.failed_connections.append(f"Timeout conectando a {device_ip} ({device_type})")
            return None
        except Exception as e:
            self.failed_connections.append(f"Error conectando a {device_ip} ({device_type}): {str(e)}")
            return None

    def execute_command(self, ssh, command):
        """Versión idéntica a tu script local"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                return None
            return output
        except Exception as e:
            return None

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Misma lógica que tu versión local"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return None, None
        
        try:
            # Comandos idénticos a tu versión local
            if 'huawei' in device_type.lower():
                command = f"dis ip routing-table {target_ip}"
                search_terms = ["Routing Table", target_ip]
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip}"
                search_terms = ["Network", "Known", target_ip]
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip}"
                search_terms = ["Network", "Known", target_ip]
            else:
                return device_ip, None
            
            output = self.execute_command(ssh, command)
            
            if output and all(term in output for term in search_terms):
                return device_ip, output
            
            return device_ip, None
        finally:
            ssh.close()

    def process_devices(self, excel_data, target_ip, progress_bar, status_text):
        """Procesamiento similar pero con actualización de UI"""
        try:
            df = pd.read_excel(BytesIO(excel_data))
            devices = [(str(row[0]), str(row[1]).lower()) for _, row in df.iterrows()]
        except Exception as e:
            st.error(f"Error leyendo Excel: {str(e)}")
            return False
        
        start_time = time.time()
        total_devices = len(devices)
        
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
            
            for i, future in enumerate(as_completed(futures), 1):
                device_ip, device_type = futures[future]
                progress = i / total_devices
                progress_bar.progress(progress)
                status_text.text(f"Procesando {i}/{total_devices} | Fallos: {len(self.failed_connections)}")
                
                try:
                    result_ip, output = future.result()
                    if output:
                        self.found_devices.append((result_ip, device_type, output))
                        st.success(f"¡IP encontrada en {result_ip} ({device_type})!")
                        with st.expander("Ver detalles"):
                            st.text(output)
                except Exception as e:
                    self.failed_connections.append(f"Error procesando {device_ip}: {str(e)}")
        
        elapsed_time = time.time() - start_time
        status_text.text(f"Completado en {elapsed_time:.2f} segundos | Fallos: {len(self.failed_connections)}")
        
        return len(self.found_devices) > 0

def main():
    st.set_page_config(page_title="Buscador de IP en Red", layout="wide")
    st.title("🔍 Buscador de IP (Versión Híbrida)")
    
    # Sidebar con credenciales
    with st.sidebar:
        st.header("Credenciales SSH")
        username = st.text_input("Usuario", "juribeb")
        password = st.text_input("Contraseña", "Gravy201219@", type="password")
        st.markdown("---")
        st.info("Usa el mismo formato que en tu script local")

    # Área principal
    uploaded_file = st.file_uploader("Sube tu archivo Excel", type=['xlsx'])
    
    if uploaded_file is not None:
        target_ip = st.text_input("IP a buscar", "172.20.142.85")
        
        if st.button("Iniciar Búsqueda"):
            # Configurar elementos de UI
            progress_bar = st.progress(0)
            status_text = st.empty()
            results_container = st.container()
            failures_container = st.container()
            
            # Crear scanner
            scanner = NetworkDeviceScanner(username, password)
            
            # Ejecutar escaneo
            has_results = scanner.process_devices(
                uploaded_file.read(),
                target_ip,
                progress_bar,
                status_text
            )
            
            # Mostrar resultados
            with results_container:
                if has_results:
                    st.success("Resumen de dispositivos con la IP encontrada:")
                    for device_ip, device_type, _ in scanner.found_devices:
                        st.write(f"- {device_ip} ({device_type})")
                else:
                    st.warning(f"La IP {target_ip} no se encontró en los dispositivos accesibles")
            
            # Mostrar fallos de conexión
            with failures_container:
                if scanner.failed_connections:
                    st.error("Problemas de conectividad encontrados:")
                    with st.expander("Ver detalles de fallos", expanded=False):
                        for error in scanner.failed_connections:
                            st.text(error)

if __name__ == "__main__":
    main()
