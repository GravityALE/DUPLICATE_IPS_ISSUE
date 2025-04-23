import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from io import BytesIO
import queue
from datetime import datetime

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 15  # Aumentado para dispositivos lentos
        self.command_timeout = 20
        self.max_workers = 8  # Reducido para mayor estabilidad
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.results_queue = queue.Queue()

    def log_message(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        self.log_queue.put((level, formatted_msg))

    def update_progress(self, current, total):
        self.progress_queue.put((current, total))

    def add_result(self, device_ip, device_type, output):
        self.results_queue.put(("found", device_ip, device_type, output))

    def connect_to_device(self, device_ip, device_type):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.log_message(f"Conectando a {device_ip} ({device_type})...")
            ssh.connect(device_ip, 
                      username=self.username, 
                      password=self.password, 
                      timeout=self.ssh_timeout,
                      banner_timeout=45,
                      look_for_keys=False,
                      allow_agent=False)
            self.log_message(f"Conexión exitosa a {device_ip}", "success")
            return ssh
        except Exception as e:
            self.log_message(f"Error al conectar a {device_ip}: {str(e)}", "warning")
            return None

    def execute_command(self, ssh, command, device_ip):
        try:
            self.log_message(f"Ejecutando en {device_ip}: {command}")
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            if error and "Invalid input detected" not in error:
                self.log_message(f"Error en {device_ip}: {error}", "warning")
                return None
            return output
        except Exception as e:
            self.log_message(f"Error ejecutando comando: {str(e)}", "warning")
            return None

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return None
        
        try:
            # Comandos mejorados para cada tipo de dispositivo
            if 'huawei' in device_type.lower():
                command = f"display ip routing-table | include {target_ip}"
                search_patterns = [f"{target_ip}/", "Routing Table", target_ip]
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip} | include {target_ip}"
                search_patterns = [f" {target_ip} ", "directly connected", "subnetted"]
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip} | include {target_ip}"
                search_patterns = [f" {target_ip}/", "Routing entry"]
            else:
                self.log_message(f"Tipo no reconocido: {device_type}", "warning")
                return None
            
            output = self.execute_command(ssh, command, device_ip)
            
            # Análisis más exhaustivo de la salida
            if output:
                self.log_message(f"Respuesta completa de {device_ip}:\n{output}", "debug")
                
                if any(pattern in output for pattern in search_patterns):
                    self.add_result(device_ip, device_type, output)
                    self.log_message(f"¡COINCIDENCIA CONFIRMADA en {device_ip}!", "success")
                    return True
            
            self.log_message(f"IP no encontrada en {device_ip}", "info")
            return False
        except Exception as e:
            self.log_message(f"Error procesando {device_ip}: {str(e)}", "warning")
            return False
        finally:
            if ssh:
                ssh.close()

    def process_devices(self, excel_data, target_ip):
        try:
            df = pd.read_excel(BytesIO(excel_data))
            df['IP'] = df['IP'].astype(str).str.strip()
            df['Tipo'] = df['Tipo'].astype(str).str.strip().str.lower()
            devices = [(row['IP'], row['Tipo']) for _, row in df.iterrows()]
        except Exception as e:
            self.log_message(f"Error al leer Excel: {str(e)}", "error")
            return False
        
        self.log_message(f"Iniciando búsqueda precisa de {target_ip} en {len(devices)} dispositivos")
        
        start_time = time.time()
        total_devices = len(devices)
        found_count = 0
        
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
                self.update_progress(i, total_devices)
                if future.result():
                    found_count += 1
        
        elapsed_time = time.time() - start_time
        self.log_message(f"Búsqueda completada en {elapsed_time:.2f} segundos")
        self.results_queue.put(("summary", found_count, total_devices, target_ip))
        
        return found_count > 0

def display_ui_updates(log_placeholder, progress_bar, progress_text, results_area, scanner):
    """Muestra actualizaciones en la UI desde el hilo principal"""
    while True:
        # Procesar logs
        while not scanner.log_queue.empty():
            level, message = scanner.log_queue.get()
            if level == "error":
                log_placeholder.error(message)
            elif level == "warning":
                log_placeholder.warning(message)
            elif level == "success":
                log_placeholder.success(message)
            else:
                log_placeholder.info(message)
        
        # Procesar progreso
        while not scanner.progress_queue.empty():
            current, total = scanner.progress_queue.get()
            progress_bar.progress(current / total)
            progress_text.text(f"📡 Procesados: {current}/{total}")
        
        # Procesar resultados
        while not scanner.results_queue.empty():
            result_type, *data = scanner.results_queue.get()
            if result_type == "found":
                device_ip, device_type, output = data
                with results_area.expander(f"✅ IP encontrada en {device_ip} ({device_type})", expanded=True):
                    st.text_area("Salida del comando:", value=output, height=200)
            elif result_type == "summary":
                found_count, total_devices, target_ip = data
                if found_count > 0:
                    results_area.success(f"🎯 La IP {target_ip} se encontró en {found_count} dispositivo(s)")
                else:
                    results_area.warning(f"La IP {target_ip} no se encontró en los {total_devices} dispositivos escaneados")
        
        time.sleep(0.1)

def main():
    st.set_page_config(page_title="Buscador Avanzado de IP", layout="wide")
    st.title("🔍 Buscador Avanzado de IP en Red")
    
    with st.sidebar:
        st.header("Credenciales SSH")
        username = st.text_input("Usuario", "juribeb")
        password = st.text_input("Contraseña", type="password")
        st.markdown("---")
        st.info("Asegúrese que los tipos de dispositivo sean: Huawei, IOS XE o IOS XR")
    
    uploaded_file = st.file_uploader("Sube archivo Excel con dispositivos", type=['xlsx'])
    
    if uploaded_file:
        target_ip = st.text_input("IP a buscar", "172.20.142.85")
        
        if st.button("🔎 Iniciar Búsqueda Profunda", use_container_width=True):
            # Configurar áreas de visualización
            progress_bar = st.progress(0)
            progress_text = st.empty()
            log_container = st.expander("📝 Logs Detallados", expanded=True)
            log_placeholder = log_container.empty()
            results_area = st.container()
            
            # Iniciar escaneo
            scanner = NetworkDeviceScanner(username, password)
            
            def run_scan():
                try:
                    has_matches = scanner.process_devices(uploaded_file.read(), target_ip)
                    if not has_matches:
                        df = pd.read_excel(BytesIO(uploaded_file.read()))
                        scanner.results_queue.put(("summary", 0, len(df), target_ip))
                except Exception as e:
                    log_placeholder.error(f"Error crítico: {str(e)}")
            
            import threading
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.start()
            
            # Mostrar actualizaciones
            while scan_thread.is_alive():
                display_ui_updates(log_placeholder, progress_bar, progress_text, results_area, scanner)
                time.sleep(0.1)
            
            # Procesar cualquier mensaje restante
            display_ui_updates(log_placeholder, progress_bar, progress_text, results_area, scanner)

if __name__ == "__main__":
    main()
