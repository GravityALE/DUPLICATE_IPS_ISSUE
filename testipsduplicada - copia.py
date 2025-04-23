import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from io import BytesIO
import logging
from datetime import datetime
import queue

# Configuración básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 10
        self.command_timeout = 15
        self.max_workers = 10
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()

    def log_message(self, message, level="info"):
        """Envía mensajes a la cola para ser procesados por el hilo principal"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        self.log_queue.put((level, formatted_msg))
        logger.log(getattr(logging, level.upper()), formatted_msg)

    def update_progress(self, current, total):
        """Actualiza el progreso a través de la cola"""
        self.progress_queue.put((current, total))

    def connect_to_device(self, device_ip, device_type):
        """Establece conexión SSH con el dispositivo"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.log_message(f"Conectando a {device_ip} ({device_type})...")
            ssh.connect(device_ip, 
                      username=self.username, 
                      password=self.password, 
                      timeout=self.ssh_timeout,
                      banner_timeout=30,
                      look_for_keys=False,
                      allow_agent=False)
            self.log_message(f"Conexión exitosa a {device_ip}", "success")
            return ssh
        except socket.timeout:
            self.log_message(f"Timeout al conectar a {device_ip} ({device_type})", "warning")
            return None
        except Exception as e:
            self.log_message(f"Error al conectar a {device_ip} ({device_type}): {str(e)}", "warning")
            return None

    def execute_command(self, ssh, command, device_ip):
        """Ejecuta un comando y devuelve la salida"""
        try:
            self.log_message(f"Ejecutando en {device_ip}: {command}")
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            if error and "Invalid input detected" not in error:
                self.log_message(f"Error en {device_ip}: {error}", "warning")
                return None, error
            return output, None
        except Exception as e:
            self.log_message(f"Error ejecutando comando en {device_ip}: {str(e)}", "warning")
            return None, str(e)

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Verifica si la IP está en el dispositivo"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return device_ip, device_type, None, f"Error de conexión a {device_ip}"
        
        try:
            # Determinar el comando según el tipo de dispositivo
            if 'huawei' in device_type.lower():
                command = f"display ip routing-table {target_ip}"
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip}"
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip}"
            else:
                msg = f"Tipo no reconocido: {device_type}"
                self.log_message(msg, "warning")
                return device_ip, device_type, None, msg
            
            output, error = self.execute_command(ssh, command, device_ip)
            
            if error:
                return device_ip, device_type, None, error
            
            # Análisis detallado con logging
            if output:
                self.log_message(f"Respuesta de {device_ip}:\n{output[:200]}...")
                
                if 'huawei' in device_type.lower():
                    if f"{target_ip}/" in output or "Routing Table" in output:
                        self.log_message(f"IP encontrada en Huawei {device_ip}", "success")
                        return device_ip, device_type, output, None
                elif 'xe' in device_type.lower():
                    if "is directly connected" in output or "is subnetted" in output or f" {target_ip} " in output:
                        self.log_message(f"IP encontrada en IOS XE {device_ip}", "success")
                        return device_ip, device_type, output, None
                elif 'xr' in device_type.lower():
                    if f" {target_ip}/" in output or "Routing entry for" in output:
                        self.log_message(f"IP encontrada en IOS XR {device_ip}", "success")
                        return device_ip, device_type, output, None
            
            self.log_message(f"IP no encontrada en {device_ip}")
            return device_ip, device_type, None, "IP no encontrada en la tabla de routing"
        except Exception as e:
            self.log_message(f"Error procesando {device_ip}: {str(e)}", "warning")
            return device_ip, device_type, None, str(e)
        finally:
            if ssh:
                ssh.close()

    def process_devices(self, excel_data, target_ip):
        """Procesa todos los dispositivos en el archivo Excel"""
        try:
            df = pd.read_excel(BytesIO(excel_data))
            df['IP'] = df['IP'].astype(str).str.strip()
            df['Tipo'] = df['Tipo'].astype(str).str.strip().str.lower()
            devices = list(zip(df['IP'], df['Tipo']))
        except Exception as e:
            self.log_message(f"Error al procesar Excel: {str(e)}", "error")
            return None
        
        self.log_message(f"🔍 Iniciando búsqueda de {target_ip} en {len(devices)} dispositivos")
        
        found_devices = []
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
                self.update_progress(i, total_devices)
                result_ip, result_type, output, error = future.result()
                
                if output:
                    found_devices.append((result_ip, result_type, output))
        
        elapsed_time = time.time() - start_time
        self.log_message(f"⏱️ Tiempo total: {elapsed_time:.2f} segundos")
        
        return found_devices

def display_logs_and_progress(log_placeholder, progress_bar, progress_text, scanner):
    """Muestra logs y progreso desde las colas (debe ejecutarse en el hilo principal)"""
    while True:
        # Procesar mensajes de log
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
        
        # Procesar actualizaciones de progreso
        while not scanner.progress_queue.empty():
            current, total = scanner.progress_queue.get()
            progress = current / total
            progress_bar.progress(progress)
            progress_text.text(f"📡 Procesados: {current}/{total}")
        
        time.sleep(0.1)

def main():
    st.set_page_config(page_title="Network IP Scanner Fixed", layout="wide")
    
    st.title("🌐 Network IP Scanner - Versión Estable")
    st.markdown("""
    **Versión corregida** con manejo adecuado de threads y logging
    """)
    
    # Sidebar
    with st.sidebar:
        st.header("🔐 Credenciales SSH")
        username = st.text_input("Usuario", "juribeb")
        password = st.text_input("Contraseña", type="password")
        
        st.markdown("---")
        st.info("""
        - Columna 'IP': Direcciones de los dispositivos
        - Columna 'Tipo': IOS XE, IOS XR o Huawei
        """)
    
    # Área principal
    uploaded_file = st.file_uploader("Sube archivo Excel con dispositivos", type=['xlsx'])
    
    if uploaded_file is not None:
        target_ip = st.text_input("IP a buscar", "172.20.142.85")
        
        if st.button("🚀 Iniciar Escaneo", use_container_width=True):
            # Configurar elementos de UI
            progress_bar = st.progress(0)
            progress_text = st.empty()
            log_container = st.expander("📝 Logs de Ejecución", expanded=True)
            log_placeholder = log_container.empty()
            results_placeholder = st.empty()
            
            # Crear scanner
            scanner = NetworkDeviceScanner(username, password)
            
            # Mostrar estado inicial
            log_placeholder.info("Preparando escaneo...")
            
            # Ejecutar el escaneo en un thread separado
            def run_scan():
                try:
                    found_devices = scanner.process_devices(uploaded_file.read(), target_ip)
                    
                    # Mostrar resultados finales
                    results_placeholder.empty()
                    if found_devices:
                        results_placeholder.success(f"🎯 IP encontrada en {len(found_devices)} dispositivos:")
                        for device_ip, device_type, _ in found_devices:
                            results_placeholder.write(f"- {device_ip} ({device_type})")
                    else:
                        results_placeholder.warning(f"La IP {target_ip} no se encontró en ningún dispositivo")
                except Exception as e:
                    log_placeholder.error(f"Error en el escaneo: {str(e)}")
            
            # Iniciar el escaneo en un thread
            import threading
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.start()
            
            # Procesar logs y progreso en el hilo principal
            while scan_thread.is_alive():
                display_logs_and_progress(log_placeholder, progress_bar, progress_text, scanner)
                time.sleep(0.1)
            
            # Procesar cualquier mensaje restante
            display_logs_and_progress(log_placeholder, progress_bar, progress_text, scanner)

if __name__ == "__main__":
    main()
